#!/usr/bin/env python3
"""
DNS Relay - 通信与网络课程设计

实现一个基于 UDP Socket 的 DNS 中继器：
  1. 查询本地数据库 dnsrelay.txt
  2. 屏蔽域名返回 NXDOMAIN
  3. 本地命中返回 A 记录
  4. 未命中则转发上游 DNS，并缓存成功响应
"""

from __future__ import annotations

import argparse
import logging
import signal
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# 常量定义
# ---------------------------------------------------------------------------

class DNSConstants:
    """DNS 协议常用常量（RFC 1035）。"""

    # QTYPE
    TYPE_A = 1

    # QCLASS
    CLASS_IN = 1

    # RCODE（Response Code，位于 Header 低 4 位）
    RCODE_NOERROR = 0
    RCODE_SERVFAIL = 2
    RCODE_NXDOMAIN = 3

    # Header 标志位掩码
    FLAG_QR = 0x8000       # bit15: 0=查询, 1=响应
    FLAG_OPCODE_MASK = 0x7800
    FLAG_RCODE_MASK = 0x000F

    HEADER_SIZE = 12
    DEFAULT_TTL = 60
    CACHE_TTL = 60

    QTYPE_NAMES = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        15: "MX",
        16: "TXT",
        28: "AAAA",
    }


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class DNSHeader:
    """
    DNS Header（固定 12 字节）

    字节布局（大端序）:
      0-1   ID          Transaction ID，用于匹配请求与响应
      2-3   FLAGS       标志位（QR/OPCODE/AA/TC/RD/RA/Z/RCODE）
      4-5   QDCOUNT     Question 数量
      6-7   ANCOUNT     Answer 数量
      8-9   NSCOUNT     Authority 数量
      10-11 ARCOUNT     Additional 数量

  FLAGS 常用位:
      QR    (bit15)  1 表示响应
      RCODE (bit0-3) 响应码，3 表示 NXDOMAIN
    """

    transaction_id: int
    flags: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

    @property
    def is_response(self) -> bool:
        return bool(self.flags & DNSConstants.FLAG_QR)

    @property
    def rcode(self) -> int:
        return self.flags & DNSConstants.FLAG_RCODE_MASK

    def pack(self) -> bytes:
        return struct.pack(
            "!HHHHHH",
            self.transaction_id,
            self.flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "DNSHeader":
        fields = struct.unpack("!HHHHHH", data[:DNSConstants.HEADER_SIZE])
        return cls(*fields)


@dataclass
class DNSQuestion:
    """
    DNS Question Section

    结构:
      QNAME   变长，域名标签序列，以 0 结束
      QTYPE   2 字节，查询类型（A=1）
      QCLASS  2 字节，查询类（IN=1）
    """

    qname: str
    qtype: int
    qclass: int
    raw_qname: bytes
    end_offset: int


# ---------------------------------------------------------------------------
# DNS 编解码
# ---------------------------------------------------------------------------

class DNSCodec:
    """DNS 报文解析与构造工具。"""

    @staticmethod
    def qtype_name(qtype: int) -> str:
        return DNSConstants.QTYPE_NAMES.get(qtype, str(qtype))

    @staticmethod
    def decode_qname(data: bytes, offset: int) -> Tuple[str, int]:
        """
        解析 QNAME（域名标签格式）。

        例如 www.example.com 编码为:
          3 www 7 example 3 com 0
        """
        labels = []
        jumped = False
        original_offset = offset
        max_jumps = 10
        jumps = 0

        while True:
            if offset >= len(data):
                raise ValueError("QNAME 超出报文范围")

            length = data[offset]

            # 压缩指针（高 2 位为 11）
            if length & 0xC0 == 0xC0:
                if offset + 1 >= len(data):
                    raise ValueError("压缩指针不完整")
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                if not jumped:
                    original_offset = offset + 2
                offset = pointer
                jumps += 1
                if jumps > max_jumps:
                    raise ValueError("QNAME 压缩指针跳转过多")
                jumped = True
                continue

            if length == 0:
                offset += 1
                break

            offset += 1
            label = data[offset : offset + length]
            if len(label) != length:
                raise ValueError("QNAME 标签长度不匹配")
            labels.append(label.decode("ascii", errors="replace"))
            offset += length

        qname = ".".join(labels)
        end_offset = offset if not jumped else original_offset
        return qname, end_offset

    @staticmethod
    def encode_qname(domain: str) -> bytes:
        """将域名编码为 QNAME 标签序列。"""
        if not domain or domain == ".":
            return b"\x00"

        result = bytearray()
        for label in domain.rstrip(".").split("."):
            encoded = label.encode("ascii")
            if len(encoded) > 63:
                raise ValueError(f"标签过长: {label}")
            result.append(len(encoded))
            result.extend(encoded)
        result.append(0)
        return bytes(result)

    @classmethod
    def parse_question(cls, data: bytes, offset: int) -> DNSQuestion:
        """从 offset 处解析一条 Question。"""
        qname, end = cls.decode_qname(data, offset)
        if end + 4 > len(data):
            raise ValueError("Question 字段不完整")
        qtype, qclass = struct.unpack("!HH", data[end : end + 4])
        return DNSQuestion(
            qname=qname.lower(),
            qtype=qtype,
            qclass=qclass,
            raw_qname=data[offset:end],
            end_offset=end + 4,
        )

    @classmethod
    def parse_query(cls, data: bytes) -> Tuple[DNSHeader, DNSQuestion]:
        """解析 DNS 查询报文，返回 Header 与第一条 Question。"""
        if len(data) < DNSConstants.HEADER_SIZE:
            raise ValueError("报文长度不足 12 字节")

        header = DNSHeader.unpack(data)
        if header.is_response:
            raise ValueError("收到的是响应报文，非查询")
        if header.qdcount < 1:
            raise ValueError("QDCOUNT 为 0")

        question = cls.parse_question(data, DNSConstants.HEADER_SIZE)
        return header, question

    @classmethod
    def build_response_header(
        cls,
        transaction_id: int,
        rcode: int,
        ancount: int = 0,
        rd: bool = True,
    ) -> bytes:
        """
        构造响应 Header。

        flags 典型值:
          0x8180 = QR=1, RD=1, RCODE=0 (NOERROR)
          0x8183 = QR=1, RD=1, RCODE=3 (NXDOMAIN)
          0x8182 = QR=1, RD=1, RCODE=2 (SERVFAIL)
        """
        flags = DNSConstants.FLAG_QR
        if rd:
            flags |= 0x0100  # RD 位
        flags |= rcode & DNSConstants.FLAG_RCODE_MASK

        header = DNSHeader(
            transaction_id=transaction_id,
            flags=flags,
            qdcount=1,
            ancount=ancount,
            nscount=0,
            arcount=0,
        )
        return header.pack()

    @classmethod
    def build_a_answer(cls, ip_address: str, ttl: int = DNSConstants.DEFAULT_TTL) -> bytes:
        """
        构造一条 A 记录 Answer Section。

        Answer RR 结构:
          NAME    2 字节压缩指针 0xC00C（指向偏移 12 处的 Question QNAME）
          TYPE    2 字节，A=1
          CLASS   2 字节，IN=1
          TTL     4 字节
          RDLENGTH 2 字节，IPv4 为 4
          RDATA   4 字节 IPv4 地址
        """
        rdata = socket.inet_aton(ip_address)
        # NAME(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA(4)
        return struct.pack(
            "!HHHIH",
            0xC00C,
            DNSConstants.TYPE_A,
            DNSConstants.CLASS_IN,
            ttl,
            4,
        ) + rdata

    @classmethod
    def build_local_a_response(cls, query_data: bytes, ip_address: str) -> bytes:
        """构造本地 A 记录命中响应。"""
        header = DNSHeader.unpack(query_data)
        question = cls.parse_question(query_data, DNSConstants.HEADER_SIZE)

        response_header = cls.build_response_header(
            header.transaction_id,
            DNSConstants.RCODE_NOERROR,
            ancount=1,
            rd=bool(header.flags & 0x0100),
        )
        question_bytes = query_data[DNSConstants.HEADER_SIZE : question.end_offset]
        answer = cls.build_a_answer(ip_address)
        return response_header + question_bytes + answer

    @classmethod
    def build_nxdomain_response(cls, query_data: bytes) -> bytes:
        """构造 NXDOMAIN 响应（屏蔽域名，RCODE=3）。"""
        header = DNSHeader.unpack(query_data)
        question = cls.parse_question(query_data, DNSConstants.HEADER_SIZE)

        response_header = cls.build_response_header(
            header.transaction_id,
            DNSConstants.RCODE_NXDOMAIN,
            ancount=0,
            rd=bool(header.flags & 0x0100),
        )
        question_bytes = query_data[DNSConstants.HEADER_SIZE : question.end_offset]
        return response_header + question_bytes

    @classmethod
    def build_servfail_response(cls, query_data: bytes) -> bytes:
        """构造 SERVFAIL 响应（上游超时等错误，RCODE=2）。"""
        header = DNSHeader.unpack(query_data)
        question = cls.parse_question(query_data, DNSConstants.HEADER_SIZE)

        response_header = cls.build_response_header(
            header.transaction_id,
            DNSConstants.RCODE_SERVFAIL,
            ancount=0,
            rd=bool(header.flags & 0x0100),
        )
        question_bytes = query_data[DNSConstants.HEADER_SIZE : question.end_offset]
        return response_header + question_bytes

    @classmethod
    def replace_transaction_id(cls, response_data: bytes, new_id: int) -> bytes:
        """替换响应报文中的 Transaction ID（缓存命中时使用）。"""
        if len(response_data) < 2:
            return response_data
        return struct.pack("!H", new_id) + response_data[2:]

    @classmethod
    def extract_first_a_record(cls, response_data: bytes) -> Optional[str]:
        """从上游响应中提取第一条 A 记录的 IPv4 地址，用于日志展示。"""
        try:
            if len(response_data) < DNSConstants.HEADER_SIZE:
                return None
            header = DNSHeader.unpack(response_data)
            if header.ancount < 1:
                return None

            offset = DNSConstants.HEADER_SIZE
            # 跳过 Question
            for _ in range(header.qdcount):
                _, offset = cls.decode_qname(response_data, offset)
                offset += 4

            # 解析第一条 Answer
            _, offset = cls.decode_qname(response_data, offset)
            if offset + 10 > len(response_data):
                return None
            rtype, _, _, rdlength = struct.unpack("!HHIH", response_data[offset : offset + 10])
            offset += 10
            if rtype != DNSConstants.TYPE_A or offset + rdlength > len(response_data):
                return None
            return socket.inet_ntoa(response_data[offset : offset + rdlength])
        except (ValueError, struct.error, OSError):
            return None

    @classmethod
    def is_success_response(cls, response_data: bytes) -> bool:
        """判断上游响应是否成功（RCODE=0）。"""
        if len(response_data) < DNSConstants.HEADER_SIZE:
            return False
        header = DNSHeader.unpack(response_data)
        return header.rcode == DNSConstants.RCODE_NOERROR


# ---------------------------------------------------------------------------
# 本地数据库
# ---------------------------------------------------------------------------

class DNSDatabase:
    """加载并查询 dnsrelay.txt 本地域名库。"""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.records: Dict[str, str] = {}
        self.load()

    def load(self) -> None:
        """从文件加载 IP-domain 映射。"""
        self.records.clear()
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                for line_no, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) < 2:
                        logging.warning("忽略无效行 %d: %s", line_no, line)
                        continue
                    ip_addr, domain = parts[0], parts[1].lower()
                    self.records[domain] = ip_addr
        except FileNotFoundError:
            logging.error("数据库文件不存在: %s", self.filepath)
            raise

        logging.info("已加载本地数据库 %s，共 %d 条记录", self.filepath, len(self.records))

    def lookup(self, domain: str) -> Optional[str]:
        """查询域名对应的 IP，不存在返回 None。"""
        return self.records.get(domain.lower())


# ---------------------------------------------------------------------------
# 响应缓存
# ---------------------------------------------------------------------------

class DNSCache:
    """上游 DNS 成功响应缓存，默认 TTL 60 秒。"""

    def __init__(self, ttl: int = DNSConstants.CACHE_TTL) -> None:
        self.ttl = ttl
        self._store: Dict[Tuple[str, int], Tuple[bytes, float]] = {}

    def _purge_expired(self) -> None:
        now = time.time()
        expired = [k for k, (_, ts) in self._store.items() if now - ts >= self.ttl]
        for key in expired:
            del self._store[key]

    def get(self, qname: str, qtype: int) -> Optional[bytes]:
        """获取缓存响应，过期则返回 None。"""
        self._purge_expired()
        entry = self._store.get((qname.lower(), qtype))
        if entry is None:
            return None
        data, ts = entry
        if time.time() - ts >= self.ttl:
            del self._store[(qname.lower(), qtype)]
            return None
        return data

    def set(self, qname: str, qtype: int, response_data: bytes) -> None:
        """缓存上游成功响应。"""
        self._purge_expired()
        self._store[(qname.lower(), qtype)] = (response_data, time.time())


# ---------------------------------------------------------------------------
# DNS Relay 主服务
# ---------------------------------------------------------------------------

class DNSRelay:
    """DNS Relay 核心服务：接收查询、本地解析、转发上游。"""

    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        upstream_host: str,
        upstream_port: int,
        database_path: str,
        timeout: float,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.timeout = timeout
        self.database = DNSDatabase(database_path)
        self.cache = DNSCache()
        self.running = True
        self.sock: Optional[socket.socket] = None

    def start(self) -> None:
        """绑定端口并进入主循环。"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.listen_host, self.listen_port))

        logging.info(
            "DNS Relay 已启动 | 监听 %s:%d | 上游 %s:%d | 数据库 %s",
            self.listen_host,
            self.listen_port,
            self.upstream_host,
            self.upstream_port,
            self.database.filepath,
        )

        while self.running:
            try:
                data, client_addr = self.sock.recvfrom(512)
                self._handle_query(data, client_addr)
            except OSError:
                if self.running:
                    logging.exception("接收数据时发生错误")
                break

    def stop(self) -> None:
        """优雅停止服务。"""
        self.running = False
        if self.sock:
            self.sock.close()
            self.sock = None
        logging.info("DNS Relay 已停止")

    def _log_query(
        self,
        client_addr: Tuple[str, int],
        qname: str,
        qtype: int,
        action: str,
        result: str,
    ) -> None:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        qtype_name = DNSCodec.qtype_name(qtype)
        client = f"{client_addr[0]}:{client_addr[1]}"
        logging.info(
            "%s | %s | %s | %s | %s | %s",
            timestamp,
            client,
            qname,
            qtype_name,
            action,
            result,
        )

    def _send_response(
        self, response: bytes, client_addr: Tuple[str, int]
    ) -> None:
        if self.sock:
            self.sock.sendto(response, client_addr)

    def _handle_query(self, data: bytes, client_addr: Tuple[str, int]) -> None:
        """处理一条 DNS 查询。"""
        try:
            header, question = DNSCodec.parse_query(data)
        except (ValueError, struct.error) as exc:
            logging.warning("非法 DNS 报文来自 %s:%d: %s", client_addr[0], client_addr[1], exc)
            self._log_query(client_addr, "?", 0, "ERROR", "INVALID_PACKET")
            return

        qname = question.qname
        qtype = question.qtype

        # 仅对 A/IN 查询走本地库；其他类型转发上游
        if qtype == DNSConstants.TYPE_A and question.qclass == DNSConstants.CLASS_IN:
            ip_addr = self.database.lookup(qname)
            if ip_addr is not None:
                if ip_addr == "0.0.0.0":
                    response = DNSCodec.build_nxdomain_response(data)
                    self._send_response(response, client_addr)
                    self._log_query(client_addr, qname, qtype, "BLOCK", "NXDOMAIN")
                else:
                    response = DNSCodec.build_local_a_response(data, ip_addr)
                    self._send_response(response, client_addr)
                    self._log_query(client_addr, qname, qtype, "LOCAL", ip_addr)
                return

        # 检查缓存
        cached = self.cache.get(qname, qtype)
        if cached is not None:
            response = DNSCodec.replace_transaction_id(cached, header.transaction_id)
            self._send_response(response, client_addr)
            result = DNSCodec.extract_first_a_record(cached) or "CACHED"
            self._log_query(client_addr, qname, qtype, "CACHE", result)
            return

        # 转发上游 DNS
        self._forward_to_upstream(data, client_addr, header.transaction_id, qname, qtype)

    def _forward_to_upstream(
        self,
        query_data: bytes,
        client_addr: Tuple[str, int],
        transaction_id: int,
        qname: str,
        qtype: int,
    ) -> None:
        """将查询转发给上游 DNS，并返回响应。"""
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.settimeout(self.timeout)

        try:
            upstream.sendto(query_data, (self.upstream_host, self.upstream_port))
            response, _ = upstream.recvfrom(512)

            # 缓存成功响应
            if DNSCodec.is_success_response(response):
                self.cache.set(qname, qtype, response)

            # 保持原 Transaction ID（转发响应通常已一致，缓存命中时才需替换）
            response = DNSCodec.replace_transaction_id(response, transaction_id)
            self._send_response(response, client_addr)

            result = DNSCodec.extract_first_a_record(response) or "OK"
            self._log_query(client_addr, qname, qtype, "FORWARD", result)

        except socket.timeout:
            servfail = DNSCodec.build_servfail_response(query_data)
            self._send_response(servfail, client_addr)
            self._log_query(client_addr, qname, qtype, "ERROR", "SERVFAIL")

        except OSError as exc:
            logging.warning("上游 DNS 通信失败: %s", exc)
            servfail = DNSCodec.build_servfail_response(query_data)
            self._send_response(servfail, client_addr)
            self._log_query(client_addr, qname, qtype, "ERROR", "SERVFAIL")

        finally:
            upstream.close()


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DNS Relay - 通信与网络课程设计",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--listen-host", default="127.0.0.1", help="监听地址")
    parser.add_argument("--listen-port", type=int, default=1053, help="监听端口")
    parser.add_argument("--upstream", default="114.114.114.114", help="上游 DNS 地址")
    parser.add_argument("--upstream-port", type=int, default=53, help="上游 DNS 端口")
    parser.add_argument("--database", default="dnsrelay.txt", help="本地域名数据库文件")
    parser.add_argument("--timeout", type=float, default=3.0, help="上游 DNS 超时（秒）")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
    )

    relay = DNSRelay(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        upstream_host=args.upstream,
        upstream_port=args.upstream_port,
        database_path=args.database,
        timeout=args.timeout,
    )

    def handle_signal(signum, frame):
        logging.info("收到退出信号 (Ctrl+C)，正在关闭...")
        relay.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        relay.start()
    except KeyboardInterrupt:
        logging.info("收到 KeyboardInterrupt，正在关闭...")
        relay.stop()


if __name__ == "__main__":
    main()
