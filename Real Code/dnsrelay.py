#!/usr/bin/env python3
"""
DNS Relay - 通信与网络课程设计

实现一个基于 UDP Socket 的 DNS 中继器：
  1. 查询本地数据库 dnsrelay.txt
  2. 屏蔽域名返回 NXDOMAIN（含 AAAA 查询）
  3. 本地命中返回 A 记录
  4. 未命中则转发上游 DNS，并缓存成功响应

命令行格式（对齐课件）:
  dnsrelay [-d | -dd] [dns-server-ipaddr] [filename]
"""

from __future__ import annotations

import argparse
import logging
import signal
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# 常量定义
# ---------------------------------------------------------------------------

class DNSConstants:
    """DNS 协议常用常量（RFC 1035）。"""

    TYPE_A = 1
    TYPE_AAAA = 28
    CLASS_IN = 1

    RCODE_NOERROR = 0
    RCODE_SERVFAIL = 2
    RCODE_NXDOMAIN = 3

    FLAG_QR = 0x8000
    FLAG_RCODE_MASK = 0x000F

    HEADER_SIZE = 12
    DEFAULT_TTL = 60
    CACHE_TTL = 60
    DEFAULT_UPSTREAM = "114.114.114.114"
    DEFAULT_DATABASE = "dnsrelay.txt"

    QTYPE_NAMES = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        15: "MX",
        16: "TXT",
        28: "AAAA",
    }

    RCODE_NAMES = {
        0: "NOERROR",
        1: "FORMAT_ERROR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
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
    """DNS Question Section: QNAME + QTYPE + QCLASS"""

    qname: str
    qtype: int
    qclass: int
    raw_qname: bytes
    end_offset: int


@dataclass
class PendingRequest:
    """上游转发时的 ID 映射表项。"""

    client_addr: Tuple[str, int]
    original_id: int
    timestamp: float


# ---------------------------------------------------------------------------
# DNS 编解码
# ---------------------------------------------------------------------------

class DNSCodec:
    """DNS 报文解析与构造工具。"""

    @staticmethod
    def qtype_name(qtype: int) -> str:
        return DNSConstants.QTYPE_NAMES.get(qtype, str(qtype))

    @staticmethod
    def rcode_name(rcode: int) -> str:
        return DNSConstants.RCODE_NAMES.get(rcode, str(rcode))

    @classmethod
    def describe_header(cls, data: bytes) -> str:
        """解析并描述 DNS Header，用于 -dd 详细调试输出。"""
        if len(data) < DNSConstants.HEADER_SIZE:
            return "报文过短，无法解析 Header"
        header = DNSHeader.unpack(data)
        qr = "Response" if header.is_response else "Query"
        rd = "RD" if header.flags & 0x0100 else ""
        ra = "RA" if header.flags & 0x0080 else ""
        flags_extra = " ".join(filter(None, [rd, ra]))
        return (
            f"ID=0x{header.transaction_id:04X} "
            f"QR={qr} "
            f"RCODE={cls.rcode_name(header.rcode)} "
            f"QD={header.qdcount} AN={header.ancount} "
            f"NS={header.nscount} AR={header.arcount}"
            + (f" [{flags_extra}]" if flags_extra else "")
        )

    @staticmethod
    def decode_qname(data: bytes, offset: int) -> Tuple[str, int]:
        """解析 QNAME（域名标签格式）。"""
        labels = []
        jumped = False
        original_offset = offset
        jumps = 0

        while True:
            if offset >= len(data):
                raise ValueError("QNAME 超出报文范围")

            length = data[offset]

            if length & 0xC0 == 0xC0:
                if offset + 1 >= len(data):
                    raise ValueError("压缩指针不完整")
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                if not jumped:
                    original_offset = offset + 2
                offset = pointer
                jumps += 1
                if jumps > 10:
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
        """解析 DNS 查询报文。"""
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
        nscount: int = 0,
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
            flags |= 0x0100
        flags |= rcode & DNSConstants.FLAG_RCODE_MASK

        header = DNSHeader(
            transaction_id=transaction_id,
            flags=flags,
            qdcount=1,
            ancount=ancount,
            nscount=nscount,
            arcount=0,
        )
        return header.pack()

    @classmethod
    def build_a_answer(cls, ip_address: str, ttl: int = DNSConstants.DEFAULT_TTL) -> bytes:
        """
        构造一条 A 记录 Answer Section。

        Answer RR: NAME(指针0xC00C) + TYPE + CLASS + TTL + RDLENGTH + RDATA
        """
        rdata = socket.inet_aton(ip_address)
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
        """构造 NXDOMAIN 响应（屏蔽域名，RCODE=3，ANCOUNT=0）。"""
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
    def replace_transaction_id(cls, packet_data: bytes, new_id: int) -> bytes:
        """替换报文前 2 字节的 Transaction ID。"""
        if len(packet_data) < 2:
            return packet_data
        return struct.pack("!H", new_id) + packet_data[2:]

    @classmethod
    def extract_first_a_record(cls, response_data: bytes) -> Optional[str]:
        """从响应中提取第一条 A 记录的 IPv4 地址。"""
        try:
            if len(response_data) < DNSConstants.HEADER_SIZE:
                return None
            header = DNSHeader.unpack(response_data)
            if header.ancount < 1:
                return None

            offset = DNSConstants.HEADER_SIZE
            for _ in range(header.qdcount):
                _, offset = cls.decode_qname(response_data, offset)
                offset += 4

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
# ID 映射表（并发转发）
# ---------------------------------------------------------------------------

class IDMapper:
    """
    上游转发 ID 映射表（IDTransition）。

    转发时将客户端 Transaction ID 改写为内部 ID，避免并发查询时
    多个客户端使用相同 ID 导致响应张冠李戴。
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self._lock = threading.Lock()
        self._next_id = 1
        self._pending: Dict[int, PendingRequest] = {}
        self._timeout = timeout

    def allocate(self, client_addr: Tuple[str, int], original_id: int) -> int:
        with self._lock:
            self._purge_expired_locked()
            internal_id = self._next_id
            self._next_id = (self._next_id + 1) % 0x10000
            if self._next_id == 0:
                self._next_id = 1
            self._pending[internal_id] = PendingRequest(
                client_addr=client_addr,
                original_id=original_id,
                timestamp=time.time(),
            )
            return internal_id

    def pop(self, internal_id: int) -> Optional[PendingRequest]:
        with self._lock:
            return self._pending.pop(internal_id, None)

    def _purge_expired_locked(self) -> None:
        now = time.time()
        expired = [
            iid
            for iid, req in self._pending.items()
            if now - req.timestamp >= self._timeout
        ]
        for iid in expired:
            del self._pending[iid]


# ---------------------------------------------------------------------------
# 本地数据库
# ---------------------------------------------------------------------------

class DNSDatabase:
    """加载并查询 dnsrelay.txt 本地域名库。"""

    def __init__(self, filepath: str, debug_level: int = 0) -> None:
        self.filepath = filepath
        self.debug_level = debug_level
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
                        if self.debug_level >= 1:
                            logging.warning("忽略无效行 %d: %s", line_no, line)
                        continue
                    ip_addr, domain = parts[0], parts[1].lower()
                    self.records[domain] = ip_addr
        except FileNotFoundError:
            print(f"错误: 数据库文件不存在: {self.filepath}", file=sys.stderr)
            raise SystemExit(1)

        if self.debug_level >= 1:
            logging.info(
                "已加载本地数据库 %s，共 %d 条记录",
                self.filepath,
                len(self.records),
            )

    def lookup(self, domain: str) -> Optional[str]:
        return self.records.get(domain.lower())


# ---------------------------------------------------------------------------
# 响应缓存
# ---------------------------------------------------------------------------

class DNSCache:
    """上游 DNS 成功响应缓存，默认 TTL 60 秒。"""

    def __init__(self, ttl: int = DNSConstants.CACHE_TTL) -> None:
        self.ttl = ttl
        self._lock = threading.Lock()
        self._store: Dict[Tuple[str, int], Tuple[bytes, float]] = {}

    def _purge_expired_locked(self) -> None:
        now = time.time()
        expired = [k for k, (_, ts) in self._store.items() if now - ts >= self.ttl]
        for key in expired:
            del self._store[key]

    def get(self, qname: str, qtype: int) -> Optional[bytes]:
        with self._lock:
            self._purge_expired_locked()
            entry = self._store.get((qname.lower(), qtype))
            if entry is None:
                return None
            data, ts = entry
            if time.time() - ts >= self.ttl:
                del self._store[(qname.lower(), qtype)]
                return None
            return data

    def set(self, qname: str, qtype: int, response_data: bytes) -> None:
        with self._lock:
            self._purge_expired_locked()
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
        debug_level: int = 0,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.timeout = timeout
        self.debug_level = debug_level
        self.database = DNSDatabase(database_path, debug_level=debug_level)
        self.cache = DNSCache()
        self.id_mapper = IDMapper(timeout=timeout + 5)
        self.running = True
        self.sock: Optional[socket.socket] = None
        self._send_lock = threading.Lock()

    def start(self) -> None:
        """绑定端口并进入主循环（每查询一线程）。"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.listen_host, self.listen_port))

        if self.debug_level >= 1:
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
                worker = threading.Thread(
                    target=self._handle_query,
                    args=(data, client_addr),
                    daemon=True,
                )
                worker.start()
            except OSError:
                if self.running:
                    if self.debug_level >= 1:
                        logging.exception("接收数据时发生错误")
                break

    def stop(self) -> None:
        self.running = False
        if self.sock:
            self.sock.close()
            self.sock = None
        if self.debug_level >= 1:
            logging.info("DNS Relay 已停止")

    def _log_packet(self, direction: str, data: bytes) -> None:
        """-dd 模式：打印报文十六进制与 Header 解析。"""
        if self.debug_level < 2:
            return
        logging.info("[%s] %d bytes: %s", direction, len(data), data.hex())
        logging.info("  %s", DNSCodec.describe_header(data))

    def _log_query(
        self,
        client_addr: Tuple[str, int],
        qname: str,
        qtype: int,
        action: str,
        result: str,
    ) -> None:
        """-d / -dd 模式：打印查询处理摘要。"""
        if self.debug_level < 1:
            return
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        client = f"{client_addr[0]}:{client_addr[1]}"
        logging.info(
            "%s | %s | %s | %s | %s | %s",
            timestamp,
            client,
            qname,
            DNSCodec.qtype_name(qtype),
            action,
            result,
        )

    def _send_response(self, response: bytes, client_addr: Tuple[str, int]) -> None:
        with self._send_lock:
            if self.sock:
                self.sock.sendto(response, client_addr)
        self._log_packet("SEND", response)

    def _handle_query(self, data: bytes, client_addr: Tuple[str, int]) -> None:
        """处理一条 DNS 查询。"""
        self._log_packet("RECV", data)

        try:
            header, question = DNSCodec.parse_query(data)
        except (ValueError, struct.error) as exc:
            if self.debug_level >= 1:
                logging.warning(
                    "非法 DNS 报文来自 %s:%d: %s",
                    client_addr[0],
                    client_addr[1],
                    exc,
                )
            self._log_query(client_addr, "?", 0, "ERROR", "INVALID_PACKET")
            return

        qname = question.qname
        qtype = question.qtype
        ip_addr = self.database.lookup(qname)

        # Case 1: 屏蔽域名 — 任意 QTYPE（含 AAAA）均返回 NXDOMAIN
        if ip_addr == "0.0.0.0":
            response = DNSCodec.build_nxdomain_response(data)
            self._send_response(response, client_addr)
            self._log_query(client_addr, qname, qtype, "BLOCK", "NXDOMAIN")
            return

        # Case 2: 本地 A 记录命中
        if (
            qtype == DNSConstants.TYPE_A
            and question.qclass == DNSConstants.CLASS_IN
            and ip_addr is not None
        ):
            response = DNSCodec.build_local_a_response(data, ip_addr)
            self._send_response(response, client_addr)
            self._log_query(client_addr, qname, qtype, "LOCAL", ip_addr)
            return

        # 缓存命中
        cached = self.cache.get(qname, qtype)
        if cached is not None:
            response = DNSCodec.replace_transaction_id(cached, header.transaction_id)
            self._send_response(response, client_addr)
            result = DNSCodec.extract_first_a_record(cached) or "CACHED"
            self._log_query(client_addr, qname, qtype, "CACHE", result)
            return

        # Case 3: 转发上游 DNS
        self._forward_to_upstream(data, client_addr, header.transaction_id, qname, qtype)

    def _forward_to_upstream(
        self,
        query_data: bytes,
        client_addr: Tuple[str, int],
        transaction_id: int,
        qname: str,
        qtype: int,
    ) -> None:
        """将查询转发给上游 DNS（改写 ID 防并发冲突），并返回响应。"""
        internal_id = self.id_mapper.allocate(client_addr, transaction_id)
        forward_query = DNSCodec.replace_transaction_id(query_data, internal_id)

        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.settimeout(self.timeout)

        try:
            if self.debug_level >= 2:
                logging.info(
                    "转发上游: client_id=0x%04X -> internal_id=0x%04X -> %s:%d",
                    transaction_id,
                    internal_id,
                    self.upstream_host,
                    self.upstream_port,
                )

            self._log_packet("FWD_SEND", forward_query)
            upstream.sendto(forward_query, (self.upstream_host, self.upstream_port))
            response, _ = upstream.recvfrom(512)
            self._log_packet("FWD_RECV", response)

            # 将上游响应 ID 映射回客户端原始 ID
            response = DNSCodec.replace_transaction_id(response, transaction_id)
            self.id_mapper.pop(internal_id)

            if DNSCodec.is_success_response(response):
                # 缓存时使用原始 ID 无关的响应体（以 internal_id 收到的）
                cache_data = DNSCodec.replace_transaction_id(response, internal_id)
                self.cache.set(qname, qtype, cache_data)

            self._send_response(response, client_addr)
            result = DNSCodec.extract_first_a_record(response) or "OK"
            self._log_query(client_addr, qname, qtype, "FORWARD", result)

        except socket.timeout:
            self.id_mapper.pop(internal_id)
            servfail = DNSCodec.build_servfail_response(query_data)
            self._send_response(servfail, client_addr)
            self._log_query(client_addr, qname, qtype, "ERROR", "SERVFAIL")

        except OSError as exc:
            self.id_mapper.pop(internal_id)
            if self.debug_level >= 1:
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
    """
    解析命令行参数，对齐课件格式:
      dnsrelay [-d | -dd] [dns-server-ipaddr] [filename]
    """
    parser = argparse.ArgumentParser(
        description="DNS Relay - 通信与网络课程设计",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        usage="%(prog)s [-d | -dd] [dns-server-ipaddr] [filename] [options]",
        allow_abbrev=False,
    )
    parser.add_argument(
        "-d",
        action="store_const",
        const=1,
        dest="debug_level",
        help="调试模式：打印查询摘要日志",
    )
    parser.add_argument(
        "-dd",
        action="store_const",
        const=2,
        dest="debug_level",
        help="详细调试：打印查询日志 + 报文十六进制 + Header 解析",
    )
    parser.add_argument(
        "dns_server",
        nargs="?",
        default=DNSConstants.DEFAULT_UPSTREAM,
        help="上游 DNS 服务器地址",
    )
    parser.add_argument(
        "filename",
        nargs="?",
        default=DNSConstants.DEFAULT_DATABASE,
        help="本地域名数据库文件",
    )
    parser.add_argument(
        "--listen-host",
        default="0.0.0.0",
        help="监听地址（课件验收绑定 0.0.0.0）",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=53,
        help="监听端口（开发调试可用 1053 免 sudo）",
    )
    parser.add_argument(
        "--dns-server-port",
        type=int,
        default=53,
        help="上游 DNS 端口",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="上游 DNS 超时（秒）",
    )
    parser.set_defaults(debug_level=0)
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # 无 -d/-dd 时静默运行
    if args.debug_level >= 1:
        logging.basicConfig(level=logging.INFO, format="%(message)s")
    else:
        logging.basicConfig(level=logging.CRITICAL + 1)

    relay = DNSRelay(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        upstream_host=args.dns_server,
        upstream_port=args.dns_server_port,
        database_path=args.filename,
        timeout=args.timeout,
        debug_level=args.debug_level,
    )

    def handle_signal(signum, frame):
        if args.debug_level >= 1:
            logging.info("收到退出信号 (Ctrl+C)，正在关闭...")
        relay.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        relay.start()
    except KeyboardInterrupt:
        if args.debug_level >= 1:
            logging.info("收到 KeyboardInterrupt，正在关闭...")
        relay.stop()
    except PermissionError:
        print(
            "错误: 绑定端口 %d 需要管理员权限。\n"
            "请使用 sudo 运行，或指定 --listen-port 1053 进行开发调试。"
            % args.listen_port,
            file=sys.stderr,
        )
        sys.exit(1)
    except OSError as exc:
        if exc.errno in (48, 98, 10048):  # Address already in use
            print(
                "错误: 端口 %d 已被占用。请关闭占用进程或使用 --listen-port 1053。"
                % args.listen_port,
                file=sys.stderr,
            )
            sys.exit(1)
        raise


if __name__ == "__main__":
    main()
