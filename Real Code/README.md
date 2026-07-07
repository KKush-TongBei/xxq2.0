# DNS Relay 课程设计

基于 Python 3 标准库实现的 DNS 中继器（DNS Relay），用于通信与网络课程设计。

## 功能简介

| 处理方式 | 说明 |
|---------|------|
| **BLOCK** | 本地库中 IP 为 `0.0.0.0`，任意记录类型均返回 NXDOMAIN |
| **LOCAL** | 本地库命中正常 IPv4，直接构造 A 记录响应 |
| **FORWARD** | 域名不在本地库（或非 A 查询），转发给上游 DNS |
| **CACHE** | 上游成功响应缓存 60 秒，再次查询直接返回 |
| **ERROR** | 非法报文丢弃，上游超时返回 SERVFAIL |

## 命令行格式（对齐课件）

```
dnsrelay [-d | -dd] [dns-server-ipaddr] [filename]
```

| 参数 | 说明 |
|------|------|
| 无参数 | 静默运行，使用默认上游 `114.114.114.114` 和 `dnsrelay.txt` |
| `-d` | 调试模式：打印查询摘要日志 |
| `-dd` | 详细调试：查询日志 + 报文十六进制 + Header 字段解析 |
| `dns-server-ipaddr` | 上游 DNS 地址（可选，默认 `114.114.114.114`） |
| `filename` | 本地数据库文件（可选，默认 `dnsrelay.txt`） |

### 示例

```bash
# 课件标准入口（与 dnsrelay.py 等价）
./dnsrelay -d 114.114.114.114 dnsrelay.txt

# 课件标准启动（需 sudo 绑定 53 端口）
sudo python3 dnsrelay.py
# 或
sudo ./dnsrelay

# 带调试日志
sudo python3 dnsrelay.py -d

# 指定上游 DNS 和数据库
sudo python3 dnsrelay.py -d 114.114.114.114 dnsrelay.txt

# 详细报文调试
sudo python3 dnsrelay.py -dd 8.8.8.8 dnsrelay.txt

# 开发调试（无需 sudo，使用 1053 端口）
python3 dnsrelay.py -d --listen-port 1053
```

### 扩展参数（开发用）

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--listen-host` | `0.0.0.0` | 监听地址 |
| `--listen-port` | `53` | 监听端口 |
| `--dns-server-port` | `53` | 上游 DNS 端口 |
| `--timeout` | `3.0` | 上游超时（秒） |

## 环境要求

- Python 3.8+
- 无需第三方库
- 绑定 53 端口需管理员权限（`sudo`）

## 项目文件

```
Real Code/
├── dnsrelay.py      # 主程序
├── dnsrelay.txt     # 本地域名数据库
├── README.md        # 本说明文档
└── test_cases.md    # 测试用例文档
```

## 本地数据库格式

```
IP domain
```

示例：

```
0.0.0.0 blocked.com
1.2.3.4 local.test.com
```

## 测试方法

### 方式一：开发调试（推荐，无需改系统 DNS）

```bash
cd "Real Code"
python3 dnsrelay.py -d --listen-port 1053
```

另开终端：

```bash
nslookup -type=A blocked.com 127.0.0.1 -port=1053
nslookup -type=A local.test.com 127.0.0.1 -port=1053
nslookup -type=A www.baidu.com 127.0.0.1 -port=1053
dig @127.0.0.1 -p 1053 blocked.com AAAA    # 验证 AAAA 屏蔽
```

### 方式二：课件验收（系统 DNS + 53 端口）

1. 以管理员权限启动：

```bash
sudo python3 dnsrelay.py -d
```

2. 将系统 DNS 设为 `127.0.0.1`（Windows 网络适配器 / macOS 系统偏好设置）

3. 测试：

```bash
nslookup blocked.com
ping local.test.com
# 浏览器访问 local.test.com
```

### Wireshark 抓包

过滤器：`udp.port == 53` 或 `udp.port == 1053`

## 并发与 ID 映射

程序使用多线程处理并发查询。转发上游时通过 **ID 映射表（IDTransition）** 将客户端 Transaction ID 改写为内部 ID，避免多客户端 ID 冲突导致响应错乱。

## 课程设计对应关系

| 课件 Case | 本程序行为 |
|-----------|-----------|
| Case 1: IP 为 0.0.0.0 | BLOCK，任意 QTYPE 返回 NXDOMAIN |
| Case 2: 本地库命中 | LOCAL，返回对应 A 记录 |
| Case 3: 不在本地库 | FORWARD 转发上游 DNS |

## 常见问题

**Q: 端口 53 权限不足？**

```bash
python3 dnsrelay.py -d --listen-port 1053
```

**Q: Windows nslookup 不支持 `-port`？**

使用 `dig` 或绑 53 端口 + 修改系统 DNS。

**Q: 如何查看报文细节？**

使用 `-dd` 参数，会打印每条收发包十六进制和 Header 解析。
