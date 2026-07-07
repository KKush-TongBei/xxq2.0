# DNS Relay 测试用例

本文档列出课程设计验收所需的三个核心测试 Case，以及预期结果与验证命令。

## 测试环境准备

1. 启动 DNS Relay：

```bash
cd "/Applications/School/xxq2.0/Real Code"
python3 dnsrelay.py
```

2. 确认 `dnsrelay.txt` 包含以下测试记录：

```
0.0.0.0 blocked.com
1.2.3.4 local.test.com
```

3. 在新终端执行测试命令。

---

## Case 1：屏蔽域名（0.0.0.0 → NXDOMAIN）

### 测试目的

验证本地数据库中 IP 为 `0.0.0.0` 的域名被屏蔽，返回 Name Error。

### 测试域名

`blocked.com`（本地库：`0.0.0.0 blocked.com`）

### 预期行为

| 项目 | 预期值 |
|------|--------|
| 处理方式 | `BLOCK` |
| RCODE | 3（NXDOMAIN） |
| 返回 IP | 无 |
| 日志关键字 | `BLOCK \| NXDOMAIN` |

### 测试命令

```bash
nslookup -type=A blocked.com 127.0.0.1 -port=1053
```

或使用 dig：

```bash
dig @127.0.0.1 -p 1053 blocked.com A
```

### 预期输出示例

```
** server can't find blocked.com: NXDOMAIN
```

Relay 日志：

```
... | blocked.com | A | BLOCK | NXDOMAIN
```

### Wireshark 验证要点

- DNS Response 中 Flags: Response, RCODE=NXDOMAIN (3)
- Answer Count = 0

---

## Case 2：本地命中正常 IP

### 测试目的

验证本地数据库命中时，Relay 直接构造 A 记录响应，不转发上游。

### 测试域名

`local.test.com`（本地库：`1.2.3.4 local.test.com`）

### 预期行为

| 项目 | 预期值 |
|------|--------|
| 处理方式 | `LOCAL` |
| RCODE | 0（NOERROR） |
| 返回 IP | `1.2.3.4` |
| ANCOUNT | 1 |
| TTL | 60 |
| 日志关键字 | `LOCAL \| 1.2.3.4` |

### 测试命令

```bash
nslookup -type=A local.test.com 127.0.0.1 -port=1053
```

或使用 dig：

```bash
dig @127.0.0.1 -p 1053 local.test.com A +short
```

### 预期输出示例

```
Name:   local.test.com
Address: 1.2.3.4
```

Relay 日志：

```
... | local.test.com | A | LOCAL | 1.2.3.4
```

### Wireshark 验证要点

- DNS Response: QR=1, RCODE=0
- Answer Section 含 1 条 A 记录，RDATA=1.2.3.4

---

## Case 3：本地未命中，转发上游 DNS

### 测试目的

验证不在本地数据库中的域名被转发给上游 DNS，且成功响应会被缓存。

### 测试域名

`www.baidu.com`（不在 `dnsrelay.txt` 中）

### 预期行为

| 项目 | 首次查询 | 二次查询（60秒内） |
|------|---------|-------------------|
| 处理方式 | `FORWARD` | `CACHE` |
| RCODE | 0（NOERROR） | 0（NOERROR） |
| 返回 IP | 上游解析结果 | 与首次相同 |
| 日志关键字 | `FORWARD` | `CACHE` |

### 测试命令

```bash
# 首次查询 — 应走 FORWARD
nslookup -type=A www.baidu.com 127.0.0.1 -port=1053

# 立即再次查询 — 应走 CACHE
nslookup -type=A www.baidu.com 127.0.0.1 -port=1053
```

或使用 dig：

```bash
dig @127.0.0.1 -p 1053 www.baidu.com A +short
dig @127.0.0.1 -p 1053 www.baidu.com A +short
```

### 预期输出示例

```
Name:   www.baidu.com
Address: 39.156.66.10
（实际 IP 可能因上游 DNS 而异）
```

Relay 日志：

```
... | www.baidu.com | A | FORWARD | 39.156.66.10
... | www.baidu.com | A | CACHE | 39.156.66.10
```

### Wireshark 验证要点

- 首次：客户端 → Relay → 上游 DNS（114.114.114.114:53）→ Relay → 客户端
- 二次：仅客户端 ↔ Relay，无上游流量

---

## 附加测试（可选）

### 非法报文不崩溃

向 Relay 发送非 DNS 数据（如 `echo "hello" | nc -u 127.0.0.1 1053`），程序应记录 `ERROR | INVALID_PACKET` 并继续运行。

### 上游超时 SERVFAIL

使用不可达的上游 DNS 启动：

```bash
python3 dnsrelay.py --upstream 192.0.2.1 --timeout 1.0
```

查询不在本地库的域名，应返回 SERVFAIL，日志显示 `ERROR | SERVFAIL`。

### 非 A 记录查询转发

```bash
dig @127.0.0.1 -p 1053 www.baidu.com MX
```

应走 `FORWARD` 路径（本地库仅完整支持 A 记录）。

---

## 验收检查清单

- [ ] Case 1：`blocked.com` 返回 NXDOMAIN，日志 `BLOCK`
- [ ] Case 2：`local.test.com` 返回 `1.2.3.4`，日志 `LOCAL`
- [ ] Case 3：`www.baidu.com` 首次 `FORWARD`，二次 `CACHE`
- [ ] 非法报文不导致程序崩溃
- [ ] Ctrl+C 可优雅退出
- [ ] Wireshark 可观察到正确的 DNS 报文结构
