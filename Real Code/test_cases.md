# DNS Relay 测试用例

本文档列出课程设计验收所需的测试 Case 及验证命令。

## 测试环境准备

### 开发调试模式（推荐）

```bash
cd "/Applications/School/xxq2.0/Real Code"
python3 dnsrelay.py -d --listen-port 1053
```

### 课件验收模式

```bash
cd "/Applications/School/xxq2.0/Real Code"
sudo python3 dnsrelay.py -d
# 同时将系统 DNS 设为 127.0.0.1
```

确认 `dnsrelay.txt` 包含：

```
0.0.0.0 blocked.com
1.2.3.4 local.test.com
```

---

## Case 1：屏蔽域名（0.0.0.0 → NXDOMAIN）

### 测试域名

`blocked.com`

### 预期行为

| 项目 | 预期值 |
|------|--------|
| 处理方式 | `BLOCK` |
| RCODE | 3（NXDOMAIN） |
| 日志关键字 | `BLOCK \| NXDOMAIN` |

### 测试命令

```bash
# A 记录
nslookup -type=A blocked.com 127.0.0.1 -port=1053

# AAAA 记录（验证 IPv6 查询也被屏蔽）
dig @127.0.0.1 -p 1053 blocked.com AAAA
```

### 预期结果

- A 查询：`** server can't find blocked.com: NXDOMAIN`
- AAAA 查询：同样返回 NXDOMAIN（不再转发上游）

---

## Case 2：本地命中正常 IP

### 测试域名

`local.test.com`（`1.2.3.4 local.test.com`）

### 预期行为

| 项目 | 预期值 |
|------|--------|
| 处理方式 | `LOCAL` |
| 返回 IP | `1.2.3.4` |
| 日志关键字 | `LOCAL \| 1.2.3.4` |

### 测试命令

```bash
nslookup -type=A local.test.com 127.0.0.1 -port=1053
dig @127.0.0.1 -p 1053 local.test.com A +short
```

### 预期结果

```
Address: 1.2.3.4
```

---

## Case 3：本地未命中，转发上游 DNS

### 测试域名

`www.baidu.com`

### 预期行为

| 项目 | 首次查询 | 二次查询（60秒内） |
|------|---------|-------------------|
| 处理方式 | `FORWARD` | `CACHE` |
| 日志关键字 | `FORWARD` | `CACHE` |

### 测试命令

```bash
nslookup -type=A www.baidu.com 127.0.0.1 -port=1053
nslookup -type=A www.baidu.com 127.0.0.1 -port=1053
```

---

## Case 4：调试级别验证

### 静默模式（无参数）

```bash
python3 dnsrelay.py --listen-port 1053
```

预期：终端无查询日志输出。

### -d 模式

```bash
python3 dnsrelay.py -d --listen-port 1053
```

预期：打印查询摘要，如 `... | blocked.com | A | BLOCK | NXDOMAIN`。

### -dd 模式

```bash
python3 dnsrelay.py -dd --listen-port 1053
```

预期：除查询摘要外，还打印 `[RECV]`/`[SEND]` 十六进制报文和 Header 解析。

---

## Case 5：课件命令格式验证

```bash
python3 dnsrelay.py -d 114.114.114.114 dnsrelay.txt --listen-port 1053
```

预期：使用指定上游 DNS 和数据库文件正常启动。

---

## Case 6：异常处理

### 非法报文

```bash
echo "hello" | nc -u -w1 127.0.0.1 1053
```

预期：程序不崩溃，`-d` 模式下日志显示 `ERROR | INVALID_PACKET`。

### 上游超时

```bash
python3 dnsrelay.py -d 192.0.2.1 dnsrelay.txt --listen-port 1053 --timeout 1
```

查询不在本地库的域名，预期返回 SERVFAIL。

### 优雅退出

按 `Ctrl+C`，预期程序正常关闭。

---

## 验收检查清单

- [ ] Case 1：`blocked.com` A 记录返回 NXDOMAIN
- [ ] Case 1 扩展：`blocked.com` AAAA 记录也返回 NXDOMAIN
- [ ] Case 2：`local.test.com` 返回 `1.2.3.4`
- [ ] Case 3：`www.baidu.com` 首次 FORWARD，二次 CACHE
- [ ] Case 4：`-d` / `-dd` / 静默三种模式正确
- [ ] Case 5：课件命令格式 `dnsrelay [-d|-dd] [upstream] [file]` 可用
- [ ] Case 6：非法报文不崩溃，Ctrl+C 优雅退出
- [ ] （可选）课件验收：`sudo` + 53 端口 + 系统 DNS + `nslookup`/`ping`/浏览器
