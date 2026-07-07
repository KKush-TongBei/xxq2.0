# DNS Relay 课程设计

基于 Python 3 标准库实现的 DNS 中继器（DNS Relay），用于通信与网络课程设计。

## 功能简介

DNS Relay 位于 DNS 客户端（Resolver）与 DNS 服务器之间，根据本地数据库决定如何处理查询：

| 处理方式 | 说明 |
|---------|------|
| **BLOCK** | 本地库中 IP 为 `0.0.0.0`，返回 NXDOMAIN（RCODE=3） |
| **LOCAL** | 本地库命中正常 IPv4，直接构造 A 记录响应 |
| **FORWARD** | 域名不在本地库（或非 A 查询），转发给上游 DNS |
| **CACHE** | 上游成功响应缓存 60 秒，再次查询直接返回 |
| **ERROR** | 非法报文丢弃，上游超时返回 SERVFAIL |

## 环境要求

- Python 3.8 或更高版本
- 无需安装第三方库
- 可选：`nslookup` / `dig` 用于测试，Wireshark 用于抓包分析

## 项目文件

```
dnsrelay.py      # 主程序
dnsrelay.txt     # 本地域名数据库
README.md        # 本说明文档
test_cases.md    # 测试用例文档
```

## 本地数据库格式

`dnsrelay.txt` 每行一条记录，格式为：

```
IP domain
```

示例：

```
0.0.0.0 blocked.com
1.2.3.4 local.test.com
```

- `0.0.0.0` 表示屏蔽该域名
- 以 `#` 开头的行为注释

## 运行方法

### 默认启动

```bash
cd /Applications/School/xxq2.0
python3 dnsrelay.py
```

默认配置：

- 监听地址：`127.0.0.1:1053`
- 上游 DNS：`114.114.114.114:53`
- 数据库文件：`dnsrelay.txt`

> 使用端口 `1053` 而非 `53`，避免需要 root/管理员权限。

### 自定义参数

```bash
python3 dnsrelay.py \
  --listen-host 127.0.0.1 \
  --listen-port 1053 \
  --upstream 114.114.114.114 \
  --upstream-port 53 \
  --database dnsrelay.txt \
  --timeout 3.0
```

### 优雅退出

在运行终端按 `Ctrl+C`，程序会打印退出信息并关闭 Socket。

## 测试方法

### 1. 启动 DNS Relay

```bash
python3 dnsrelay.py
```

启动后会看到类似日志：

```
已加载本地数据库 dnsrelay.txt，共 4 条记录
DNS Relay 已启动 | 监听 127.0.0.1:1053 | 上游 114.114.114.114:53 | 数据库 dnsrelay.txt
```

### 2. 使用 nslookup 测试（macOS / Linux）

新开一个终端：

```bash
# Case 1: 屏蔽域名
nslookup -type=A blocked.com 127.0.0.1 -port=1053

# Case 2: 本地命中
nslookup -type=A local.test.com 127.0.0.1 -port=1053

# Case 3: 转发上游（首次 FORWARD，再次 CACHE）
nslookup -type=A www.baidu.com 127.0.0.1 -port=1053
nslookup -type=A www.baidu.com 127.0.0.1 -port=1053
```

### 3. 使用 dig 测试

```bash
dig @127.0.0.1 -p 1053 blocked.com A +short
dig @127.0.0.1 -p 1053 local.test.com A +short
dig @127.0.0.1 -p 1053 www.baidu.com A +short
```

### 4. Wireshark 抓包

1. 启动 Wireshark，过滤器输入：`udp.port == 1053`
2. 运行上述 nslookup 命令
3. 观察 DNS 查询/响应报文的 Header、Question、Answer 字段

### 5. 日志对照

Relay 终端会输出每条查询的处理日志，格式：

```
2026-07-07 14:00:01 | 127.0.0.1:54321 | local.test.com | A | LOCAL | 1.2.3.4
2026-07-07 14:00:02 | 127.0.0.1:54322 | blocked.com | A | BLOCK | NXDOMAIN
2026-07-07 14:00:03 | 127.0.0.1:54323 | www.baidu.com | A | FORWARD | 39.156.66.10
2026-07-07 14:00:04 | 127.0.0.1:54324 | www.baidu.com | A | CACHE | 39.156.66.10
```

## 配置系统 DNS（可选）

若要将本机 DNS 指向 Relay（需监听 53 端口并以管理员权限运行）：

```bash
sudo python3 dnsrelay.py --listen-port 53
```

课程设计验收推荐使用 `127.0.0.1:1053` + `nslookup -port=1053` 方式，无需修改系统 DNS。

## 常见问题

**Q: 端口被占用怎么办？**

```bash
python3 dnsrelay.py --listen-port 1054
```

**Q: 上游 DNS 超时？**

检查网络连接，或更换上游 DNS：

```bash
python3 dnsrelay.py --upstream 8.8.8.8
```

**Q: Windows 下 nslookup 如何指定端口？**

Windows 自带 nslookup 不支持 `-port` 参数，建议使用 `dig`（安装 BIND 工具）或 Python 脚本发送 UDP 查询。

## 课程设计对应关系

| 课件 Case | 本程序行为 |
|-----------|-----------|
| Case 1: IP 为 0.0.0.0 | BLOCK，返回 NXDOMAIN |
| Case 2: 本地库命中 | LOCAL，返回对应 IP |
| Case 3: 不在本地库 | FORWARD 转发上游 DNS |
