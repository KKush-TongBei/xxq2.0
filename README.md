# xxq2.0 — 通信与网络课程设计

北京邮电大学通信与网络课程设计项目：DNS Relay 实现。

## 项目结构

```
xxq2.0/
├── Real Code/              # 项目源码与文档（主要交付物）
│   ├── dnsrelay            # 课件标准入口脚本
│   ├── dnsrelay.py         # DNS Relay 主程序
│   ├── dnsrelay.txt        # 本地域名数据库
│   ├── README.md           # 运行与测试说明
│   └── test_cases.md       # 测试用例文档
└── 要求文件/               # 课程要求与参考资料
    ├── 通信与网络课程设计课件.pdf
    └── to students/        # 教师提供的参考文件
        ├── dnsrelay.exe    # 参考可执行程序
        ├── dnsrelay.txt    # 参考数据库示例
        ├── example_report.doc
        └── ...
```

## 快速开始

```bash
cd "Real Code"

# 课件标准格式（验收用，需 sudo）
sudo python3 dnsrelay.py -d

# 开发调试（无需 sudo）
python3 dnsrelay.py -d --listen-port 1053
```

详细说明见 [Real Code/README.md](Real%20Code/README.md)。

## 测试

```bash
cd "Real Code"
python3 dnsrelay.py -d --listen-port 1053

# 另开终端
nslookup -type=A blocked.com 127.0.0.1 -port=1053
nslookup -type=A local.test.com 127.0.0.1 -port=1053
nslookup -type=A www.baidu.com 127.0.0.1 -port=1053
dig @127.0.0.1 -p 1053 blocked.com AAAA   # AAAA 屏蔽测试
```

完整测试用例见 [Real Code/test_cases.md](Real%20Code/test_cases.md)。
