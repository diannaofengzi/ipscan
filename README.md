# 端口扫描器 (Port Scanner)

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

一个高性能、模块化的端口扫描工具，支持 IPv4/IPv6 双栈，支持代理，默认扫描常见高危端口。

## ⚠️ 法律声明

**本工具仅用于授权的安全测试和网络管理**

- 仅限用于您拥有或已获书面授权的网络
- 未经授权使用本工具扫描他人网络可能违反法律法规
- 使用者需自行承担法律责任

## ✨ 主要特性

### 核心功能
- 🌐 **IPv4/IPv6 双栈支持** - 同时支持两种 IP 协议版本
- 🔒 **代理支持** - SOCKS4/5, HTTP/HTTPS 代理
- ⚡ **高性能扫描** - 基于 asyncio 的异步架构
- 🎯 **智能服务识别** - 自动识别常见服务和获取 banner
- 📊 **实时结果显示** - 发现开放端口立即展示详细信息
- 🛡️ **安全加固** - 输入验证、资源管理、速率限制

### 默认扫描的高危端口
| 端口 | 服务 | 风险等级 | 说明 |
|------|------|----------|------|
| 22 | SSH | 高 | 远程登录服务 |
| 23 | Telnet | 极高 | 明文远程管理 |
| 3389 | RDP | 高 | Windows 远程桌面 |
| 3306 | MySQL | 高 | 数据库服务 |
| 6379 | Redis | 高 | 常未授权访问 |
| 27017 | MongoDB | 高 | 常未授权访问 |
| 445 | SMB | 高 | 文件共享 |
| 80/443 | HTTP/HTTPS | 中 | Web 服务 |
| ... | ... | ... | 共 26 个高危端口 |

完整端口列表见源代码中的 `HIGH_RISK_PORTS`。

## 📦 安装

### 环境要求
- Python 3.7+
- 无需额外依赖（基础功能）

### 可选依赖
如需使用 SOCKS 代理，安装以下任一库：
```bash
pip install socksio
# 或
pip install PySocks
```

### 克隆仓库
```bash
git clone <repository-url>
cd ipscan
```

## 🚀 快速开始

### 基本用法

```bash
# 扫描单个 IP
python portscan.py -i 192.168.1.1

# 扫描网段
python portscan.py -i 192.168.1.0/24

# 扫描 IPv6
python portscan.py -i 2001:db8::1

# 混合扫描
python portscan.py -i 192.168.1.0/24 2001:db8::/64
```

### 高级用法

```bash
# 从文件读取 IP 列表
python portscan.py -f ip_list.txt

# 自定义扫描端口
python portscan.py -i 10.0.0.0/8 --ports 22 3306 6379

# 使用代理
python portscan.py -i 192.168.1.0/24 --proxy socks5://127.0.0.1:1080
python portscan.py -i 192.168.1.0/24 --proxy http://proxy.example.com:8080

# 调整并发数和超时
python portscan.py -i 192.168.1.0/24 -t 200 -T 1.0

# 输出报告到文件
python portscan.py -i 192.168.1.0/24 -o report.txt

# 禁用实时显示
python portscan.py -i 192.168.1.0/24 --no-realtime

# 使用同步模式（兼容旧版）
python portscan.py -i 192.168.1.0/24 --sync
```

### 测试代理
```bash
python portscan.py --proxy socks5://127.0.0.1:1080 --test-proxy
```

## 📖 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-i, --ip` | IP 地址或网段（CIDR），可多个 | 必需* |
| `-f, --file` | 包含 IP 列表的文件路径 | 必需* |
| `-t, --threads` | 并发线程/协程数 | 100 |
| `-T, --timeout` | 连接超时时间（秒） | 0.5 |
| `-o, --output` | 输出报告文件路径 | - |
| `-v, --verbose` | 显示详细进度 | False |
| `--no-realtime` | 禁用实时显示 | False |
| `--ports` | 自定义扫描端口列表 | 高危端口列表 |
| `--sync` | 使用同步模式 | False |
| `--proxy` | 代理服务器 URL | - |
| `--test-proxy` | 测试代理后退出 | False |

*`-i` 和 `-f` 二选一

## 📁 项目结构

```
ipscan/
├── portscan.py          # 主扫描程序
├── ip_parser.py         # IP 地址解析模块
├── proxy_support.py     # 代理支持模块
├── README.md            # 本文档
├── SECURITY_AUDIT.md    # 安全审计报告
├── MODULE_REFACTOR.md   # 重构文档
└── IPV6_SUPPORT.md      # IPv6 支持说明
```

## 🔧 模块说明

### 1. portscan.py
核心扫描模块，提供：
- 端口扫描功能（同步/异步）
- 服务识别和 banner 获取
- 结果报告和可视化

### 2. ip_parser.py
IP 地址解析模块，支持：
- IPv4/IPv6 地址解析
- CIDR 网段解析
- 文件批量导入

### 3. proxy_support.py
代理支持模块，提供：
- SOCKS4/5 代理
- HTTP/HTTPS 代理
- 代理 URL 解析

## 🛡️ 安全改进

最新版本进行了全面的安全加固：

### 已修复的漏洞
1. **资源泄漏** - 确保 socket 正确关闭
2. **输入验证** - 添加参数类型和范围检查
3. **DoS 风险** - 限制 banner 接收数据量
4. **异常处理** - 替换裸 except 子句
5. **速率限制** - 添加扫描速率控制

详见 [SECURITY_AUDIT.md](SECURITY_AUDIT.md)

## 📝 输出示例

```
🎯 开始异步扫描 256 个 IP 地址 (IPv4: 256, IPv6: 0)
   目标端口：[22, 23, 3389, ...]
⚙️  最大并发数：100, 超时时间：0.5s

============================================================
✅ [15/256] 发现开放端口 - 192.168.1.10 (IPv4)
============================================================

  🔌 端口：22
     服务名称：SSH
     服务类型：SSH 服务
     常见用途：远程登录，文件传输
     服务横幅：SSH-2.0-OpenSSH_8.2p1...

  🔌 端口：80
     服务名称：HTTP
     服务类型：HTTP/Web 服务
     常见用途：Web 服务
============================================================

📊 进度：100/256 (245.3 IP/s), 发现 5 个开放端口的主机
```

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

### 开发指南
1. Fork 本仓库
2. 创建特性分支
3. 提交变更
4. 推送到分支
5. 创建 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## ⚠️ 免责声明

本工具仅供教育和研究目的使用：
- 仅限用于授权的安全测试
- 不得用于非法目的
- 使用者需遵守当地法律法规

因不当使用造成的任何后果，作者不承担任何责任。

## 📞 联系方式

如有问题或建议，请通过 Issue 联系我们。

---

**Happy Scanning! 🎉** 请始终负责任地使用本工具。
