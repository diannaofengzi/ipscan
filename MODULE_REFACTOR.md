# 端口扫描器 - 模块化重构说明

## 概述
本次重构将端口扫描器改造为模块化设计，支持 IPv4/IPv6 双栈扫描，新增代理支持，并将默认扫描端口改为常见高危端口。

## 主要变更

### 1. 模块化 IP 解析 (`ip_parser.py`)
- **ParseIPv4**: 专门处理 IPv4 地址和 CIDR 网段解析
- **ParseIPv6**: 专门处理 IPv6 地址和 CIDR 网段解析
- **IPParser**: 统一入口，自动检测 IP 版本并路由到相应解析器

```python
from ip_parser import ParseIPv4, ParseIPv6, IPParser

# 使用示例
ipv4_list = ParseIPv4.parse('192.168.1.0/24')
ipv6_list = ParseIPv6.parse('2001:db8::/64')
mixed_list = IPParser.parse_list(['192.168.1.1', '2001:db8::1'])
```

### 2. 代理支持模块 (`proxy_support.py`)
- **ProxyType**: 枚举类型，支持 SOCKS4、SOCKS5、HTTP、HTTPS
- **ProxyConfig**: 代理配置类，支持从 URL 解析配置
- **ProxySocket**: 支持代理的 Socket 包装器

```python
from proxy_support import ProxyConfig, ProxySocket

# 从 URL 创建配置
config = ProxyConfig.from_url('socks5://user:pass@127.0.0.1:1080')
config = ProxyConfig.from_url('http://proxy.example.com:8080')

# 测试代理连接
from proxy_support import test_proxy_connectivity
test_proxy_connectivity(config)
```

### 3. 主程序更新 (`portscan.py`)

#### 默认高危端口列表
现在默认扫描 26 个常见高危端口：
- **远程管理**: 22(SSH), 23(Telnet), 3389(RDP)
- **数据库**: 1433(MSSQL), 1521(Oracle), 3306(MySQL), 5432(PG), 6379(Redis), 27017(MongoDB)
- **Web 服务**: 80(HTTP), 443(HTTPS), 8080, 8443
- **文件共享**: 21(FTP), 445(SMB), 139(NetBIOS)
- **邮件服务**: 25(SMTP), 110(POP3), 143(IMAP)
- **其他高危**: 135(RPC), 5900(VNC), 11211(Memcached), 9200/9300(Elasticsearch)
- **自定义**: 19890, 18789 (保留原默认端口)

#### 新增命令行参数
```bash
--proxy PROXY       # 代理服务器 URL (支持 socks4://, socks5://, http://, https://)
--test-proxy        # 测试代理连接性后退出
--ports PORTS       # 自定义扫描端口（默认高危端口列表）
-t THREADS          # 并发数默认提升至 100
-T TIMEOUT          # 超时默认优化为 0.5 秒
```

### 4. 服务识别增强
更新了 `KNOWN_SERVICES` 字典，包含所有高危端口的详细信息：
- 服务名称
- 描述
- 常见用途
- 风险等级（高/中/低/未知）

## 使用示例

### 基础扫描
```bash
# 扫描单个 IP（默认高危端口）
python portscan.py -i 192.168.1.1

# 扫描网段
python portscan.py -i 192.168.1.0/24

# 扫描 IPv6
python portscan.py -i 2001:db8::/64
```

### 使用代理
```bash
# SOCKS5 代理
python portscan.py -i 192.168.1.0/24 --proxy socks5://127.0.0.1:1080

# HTTP 代理
python portscan.py -i 192.168.1.0/24 --proxy http://proxy.example.com:8080

# 测试代理
python portscan.py -i 127.0.0.1 --proxy socks5://127.0.0.1:1080 --test-proxy
```

### 自定义端口
```bash
# 仅扫描特定端口
python portscan.py -i 192.168.1.0/24 --ports 22 3306 6379

# 扫描全部高危端口（默认）
python portscan.py -i 192.168.1.0/24
```

### 性能调优
```bash
# 高并发快速扫描
python portscan.py -i 192.168.1.0/24 -t 200 -T 0.3

# 保守扫描（降低速度提高准确性）
python portscan.py -i 192.168.1.0/24 -t 50 -T 2.0
```

## 依赖说明

### 必需依赖
- Python 3.7+
- asyncio (内置)
- ipaddress (内置)

### 可选依赖（代理功能）
```bash
# SOCKS 代理支持（二选一）
pip install socksio    # 纯 Python 实现，推荐
pip install PySocks    # 另一种实现
```

## 文件结构
```
/workspace/
├── portscan.py         # 主程序
├── ip_parser.py        # IP 解析模块（ParseIPv4, ParseIPv6, IPParser）
├── proxy_support.py    # 代理支持模块（ProxyConfig, ProxySocket）
└── README.md           # 本文档
```

## 向后兼容性
- 保留了原有的同步扫描模式（`--sync` 参数）
- 保留了原有的命令行参数格式
- 默认行为已优化为更实用的配置

## 性能优化
- 异步模式默认并发数提升至 100
- 默认超时优化为 0.5 秒（适合内网扫描）
- 使用 `asyncio.gather` 并行扫描每个 IP 的多个端口
