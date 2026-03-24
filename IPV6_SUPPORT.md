# IPv6 支持更新说明

## 更新内容

端口扫描器 `port_scanner.py` 现已支持 IPv6 地址扫描。

## 主要改动

### 1. IP 地址解析 (`parse_ip_ranges`, `read_ip_file`)
- 返回值从 `List[str]` 改为 `List[dict]`
- 每个 IP 条目包含：`{'ip': str, 'version': 4|6}`
- 自动检测 IP 版本（IPv4 或 IPv6）

### 2. 端口扫描 (`scan_port`)
- 新增 `ip_version` 参数
- 根据 IP 版本自动选择 `AF_INET` 或 `AF_INET6`
- IPv6 使用 `getaddrinfo()` 获取正确的地址格式

### 3. IP 扫描 (`scan_ip`)
- 接收 IP 条目字典而非字符串
- 传递 IP 版本信息给 `scan_port`
- 结果中包含 `ip_version` 字段

### 4. 结果显示 (`display_result`, `print_report`)
- 显示 IP 版本标签 (IPv4/IPv6)
- 统计 IPv4 和 IPv6 的开放端口数量

## 使用示例

### 扫描单个 IPv6 地址
```bash
python3 port_scanner.py -i 2001:db8::1
```

### 扫描 IPv6 网段
```bash
python3 port_scanner.py -i 2001:db8::/64
```

### 混合扫描 IPv4 和 IPv6
```bash
python3 port_scanner.py -i 192.168.1.0/24 2001:db8::/64
```

### 从文件读取（支持混合地址）
```bash
python3 port_scanner.py -f ip_list.txt
```

### 扫描本地 IPv6 回环
```bash
python3 port_scanner.py -i ::1
```

## 文件格式示例

`ip_list.txt`:
```
# IPv4 地址
192.168.1.1
192.168.1.0/24

# IPv6 地址
2001:db8::1
2001:db8::/64

# 本地回环
127.0.0.1
::1
```

## 输出示例

```
🎯 开始扫描 100 个 IP 地址 (IPv4: 50, IPv6: 50)
   目标端口：[19890, 18789]
⚙️  线程数：50, 超时时间：2.0s

============================================================
✅ [1/100] 发现开放端口 - 2001:db8::1 (IPv6)
============================================================

  🔌 端口：19890
     服务名称：Unknown/Custom
     服务类型：HTTP/Web 服务
============================================================

端口扫描报告
扫描时间：2026-03-24 15:30:00
目标端口：[19890, 18789]
扫描总数：100 个 IP
开放端口：5 个 IP (IPv4: 3, IPv6: 2)
```

## 注意事项

1. **系统 IPv6 支持**：确保操作系统已启用 IPv6
2. **网络配置**：IPv6 地址需要正确的路由配置
3. **防火墙**：IPv6 和 IPv4 的防火墙规则是独立的
4. **链路本地地址**：扫描 `fe80::/10` 时需要指定网络接口
   ```bash
   # Linux: fe80::1%eth0
   python3 port_scanner.py -i fe80::1%eth0
   ```

## 兼容性

- ✅ 完全向后兼容 IPv4 扫描
- ✅ 支持 IPv4/IPv6 混合扫描
- ✅ 所有原有参数保持不变
- ✅ 输出格式保持一致，仅增加 IP 版本标识

## 测试

运行测试脚本验证功能：
```bash
python3 test_ipv6_scan.py
```
