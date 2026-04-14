#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端口扫描器 - 模块化重构版本
支持 IPv4 和 IPv6 地址扫描
支持代理（SOCKS4/5, HTTP/HTTPS）
默认扫描常见高危端口

⚠️  法律声明：本工具仅用于授权的安全测试和网络管理
   未经授权使用本工具扫描他人网络可能违反法律法规

高性能优化版本：使用 asyncio + 连接池
"""

import socket
import argparse
import sys
import signal
from datetime import datetime
from typing import List, Tuple, Optional, Dict, Any
import asyncio
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 导入自定义模块
from ip_parser import ParseIPv4, ParseIPv6, IPParser
from proxy_support import ProxyConfig, ProxySocket, ProxyType

# 全局标志用于控制优雅退出
shutdown_requested = False

# 速率限制配置（防止网络拥塞和检测）
RATE_LIMIT_CONFIG = {
    'max_connections_per_second': 100,  # 每秒最大连接数
    'delay_between_scans': 0.01,        # 扫描间隔（秒）
}

# 常见高危端口列表（默认扫描目标）
HIGH_RISK_PORTS = [
    # 远程管理服务
    22,     # SSH
    23,     # Telnet
    3389,   # RDP
    
    # 数据库服务
    1433,   # MSSQL
    1521,   # Oracle
    3306,   # MySQL
    5432,   # PostgreSQL
    6379,   # Redis (常未授权访问)
    27017,  # MongoDB (常未授权访问)
    
    # Web 服务
    80,     # HTTP
    443,    # HTTPS
    8080,   # HTTP Alt
    8443,   # HTTPS Alt
    
    # 文件共享
    21,     # FTP
    445,    # SMB
    139,    # NetBIOS
    
    # 邮件服务
    25,     # SMTP
    110,    # POP3
    143,    # IMAP
    
    # 其他高危服务
    135,    # RPC
    5900,   # VNC
    11211,  # Memcached
    9200,   # Elasticsearch
    9300,   # Elasticsearch Cluster
    
    # 原默认端口（保留）
    19890,  # 自定义
    18789,  # 自定义
]

# 目标端口（可被命令行覆盖）
TARGET_PORTS = HIGH_RISK_PORTS.copy()


# 全局代理配置（在 main 中设置）
proxy_config: Optional[ProxyConfig] = None


class RateLimiter:
    """速率限制器，防止扫描过快导致网络问题"""
    
    def __init__(self, rate: float = 100.0):
        """
        初始化速率限制器
        :param rate: 每秒允许的操作次数
        """
        self.rate = rate
        self.min_interval = 1.0 / rate if rate > 0 else 0
        self.last_time = 0.0
    
    async def acquire(self):
        """异步等待直到可以执行下一次操作"""
        now = asyncio.get_event_loop().time()
        elapsed = now - self.last_time
        if elapsed < self.min_interval:
            await asyncio.sleep(self.min_interval - elapsed)
        self.last_time = asyncio.get_event_loop().time()


def format_port_display(ports: List[int]) -> str:
    """
    格式化端口显示：
    - 如果端口数量少，直接列出
    - 如果端口数量多（如 all），显示范围
    """
    if not ports:
        return "无"
    
    # 如果是完整的 1-65535 范围
    if len(ports) == 65535 and ports[0] == 1 and ports[-1] == 65535:
        return "1-65535 (所有端口)"
    
    # 如果是连续范围
    if len(ports) > 20:
        # 检查是否是连续范围
        if ports[-1] - ports[0] == len(ports) - 1:
            return f"{ports[0]}-{ports[-1]} ({len(ports)} 个端口)"
        else:
            return f"{ports[0]}-{ports[-1]} 等共 {len(ports)} 个端口"
    
    # 端口数量少，直接列出
    return ",".join(map(str, ports))


def parse_port_list(port_str: str) -> List[int]:
    """
    解析端口列表字符串，支持多种格式：
    - 单个端口：80
    - 逗号分隔：22,80,443
    - 端口范围：50-65535
    - 混合模式：22,80,443,1000-2000
    - all: 所有端口 (1-65535)
    
    返回：排序后的端口列表
    """
    if not port_str:
        return []
    
    port_str = port_str.strip().lower()
    
    # 处理 'all' 特殊情况
    if port_str == 'all':
        return list(range(1, 65536))
    
    ports = set()
    parts = port_str.split(',')
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
        
        # 检查是否是范围格式 (x-y)
        if '-' in part:
            range_parts = part.split('-')
            if len(range_parts) != 2:
                raise ValueError(f"无效的端口范围格式：{part}")
            
            try:
                start = int(range_parts[0].strip())
                end = int(range_parts[1].strip())
            except ValueError:
                raise ValueError(f"无效的端口号：{part}")
            
            if start < 1 or start > 65535 or end < 1 or end > 65535:
                raise ValueError(f"端口号必须在 1-65535 之间：{part}")
            
            if start > end:
                raise ValueError(f"端口范围起始值不能大于结束值：{part}")
            
            for p in range(start, end + 1):
                ports.add(p)
        else:
            # 单个端口
            try:
                port = int(part)
            except ValueError:
                raise ValueError(f"无效的端口号：{part}")
            
            if port < 1 or port > 65535:
                raise ValueError(f"端口号必须在 1-65535 之间：{port}")
            
            ports.add(port)
    
    if not ports:
        raise ValueError("没有指定有效的端口")
    
    return sorted(list(ports))


def parse_ip_ranges(ip_ranges: List[str]) -> List[dict]:
    """
    解析 IP 地址范围，支持 CIDR 格式和单个 IP
    支持 IPv4 和 IPv6
    使用模块化的 ParseIPv4 和 ParseIPv6
    返回：[{'ip': str, 'version': 4|6}, ...]
    """
    return IPParser.parse_list(ip_ranges)


def read_ip_file(filepath: str) -> List[dict]:
    """
    从文件读取 IP 地址列表
    支持格式：每行一个 IP 或网段，# 开头为注释
    支持 IPv4 和 IPv6
    使用模块化的 IPParser
    返回：[{'ip': str, 'version': 4|6}, ...]
    """
    return IPParser.from_file(filepath)


def scan_port(ip: str, port: int, ip_version: int = 4, timeout: float = 2.0) -> Tuple[bool, Optional[str]]:
    """
    扫描单个 IP 的单个端口（同步版本，用于兼容性）
    支持 IPv4、IPv6 和代理
    返回：(是否开放，服务横幅信息)
    
    ⚠️ 安全改进：
    - 添加输入验证防止注入攻击
    - 限制 banner 获取的数据量
    - 确保 socket 正确关闭
    """
    global proxy_config
    
    # 输入验证
    if not isinstance(ip, str) or not ip:
        return False, "无效的 IP 地址"
    
    if not isinstance(port, int) or port < 1 or port > 65535:
        return False, f"无效的端口号：{port}"
    
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        return False, "无效的超时时间"
    
    sock = None
    try:
        # 如果配置了代理，使用代理连接
        if proxy_config and proxy_config.is_configured():
            proxy_socket = ProxySocket(proxy_config)
            sock = proxy_socket.create_connection(ip, port, timeout, ip_version)
        else:
            # 根据 IP 版本选择 socket 类型
            if ip_version == 6:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            sock.settimeout(timeout)
            
            # IPv6 需要使用 getaddrinfo 来获取正确的地址格式
            if ip_version == 6:
                addr_info = socket.getaddrinfo(ip, port, socket.AF_INET6, socket.SOCK_STREAM)
                if addr_info:
                    result = sock.connect_ex(addr_info[0][4])
                else:
                    return False, "无法解析地址"
            else:
                result = sock.connect_ex((ip, port))
        
        if proxy_config and proxy_config.is_configured():
            # 代理模式下，连接成功即为开放
            result = 0
        
        if result == 0:
            # 端口开放，尝试获取服务横幅（限制数据量防止 DoS）
            try:
                sock.settimeout(1.0)  # 设置接收超时
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
                banner = sock.recv(512).decode('utf-8', errors='ignore')[:200]
                return True, banner if banner else "端口开放 (无横幅信息)"
            except Exception:
                return True, "端口开放 (无法获取横幅)"
        else:
            return False, None
            
    except socket.timeout:
        return False, "超时"
    except socket.error as e:
        return False, f"错误：{e}"
    except Exception as e:
        logger.debug(f"扫描异常：{e}")
        return False, f"异常"
    finally:
        # 确保 socket 总是被关闭
        if sock:
            try:
                sock.close()
            except Exception:
                pass


async def async_scan_port(ip: str, port: int, ip_version: int = 4, 
                          timeout: float = 2.0) -> Tuple[bool, Optional[str]]:
    """
    异步扫描单个 IP 的单个端口
    支持 IPv4 和 IPv6
    返回：(是否开放，服务横幅信息)
    """
    loop = asyncio.get_event_loop()
    sock = None
    
    try:
        # 根据 IP 版本创建对应的 socket
        if ip_version == 6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        sock.setblocking(False)
        
        # 使用 asyncio 包装 socket 连接
        if ip_version == 6:
            # IPv6: 使用 getaddrinfo 获取正确的地址格式
            addr_info = await loop.getaddrinfo(
                ip, port, 
                family=socket.AF_INET6, 
                type=socket.SOCK_STREAM
            )
            if not addr_info:
                return False, "无法解析 IPv6 地址"
            
            # 连接到第一个匹配的地址
            _, _, _, _, sockaddr = addr_info[0]
            await asyncio.wait_for(
                loop.sock_connect(sock, sockaddr),
                timeout=timeout
            )
        else:
            # IPv4: 直接连接
            await asyncio.wait_for(
                loop.sock_connect(sock, (ip, port)),
                timeout=timeout
            )
        
        # 连接成功，端口开放
        banner_str = "端口开放 (无横幅信息)"
        return True, banner_str
            
    except asyncio.TimeoutError:
        return False, "超时"
    except OSError as e:
        return False, f"错误：{e}"
    except Exception as e:
        logger.debug(f"扫描异常：{e}")
        return False, f"异常：{e}"
    finally:
        # 确保 socket 总是被关闭
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# 端口服务信息映射（常见高危端口）
KNOWN_SERVICES = {
    22: {'name': 'SSH', 'description': 'Secure Shell 远程管理服务', 'common_uses': ['远程登录', '文件传输'], 'risk': '高'},
    23: {'name': 'Telnet', 'description': '明文远程管理服务', 'common_uses': ['老旧设备管理'], 'risk': '极高'},
    3389: {'name': 'RDP', 'description': '远程桌面协议', 'common_uses': ['Windows 远程桌面'], 'risk': '高'},
    1433: {'name': 'MSSQL', 'description': 'Microsoft SQL Server', 'common_uses': ['数据库服务'], 'risk': '高'},
    1521: {'name': 'Oracle', 'description': 'Oracle 数据库', 'common_uses': ['企业数据库'], 'risk': '高'},
    3306: {'name': 'MySQL', 'description': 'MySQL 数据库', 'common_uses': ['Web 应用数据库'], 'risk': '高'},
    5432: {'name': 'PostgreSQL', 'description': 'PostgreSQL 数据库', 'common_uses': ['Web 应用数据库'], 'risk': '高'},
    6379: {'name': 'Redis', 'description': 'Redis 键值存储', 'common_uses': ['缓存', '消息队列'], 'risk': '高'},
    27017: {'name': 'MongoDB', 'description': 'MongoDB 文档数据库', 'common_uses': ['NoSQL 数据库'], 'risk': '高'},
    80: {'name': 'HTTP', 'description': '超文本传输协议', 'common_uses': ['Web 服务'], 'risk': '中'},
    443: {'name': 'HTTPS', 'description': '加密的 HTTP 协议', 'common_uses': ['安全 Web 服务'], 'risk': '中'},
    8080: {'name': 'HTTP-Alt', 'description': 'HTTP 备用端口', 'common_uses': ['代理', '开发服务器'], 'risk': '中'},
    8443: {'name': 'HTTPS-Alt', 'description': 'HTTPS 备用端口', 'common_uses': ['管理界面'], 'risk': '中'},
    21: {'name': 'FTP', 'description': '文件传输协议', 'common_uses': ['文件上传下载'], 'risk': '高'},
    445: {'name': 'SMB', 'description': 'Server Message Block', 'common_uses': ['文件共享'], 'risk': '高'},
    139: {'name': 'NetBIOS', 'description': 'NetBIOS Session Service', 'common_uses': ['Windows 网络'], 'risk': '高'},
    25: {'name': 'SMTP', 'description': '简单邮件传输协议', 'common_uses': ['邮件发送'], 'risk': '中'},
    110: {'name': 'POP3', 'description': '邮局协议 v3', 'common_uses': ['邮件接收'], 'risk': '中'},
    143: {'name': 'IMAP', 'description': 'Internet 消息访问协议', 'common_uses': ['邮件管理'], 'risk': '中'},
    135: {'name': 'RPC', 'description': '远程过程调用', 'common_uses': ['Windows RPC'], 'risk': '高'},
    5900: {'name': 'VNC', 'description': '虚拟网络计算', 'common_uses': ['远程桌面'], 'risk': '高'},
    11211: {'name': 'Memcached', 'description': '分布式内存缓存', 'common_uses': ['缓存服务'], 'risk': '高'},
    9200: {'name': 'Elasticsearch', 'description': 'Elasticsearch HTTP API', 'common_uses': ['搜索引擎'], 'risk': '高'},
    9300: {'name': 'ES-Cluster', 'description': 'Elasticsearch 集群通信', 'common_uses': ['集群节点通信'], 'risk': '高'},
    19890: {'name': 'Custom', 'description': '自定义服务端口', 'common_uses': ['内部应用'], 'risk': '未知'},
    18789: {'name': 'Custom', 'description': '自定义服务端口', 'common_uses': ['内部应用'], 'risk': '未知'},
}


def identify_service(port: int, banner: str) -> dict:
    """
    根据端口和横幅识别服务类型
    """
    service_info = KNOWN_SERVICES.get(port, {
        'name': 'Unknown',
        'description': '未知服务',
        'common_uses': [],
        'risk': '未知'
    }).copy()
    
    # 根据横幅内容进一步识别
    banner_lower = banner.lower() if banner else ""
    
    if 'http' in banner_lower or 'server' in banner_lower:
        service_info['detected_type'] = 'HTTP/Web 服务'
    elif 'ssh' in banner_lower:
        service_info['detected_type'] = 'SSH 服务'
    elif 'ftp' in banner_lower:
        service_info['detected_type'] = 'FTP 服务'
    elif 'smtp' in banner_lower:
        service_info['detected_type'] = '邮件服务'
    elif 'mysql' in banner_lower or 'mariadb' in banner_lower:
        service_info['detected_type'] = 'MySQL/MariaDB 数据库'
    elif 'redis' in banner_lower:
        service_info['detected_type'] = 'Redis 服务'
    elif 'mongodb' in banner_lower:
        service_info['detected_type'] = 'MongoDB 数据库'
    elif 'postgresql' in banner_lower:
        service_info['detected_type'] = 'PostgreSQL 数据库'
    elif 'oracle' in banner_lower:
        service_info['detected_type'] = 'Oracle 数据库'
    elif 'microsoft sql' in banner_lower:
        service_info['detected_type'] = 'MSSQL 数据库'
    elif 'elasticsearch' in banner_lower:
        service_info['detected_type'] = 'Elasticsearch 服务'
    else:
        service_info['detected_type'] = '自定义/未知服务'
    
    service_info['banner'] = banner
    return service_info


def scan_ip(ip_entry: dict, ports: List[int], timeout: float = 2.0) -> dict:
    """
    扫描单个 IP 的所有目标端口（同步版本）
    ip_entry: {'ip': str, 'version': 4|6}
    """
    ip = ip_entry['ip']
    ip_version = ip_entry['version']
    
    results = {
        'ip': ip,
        'ip_version': ip_version,
        'open_ports': [],
        'closed_ports': [],
        'services': {}
    }
    
    for port in ports:
        is_open, banner = scan_port(ip, port, ip_version, timeout)
        
        if is_open:
            results['open_ports'].append(port)
            service_info = identify_service(port, banner)
            results['services'][port] = service_info
        else:
            results['closed_ports'].append(port)
    
    return results


async def async_scan_ip(ip_entry: dict, ports: List[int], 
                        timeout: float = 2.0, semaphore: asyncio.Semaphore = None,
                        port_semaphore: asyncio.Semaphore = None) -> dict:
    """
    异步扫描单个 IP 的所有目标端口
    ip_entry: {'ip': str, 'version': 4|6}
    semaphore: 用于限制 IP 级别的并发（本函数不使用）
    port_semaphore: 用于限制端口级别的并发（关键优化）
    """
    ip = ip_entry['ip']
    ip_version = ip_entry['version']
    
    results = {
        'ip': ip,
        'ip_version': ip_version,
        'open_ports': [],
        'closed_ports': [],
        'services': {}
    }
    
    # 如果提供了端口信号量，则使用它来限制端口扫描的并发
    # 这是优化大量端口扫描的关键
    if port_semaphore:
        async def scan_single_port(port):
            async with port_semaphore:
                return await async_scan_port(ip, port, ip_version, timeout)
        
        tasks = [scan_single_port(port) for port in ports]
    else:
        # 没有限制，直接扫描（不推荐用于大量端口）
        tasks = [async_scan_port(ip, port, ip_version, timeout) for port in ports]
    
    # 并行扫描所有端口
    port_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for port, result in zip(ports, port_results):
        if isinstance(result, Exception):
            results['closed_ports'].append(port)
        else:
            is_open, banner = result
            if is_open:
                results['open_ports'].append(port)
                service_info = identify_service(port, banner)
                results['services'][port] = service_info
            else:
                results['closed_ports'].append(port)
    
    return results


def signal_handler(signum, frame):
    """
    处理 Ctrl+C 信号
    """
    global shutdown_requested
    print("\n\n⚠️  检测到 Ctrl+C，正在停止扫描...")
    shutdown_requested = True


async def async_scan_network(ip_list: List[dict], ports: List[int], 
                             max_workers: int = 100, timeout: float = 2.0,
                             realtime: bool = True, port_workers: int = None) -> List[dict]:
    """
    异步批量扫描 IP 列表 - 高性能版本
    使用 asyncio 实现高并发
    
    参数:
        ip_list: [{'ip': str, 'version': 4|6}, ...]
        max_workers: 最大并发 IP 数（默认 100，比线程池更高）
        realtime: 是否实时显示发现的开放端口
        port_workers: 每个 IP 的端口扫描并发数（默认与 max_workers 相同，扫描 all 时建议设置更大值如 1000-3000）
    """
    global shutdown_requested
    
    total_ips = len(ip_list)
    ipv4_count = sum(1 for ip in ip_list if ip['version'] == 4)
    ipv6_count = sum(1 for ip in ip_list if ip['version'] == 6)
    
    # 自动优化端口并发数
    if port_workers is None:
        # 如果端口数量很大（如 all），自动增加端口并发数
        if len(ports) > 1000:
            port_workers = min(3000, max_workers * 10)  # 最多 3000 或 max_workers 的 10 倍
        else:
            port_workers = max_workers
    
    print(f"\n🎯 开始异步扫描 {total_ips} 个 IP 地址 (IPv4: {ipv4_count}, IPv6: {ipv6_count})")
    print(f"   目标端口：{format_port_display(ports)}")
    print(f"⚙️  最大并发 IP 数：{max_workers}, 端口并发数：{port_workers}, 超时时间：{timeout}s")
    print(f"💡 按 Ctrl+C 可随时终止扫描")
    if realtime:
        print(f"📢 实时显示：发现开放端口立即显示\n")
    
    results = []
    start_time = datetime.now()
    completed = 0
    
    # 创建信号量限制并发数
    ip_semaphore = asyncio.Semaphore(max_workers)
    port_semaphore = asyncio.Semaphore(port_workers)
    
    async def scan_with_progress(ip_entry, idx):
        nonlocal completed
        if shutdown_requested:
            return None
        
        result = await async_scan_ip(ip_entry, ports, timeout, ip_semaphore, port_semaphore)
        completed += 1
        
        # 实时显示结果
        if realtime and result['open_ports']:
            display_result(result, total_ips, completed)
        
        # 进度显示
        if completed % 100 == 0 or completed == total_ips:
            elapsed = (datetime.now() - start_time).total_seconds()
            rate = completed / elapsed if elapsed > 0 else 0
            print(f"📊 进度：{completed}/{total_ips} "
                  f"({rate:.1f} IP/s), "
                  f"发现 {sum(1 for r in results if r['open_ports'])} "
                  f"个开放端口的主机")
        
        return result
    
    try:
        # 创建所有任务
        tasks = [scan_with_progress(ip_entry, idx) for idx, ip_entry in enumerate(ip_list)]
        
        # 并发执行所有任务
        for coro in asyncio.as_completed(tasks):
            if shutdown_requested:
                print(f"\n⏹️  扫描已终止，已完成 {completed}/{total_ips} 个 IP")
                break
            
            result = await coro
            if result:
                results.append(result)
    
    except Exception as e:
        print(f"❌ 扫描过程中出错：{e}")
    
    elapsed = (datetime.now() - start_time).total_seconds()
    if elapsed > 0:
        print(f"\n⏱️  扫描统计：耗时 {elapsed:.2f}秒，扫描 {len(results)} 个 IP，"
              f"平均速度 {len(results)/elapsed:.1f} IP/s")
        print(f"📍 发现 {sum(1 for r in results if r['open_ports'])} 个开放端口的主机")
    
    return results


def scan_network(ip_list: List[dict], ports: List[int], max_workers: int = 50, 
                 timeout: float = 2.0, verbose: bool = False, 
                 realtime: bool = True, use_async: bool = True,
                 port_workers: int = None) -> List[dict]:
    """
    批量扫描 IP 列表（统一入口，支持同步和异步模式）
    
    参数:
        ip_list: [{'ip': str, 'version': 4|6}, ...]
        max_workers: 最大并发数
        realtime: 是否实时显示发现的开放端口
        use_async: 是否使用异步模式（默认 True，性能更好）
        port_workers: 每个 IP 的端口扫描并发数（仅异步模式有效）
    """
    if use_async:
        # 使用异步模式（推荐）
        return asyncio.run(async_scan_network(
            ip_list, ports, max_workers=max_workers, 
            timeout=timeout, realtime=realtime, port_workers=port_workers
        ))
    else:
        # 使用传统线程池模式（兼容旧版）
        return _scan_network_threaded(ip_list, ports, max_workers, timeout, verbose, realtime)


def _scan_network_threaded(ip_list: List[dict], ports: List[int], max_workers: int = 50, 
                           timeout: float = 2.0, verbose: bool = False, 
                           realtime: bool = True) -> List[dict]:
    """
    传统线程池扫描实现（向后兼容）
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    global shutdown_requested
    
    total_ips = len(ip_list)
    ipv4_count = sum(1 for ip in ip_list if ip['version'] == 4)
    ipv6_count = sum(1 for ip in ip_list if ip['version'] == 6)
    
    print(f"\n🎯 开始扫描 {total_ips} 个 IP 地址 (IPv4: {ipv4_count}, IPv6: {ipv6_count})")
    print(f"   目标端口：{format_port_display(ports)}")
    print(f"⚙️  线程数：{max_workers}, 超时时间：{timeout}s")
    print(f"💡 按 Ctrl+C 可随时终止扫描\n")
    
    results = []
    start_time = datetime.now()
    
    # 设置信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    
    executor = None
    try:
        executor = ThreadPoolExecutor(max_workers=max_workers)
        future_to_ip = {executor.submit(scan_ip, ip_entry, ports, timeout): ip_entry 
                       for ip_entry in ip_list}
        
        completed = 0
        try:
            for future in as_completed(future_to_ip):
                # 检查是否请求关闭
                if shutdown_requested:
                    print(f"\n⏹️  扫描已终止，已完成 {completed}/{total_ips} 个 IP")
                    break
                
                ip_entry = future_to_ip[future]
                completed += 1
                
                try:
                    result = future.result()
                    results.append(result)
                    
                    # 实时显示结果（默认开启）
                    if realtime and result['open_ports']:
                        display_result(result, total_ips, completed)
                    elif verbose and result['open_ports']:
                        # 兼容旧版 verbose 模式
                        ip_version = result.get('ip_version', 4)
                        print(f"[{completed}/{total_ips}] {result['ip']} (IPv{ip_version}): "
                              f"开放端口 {result['open_ports']}")
                    
                    # 进度显示
                    if completed % 100 == 0 or completed == total_ips:
                        elapsed = (datetime.now() - start_time).total_seconds()
                        rate = completed / elapsed if elapsed > 0 else 0
                        print(f"📊 进度：{completed}/{total_ips} "
                              f"({rate:.1f} IP/s), "
                              f"发现 {sum(1 for r in results if r['open_ports'])} "
                              f"个开放端口的主机")
                
                except Exception as e:
                    print(f"❌ 扫描 {ip_entry['ip']} 时出错：{e}")
        except KeyboardInterrupt:
            print(f"\n⏹️  扫描被用户中断，已完成 {completed}/{total_ips} 个 IP")
            shutdown_requested = True
    
    except Exception as e:
        print(f"❌ 扫描过程中出错：{e}")
    
    finally:
        # 清理线程池
        if executor:
            executor.shutdown(wait=False, cancel_futures=True)
        
        # 重置信号处理器
        signal.signal(signal.SIGINT, signal.default_int_handler)
    
    elapsed = (datetime.now() - start_time).total_seconds()
    if elapsed > 0:
        print(f"\n⏱️  扫描统计：耗时 {elapsed:.2f}秒，扫描 {len(results)} 个 IP，"
              f"平均速度 {len(results)/elapsed:.1f} IP/s")
        print(f"📍 发现 {sum(1 for r in results if r['open_ports'])} 个开放端口的主机")
    
    return results


def display_result(result: dict, total_ips: int, completed: int):
    """
    实时显示单个 IP 的扫描结果
    """
    if result['open_ports']:
        ip_version = result.get('ip_version', 4)
        version_label = f"IPv{ip_version}"
        print(f"\n{'='*60}")
        print(f"✅ [{completed}/{total_ips}] 发现开放端口 - {result['ip']} ({version_label})")
        print(f"{'='*60}")
        
        for port in result['open_ports']:
            service = result['services'].get(port, {})
            service_type = service.get('detected_type', '未知服务')
            service_name = service.get('name', 'Unknown')
            
            print(f"\n  🔌 端口：{port}")
            print(f"     服务名称：{service_name}")
            print(f"     服务类型：{service_type}")
            print(f"     常见用途：{', '.join(service.get('common_uses', []))}")
            
            if service.get('banner'):
                banner_preview = service['banner'][:150].replace('\n', ' ')
                print(f"     服务横幅：{banner_preview}...")
        
        print(f"{'='*60}\n")



def _scan_network_threaded_old(ip_list: List[dict], ports: List[int], max_workers: int = 50, 
                 timeout: float = 2.0, verbose: bool = False, 
                 realtime: bool = True) -> List[dict]:
    """
    批量扫描 IP 列表（旧版本，保留用于兼容）
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    global shutdown_requested, executor_instance
    executor_instance = None
    
    total_ips = len(ip_list)
    ipv4_count = sum(1 for ip in ip_list if ip['version'] == 4)
    ipv6_count = sum(1 for ip in ip_list if ip['version'] == 6)
    
    print(f"\n🎯 开始扫描 {total_ips} 个 IP 地址 (IPv4: {ipv4_count}, IPv6: {ipv6_count})")
    print(f"   目标端口：{format_port_display(ports)}")
    print(f"⚙️  线程数：{max_workers}, 超时时间：{timeout}s")
    print(f"💡 按 Ctrl+C 可随时终止扫描")
    if realtime:
        print(f"📢 实时显示：发现开放端口立即显示\n")
    
    results = []
    start_time = datetime.now()
    
    # 设置信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor_instance = executor
            future_to_ip = {executor.submit(scan_ip, ip_entry, ports, timeout): ip_entry 
                           for ip_entry in ip_list}
            
            completed = 0
            for future in as_completed(future_to_ip):
                # 检查是否请求关闭
                if shutdown_requested:
                    print(f"\n⏹️  扫描已终止，已完成 {completed}/{total_ips} 个 IP")
                    break
                
                ip_entry = future_to_ip[future]
                completed += 1
                
                try:
                    result = future.result()
                    results.append(result)
                    
                    # 实时显示结果（默认开启）
                    if realtime and result['open_ports']:
                        display_result(result, total_ips, completed)
                    elif verbose and result['open_ports']:
                        # 兼容旧版 verbose 模式
                        ip_version = result.get('ip_version', 4)
                        print(f"[{completed}/{total_ips}] {result['ip']} (IPv{ip_version}): "
                              f"开放端口 {result['open_ports']}")
                    
                    # 进度显示
                    if completed % 100 == 0 or completed == total_ips:
                        elapsed = (datetime.now() - start_time).total_seconds()
                        rate = completed / elapsed if elapsed > 0 else 0
                        print(f"📊 进度：{completed}/{total_ips} "
                              f"({rate:.1f} IP/s), "
                              f"发现 {sum(1 for r in results if r['open_ports'])} "
                              f"个开放端口的主机")
                
                except Exception as e:
                    print(f"❌ 扫描 {ip_entry['ip']} 时出错：{e}")
            
            executor_instance = None
    
    except Exception as e:
        print(f"❌ 扫描过程中出错：{e}")
    
    # 重置信号处理器
    signal.signal(signal.SIGINT, signal.default_int_handler)
    
    elapsed = (datetime.now() - start_time).total_seconds()
    if elapsed > 0:
        print(f"\n⏱️  扫描统计：耗时 {elapsed:.2f}秒，扫描 {len(results)} 个 IP，"
              f"平均速度 {len(results)/elapsed:.1f} IP/s")
        print(f"📍 发现 {sum(1 for r in results if r['open_ports'])} 个开放端口的主机")
    
    return results


def print_report(results: List[dict], output_file: Optional[str] = None, scanned_ports: List[int] = None):
    """
    生成扫描报告
    """
    # 筛选有开放端口的主机
    open_hosts = [r for r in results if r['open_ports']]
    
    # 统计 IPv4 和 IPv6
    ipv4_open = sum(1 for r in open_hosts if r.get('ip_version', 4) == 4)
    ipv6_open = sum(1 for r in open_hosts if r.get('ip_version', 4) == 6)
    
    # 使用传入的端口列表或默认端口
    ports_to_display = scanned_ports if scanned_ports else TARGET_PORTS
    
    report_lines = []
    report_lines.append("=" * 80)
    report_lines.append("端口扫描报告")
    report_lines.append(f"扫描时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f"目标端口：{format_port_display(ports_to_display)}")
    report_lines.append(f"扫描总数：{len(results)} 个 IP")
    report_lines.append(f"开放端口：{len(open_hosts)} 个 IP (IPv4: {ipv4_open}, IPv6: {ipv6_open})")
    report_lines.append("=" * 80)
    
    if open_hosts:
        report_lines.append("\n📍 开放端口的主机详情:\n")
        
        for result in open_hosts:
            ip_version = result.get('ip_version', 4)
            report_lines.append(f"IP: {result['ip']} (IPv{ip_version})")
            report_lines.append(f"  开放端口：{result['open_ports']}")
            
            for port, service in result['services'].items():
                report_lines.append(f"  端口 {port}:")
                report_lines.append(f"    服务类型：{service.get('detected_type', '未知')}")
                report_lines.append(f"    常见用途：{', '.join(service.get('common_uses', []))}")
                if service.get('banner'):
                    banner_preview = service['banner'][:100].replace('\n', ' ')
                    report_lines.append(f"    服务横幅：{banner_preview}...")
            
            report_lines.append("")
    else:
        report_lines.append("\n⚠️  未发现开放端口的主机")
    
    report_text = '\n'.join(report_lines)
    print(report_text)
    
    # 输出到文件
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"\n💾 报告已保存到：{output_file}")
        except Exception as e:
            print(f"❌ 保存报告失败：{e}")


def main():
    global proxy_config
    
    parser = argparse.ArgumentParser(
        description='端口扫描器 - 模块化设计，支持 IPv4/IPv6，支持代理，默认扫描高危端口',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
示例用法:
  # 扫描单个 IPv4 地址
  python portscan.py -i 192.168.1.1

  # 扫描单个 IPv6 地址
  python portscan.py -i 2001:db8::1

  # 扫描 IPv4 网段
  python portscan.py -i 192.168.1.0/24

  # 扫描 IPv6 网段
  python portscan.py -i 2001:db8::/64

  # 混合扫描 IPv4 和 IPv6
  python portscan.py -i 192.168.1.0/24 2001:db8::/64

  # 从文件读取 IP 列表
  python portscan.py -f ip_list.txt

  # 使用代理扫描 (SOCKS5)
  python portscan.py -i 192.168.1.0/24 --proxy socks5://127.0.0.1:1080

  # 使用 HTTP 代理扫描
  python portscan.py -i 192.168.1.0/24 --proxy http://proxy.example.com:8080

  # 自定义端口扫描
  python portscan.py -i 10.0.0.0/8 --ports 22 3306 6379

  # 仅扫描常见高危端口（默认）
  python portscan.py -i 192.168.1.0/24

默认扫描的高危端口：{HIGH_RISK_PORTS[:10]}...等共{len(HIGH_RISK_PORTS)}个端口
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--ip', nargs='+',
                      help='IP 地址或网段（CIDR 格式），可多个')
    group.add_argument('-f', '--file',
                      help='包含 IP 地址列表的文件路径')

    parser.add_argument('-t', '--threads', type=int, default=100,
                       help='并发线程数/协程数（默认：100，扫描 all 时建议增加到 500-1000）')
    parser.add_argument('--port-threads', type=int, default=None,
                       help='每个 IP 的端口扫描并发数（默认自动优化，扫描 all 时可手动设置为 1000-3000）')
    parser.add_argument('-T', '--timeout', type=float, default=0.5,
                       help='连接超时时间（秒，默认：0.5）')
    parser.add_argument('-o', '--output',
                       help='输出报告文件路径')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='显示详细扫描进度')
    parser.add_argument('--no-realtime', action='store_true',
                       help='禁用实时显示（仅在结束时显示报告）')
    parser.add_argument('--ports', type=str, default=None,
                       help=f'自定义扫描端口（默认：高危端口列表，共{len(HIGH_RISK_PORTS)}个）。支持格式：单个端口 (80)、逗号分隔 (22,80,443)、端口范围 (50-65535)、混合模式 (22,80,1000-2000)、all (所有端口 1-65535)')
    parser.add_argument('--sync', action='store_true',
                       help='使用同步模式（默认使用高性能异步模式）')
    parser.add_argument('--proxy', type=str, default=None,
                       help='代理服务器 URL (支持 socks4://, socks5://, http://, https://)')
    parser.add_argument('--test-proxy', action='store_true',
                       help='测试代理连接性后退出')

    args = parser.parse_args()

    # 配置代理
    if args.proxy:
        try:
            proxy_config = ProxyConfig.from_url(args.proxy)
            print(f"📡 使用代理：{proxy_config}")
            
            if args.test_proxy:
                from proxy_support import test_proxy_connectivity
                print("🔍 测试代理连接性...")
                if test_proxy_connectivity(proxy_config):
                    print("✅ 代理连接正常")
                else:
                    print("❌ 代理连接失败")
                sys.exit(0)
        except Exception as e:
            print(f"❌ 代理配置错误：{e}")
            sys.exit(1)
    else:
        proxy_config = None

    # 获取 IP 列表
    if args.ip:
        ip_list = parse_ip_ranges(args.ip)
    else:
        ip_list = read_ip_file(args.file)

    if not ip_list:
        print("❌ 没有有效的 IP 地址可扫描")
        sys.exit(1)

    # 使用自定义端口或默认高危端口
    if args.ports:
        try:
            ports = parse_port_list(args.ports)
            print(f"🎯 扫描 {format_port_display(ports)}")
        except ValueError as e:
            print(f"❌ 端口参数错误：{e}")
            sys.exit(1)
    else:
        ports = TARGET_PORTS
        print(f"🎯 默认扫描 {len(ports)} 个常见高危端口")

    # 执行扫描
    results = scan_network(
        ip_list,
        ports,
        max_workers=args.threads,
        timeout=args.timeout,
        verbose=args.verbose,
        realtime=not args.no_realtime,
        use_async=not args.sync,
        port_workers=args.port_threads
    )

    # 生成报告
    print_report(results, args.output, ports)

if __name__ == '__main__':
    main()
