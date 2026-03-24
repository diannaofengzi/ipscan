#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端口扫描器 - 扫描 19890 和 18789 端口并识别服务类型
支持手动输入地址段或读取地址列表文件
支持 IPv4 和 IPv6 地址
"""

import socket
import argparse
import sys
import signal
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional, Union
import ipaddress

# 全局标志用于控制优雅退出
shutdown_requested = False
executor_instance = None


# 端口到服务名称的映射（常见服务）
KNOWN_SERVICES = {
    19890: {
        'name': 'Unknown/Custom',
        'description': '非标准端口，可能是自定义应用',
        'common_uses': ['自定义 Web 服务', '游戏服务器', '内部应用']
    },
    18789: {
        'name': 'Unknown/Custom', 
        'description': '非标准端口，可能是自定义应用',
        'common_uses': ['自定义 API 服务', '代理服务器', '内部通信']
    }
}

# 目标端口
TARGET_PORTS = [19890, 18789]


def parse_ip_ranges(ip_ranges: List[str]) -> List[dict]:
    """
    解析 IP 地址范围，支持 CIDR 格式和单个 IP
    支持 IPv4 和 IPv6
    返回：[{'ip': str, 'version': 4|6}, ...]
    """
    ip_list = []
    
    for ip_range in ip_ranges:
        try:
            # 尝试解析为网络地址（CIDR 格式）
            if '/' in ip_range:
                network = ipaddress.ip_network(ip_range, strict=False)
                version = 6 if isinstance(network, ipaddress.IPv6Network) else 4
                ips = [{'ip': str(ip), 'version': version} for ip in network.hosts()]
                ip_list.extend(ips)
            else:
                # 单个 IP 地址
                ip_obj = ipaddress.ip_address(ip_range)
                version = 6 if isinstance(ip_obj, ipaddress.IPv6Address) else 4
                ip_list.append({'ip': ip_range, 'version': version})
        except ValueError as e:
            print(f"⚠️  无效的 IP 地址或网段：{ip_range} - {e}")
    
    return ip_list


def read_ip_file(filepath: str) -> List[dict]:
    """
    从文件读取 IP 地址列表
    支持格式：每行一个 IP 或网段，# 开头为注释
    支持 IPv4 和 IPv6
    返回：[{'ip': str, 'version': 4|6}, ...]
    """
    ip_list = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # 跳过空行和注释
                if not line or line.startswith('#'):
                    continue
                
                try:
                    # 尝试解析 IP 或网段
                    if '/' in line:
                        network = ipaddress.ip_network(line, strict=False)
                        version = 6 if isinstance(network, ipaddress.IPv6Network) else 4
                        ips = [{'ip': str(ip), 'version': version} for ip in network.hosts()]
                        ip_list.extend(ips)
                    else:
                        ip_obj = ipaddress.ip_address(line)
                        version = 6 if isinstance(ip_obj, ipaddress.IPv6Address) else 4
                        ip_list.append({'ip': line, 'version': version})
                except ValueError as e:
                    print(f"⚠️  文件第{line_num}行无效：{line} - {e}")
        
        ipv4_count = sum(1 for ip in ip_list if ip['version'] == 4)
        ipv6_count = sum(1 for ip in ip_list if ip['version'] == 6)
        print(f"✓ 从文件读取 {len(ip_list)} 个 IP 地址 (IPv4: {ipv4_count}, IPv6: {ipv6_count})")
        return ip_list
    
    except FileNotFoundError:
        print(f"❌ 文件不存在：{filepath}")
        return []
    except Exception as e:
        print(f"❌ 读取文件失败：{e}")
        return []


def scan_port(ip: str, port: int, ip_version: int = 4, timeout: float = 2.0) -> Tuple[bool, Optional[str]]:
    """
    扫描单个 IP 的单个端口
    支持 IPv4 和 IPv6
    返回：(是否开放，服务横幅信息)
    """
    try:
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
        
        if result == 0:
            # 端口开放，尝试获取服务横幅
            try:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')[:200]
                sock.close()
                return True, banner if banner else "端口开放 (无横幅信息)"
            except:
                sock.close()
                return True, "端口开放 (无法获取横幅)"
        else:
            sock.close()
            return False, None
            
    except socket.timeout:
        return False, "超时"
    except socket.error as e:
        return False, f"错误：{e}"
    except Exception as e:
        return False, f"异常：{e}"


def identify_service(port: int, banner: str) -> dict:
    """
    根据端口和横幅识别服务类型
    """
    service_info = KNOWN_SERVICES.get(port, {
        'name': 'Unknown',
        'description': '未知服务',
        'common_uses': []
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
        service_info['detected_type'] = '数据库服务'
    elif 'redis' in banner_lower:
        service_info['detected_type'] = 'Redis 服务'
    else:
        service_info['detected_type'] = '自定义/未知服务'
    
    service_info['banner'] = banner
    return service_info


def scan_ip(ip_entry: dict, ports: List[int], timeout: float = 2.0) -> dict:
    """
    扫描单个 IP 的所有目标端口
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


def signal_handler(signum, frame):
    """
    处理 Ctrl+C 信号
    """
    global shutdown_requested, executor_instance
    print("\n\n⚠️  检测到 Ctrl+C，正在停止扫描...")
    shutdown_requested = True
    
    # 关闭线程池
    if executor_instance:
        executor_instance.shutdown(wait=False, cancel_futures=True)


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


def scan_network(ip_list: List[dict], ports: List[int], max_workers: int = 50, 
                 timeout: float = 2.0, verbose: bool = False, 
                 realtime: bool = True) -> List[dict]:
    """
    批量扫描 IP 列表
    
    参数:
        ip_list: [{'ip': str, 'version': 4|6}, ...]
        realtime: 是否实时显示发现的开放端口（默认 True）
    """
    global shutdown_requested, executor_instance
    
    total_ips = len(ip_list)
    ipv4_count = sum(1 for ip in ip_list if ip['version'] == 4)
    ipv6_count = sum(1 for ip in ip_list if ip['version'] == 6)
    
    print(f"\n🎯 开始扫描 {total_ips} 个 IP 地址 (IPv4: {ipv4_count}, IPv6: {ipv6_count})")
    print(f"   目标端口：{ports}")
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


def print_report(results: List[dict], output_file: Optional[str] = None):
    """
    生成扫描报告
    """
    # 筛选有开放端口的主机
    open_hosts = [r for r in results if r['open_ports']]
    
    # 统计 IPv4 和 IPv6
    ipv4_open = sum(1 for r in open_hosts if r.get('ip_version', 4) == 4)
    ipv6_open = sum(1 for r in open_hosts if r.get('ip_version', 4) == 6)
    
    report_lines = []
    report_lines.append("=" * 80)
    report_lines.append("端口扫描报告")
    report_lines.append(f"扫描时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f"目标端口：{TARGET_PORTS}")
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
    parser = argparse.ArgumentParser(
        description='端口扫描器 - 扫描 19890 和 18789 端口并识别服务类型 (支持 IPv4/IPv6)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  # 扫描单个 IPv4 地址
  python port_scanner.py -i 192.168.1.1
  
  # 扫描单个 IPv6 地址
  python port_scanner.py -i 2001:db8::1
  
  # 扫描 IPv4 网段
  python port_scanner.py -i 192.168.1.0/24
  
  # 扫描 IPv6 网段
  python port_scanner.py -i 2001:db8::/64
  
  # 混合扫描 IPv4 和 IPv6
  python port_scanner.py -i 192.168.1.0/24 2001:db8::/64
  
  # 从文件读取 IP 列表
  python port_scanner.py -f ip_list.txt
  
  # 自定义参数
  python port_scanner.py -i 10.0.0.0/8 -t 50 -o report.txt -v
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--ip', nargs='+', 
                      help='IP 地址或网段（CIDR 格式），可多个')
    group.add_argument('-f', '--file', 
                      help='包含 IP 地址列表的文件路径')
    
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='并发线程数（默认：50）')
    parser.add_argument('-T', '--timeout', type=float, default=2.0,
                       help='连接超时时间（秒，默认：2.0）')
    parser.add_argument('-o', '--output', 
                       help='输出报告文件路径')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='显示详细扫描进度')
    parser.add_argument('--no-realtime', action='store_true',
                       help='禁用实时显示（仅在结束时显示报告）')
    parser.add_argument('--ports', type=int, nargs='+',
                       help=f'自定义扫描端口（默认：{TARGET_PORTS}）')
    
    args = parser.parse_args()
    
    # 获取 IP 列表
    if args.ip:
        ip_list = parse_ip_ranges(args.ip)
    else:
        ip_list = read_ip_file(args.file)
    
    if not ip_list:
        print("❌ 没有有效的 IP 地址可扫描")
        sys.exit(1)
    
    # 使用自定义端口或默认端口
    ports = args.ports if args.ports else TARGET_PORTS
    
    # 执行扫描
    results = scan_network(
        ip_list, 
        ports, 
        max_workers=args.threads,
        timeout=args.timeout,
        verbose=args.verbose,
        realtime=not args.no_realtime
    )
    
    # 生成报告
    print_report(results, args.output)


if __name__ == '__main__':
    main()
