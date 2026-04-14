#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP 解析模块 - 模块化设计
支持 IPv4 和 IPv6 地址解析
"""

import ipaddress
from typing import List, Dict


class ParseIPv4:
    """IPv4 地址解析器"""
    
    @staticmethod
    def parse_single(ip: str) -> Dict[str, any]:
        """
        解析单个 IPv4 地址
        :param ip: IP 地址字符串
        :return: {'ip': str, 'version': 4, 'object': IPv4Address}
        """
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            return {
                'ip': str(ip_obj),
                'version': 4,
                'object': ip_obj
            }
        except ipaddress.AddressValueError as e:
            raise ValueError(f"无效的 IPv4 地址：{ip} - {e}")
    
    @staticmethod
    def parse_cidr(cidr: str) -> List[Dict[str, any]]:
        """
        解析 IPv4 CIDR 网段
        :param cidr: CIDR 格式字符串 (如 192.168.1.0/24)
        :return: [{'ip': str, 'version': 4, 'object': IPv4Address}, ...]
        """
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            return [
                {
                    'ip': str(ip),
                    'version': 4,
                    'object': ip
                }
                for ip in network.hosts()
            ]
        except ipaddress.NetmaskValueError as e:
            raise ValueError(f"无效的 IPv4 网段：{cidr} - {e}")
    
    @staticmethod
    def parse(ip_input: str) -> List[Dict[str, any]]:
        """
        智能解析 IPv4 输入（支持单个 IP 或 CIDR）
        :param ip_input: IP 地址或 CIDR 网段
        :return: IP 列表
        """
        if '/' in ip_input:
            return ParseIPv4.parse_cidr(ip_input)
        else:
            return [ParseIPv4.parse_single(ip_input)]
    
    @staticmethod
    def is_valid(ip: str) -> bool:
        """检查是否为有效的 IPv4 地址"""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False
    
    @staticmethod
    def is_private(ip: str) -> bool:
        """检查 IPv4 地址是否为私有地址"""
        try:
            return ipaddress.IPv4Address(ip).is_private
        except ipaddress.AddressValueError:
            return False


class ParseIPv6:
    """IPv6 地址解析器"""
    
    @staticmethod
    def parse_single(ip: str) -> Dict[str, any]:
        """
        解析单个 IPv6 地址
        :param ip: IP 地址字符串
        :return: {'ip': str, 'version': 6, 'object': IPv6Address}
        """
        try:
            ip_obj = ipaddress.IPv6Address(ip)
            return {
                'ip': str(ip_obj),
                'version': 6,
                'object': ip_obj,
                'compressed': ip_obj.compressed,
                'exploded': ip_obj.exploded
            }
        except ipaddress.AddressValueError as e:
            raise ValueError(f"无效的 IPv6 地址：{ip} - {e}")
    
    @staticmethod
    def parse_cidr(cidr: str) -> List[Dict[str, any]]:
        """
        解析 IPv6 CIDR 网段
        :param cidr: CIDR 格式字符串 (如 2001:db8::/64)
        :return: [{'ip': str, 'version': 6, 'object': IPv6Address}, ...]
        """
        try:
            network = ipaddress.IPv6Network(cidr, strict=False)
            return [
                {
                    'ip': str(ip),
                    'version': 6,
                    'object': ip,
                    'compressed': ip.compressed
                }
                for ip in network.hosts()
            ]
        except ipaddress.NetmaskValueError as e:
            raise ValueError(f"无效的 IPv6 网段：{cidr} - {e}")
    
    @staticmethod
    def parse(ip_input: str) -> List[Dict[str, any]]:
        """
        智能解析 IPv6 输入（支持单个 IP 或 CIDR）
        :param ip_input: IP 地址或 CIDR 网段
        :return: IP 列表
        """
        if '/' in ip_input:
            return ParseIPv6.parse_cidr(ip_input)
        else:
            return [ParseIPv6.parse_single(ip_input)]
    
    @staticmethod
    def is_valid(ip: str) -> bool:
        """检查是否为有效的 IPv6 地址"""
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False
    
    @staticmethod
    def is_unique_local(ip: str) -> bool:
        """检查 IPv6 地址是否为唯一本地地址 (ULA)"""
        try:
            return ipaddress.IPv6Address(ip).is_private
        except ipaddress.AddressValueError:
            return False


class IPParser:
    """统一的 IP 解析器入口，自动检测 IPv4/IPv6"""
    
    @staticmethod
    def parse(ip_input: str) -> List[Dict[str, any]]:
        """
        智能解析 IP 地址（自动检测 IPv4/IPv6）
        :param ip_input: IP 地址或 CIDR 网段
        :return: IP 列表 [{'ip': str, 'version': 4|6, ...}, ...]
        """
        # 先尝试 IPv4
        if ParseIPv4.is_valid(ip_input.split('/')[0]):
            return ParseIPv4.parse(ip_input)
        # 再尝试 IPv6
        elif ParseIPv6.is_valid(ip_input.split('%')[0].split('/')[0]):
            return ParseIPv6.parse(ip_input)
        else:
            raise ValueError(f"无效的 IP 地址格式：{ip_input}")
    
    @staticmethod
    def parse_list(ip_inputs: List[str]) -> List[Dict[str, any]]:
        """
        解析多个 IP 地址或网段
        :param ip_inputs: IP 地址或 CIDR 网段列表
        :return: IP 列表
        """
        result = []
        for ip_input in ip_inputs:
            try:
                result.extend(IPParser.parse(ip_input))
            except ValueError as e:
                print(f"⚠️  {e}")
        return result
    
    @staticmethod
    def from_file(filepath: str) -> List[Dict[str, any]]:
        """
        从文件读取并解析 IP 列表
        :param filepath: 文件路径
        :return: IP 列表
        """
        result = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    # 跳过空行和注释
                    if not line or line.startswith('#'):
                        continue
                    try:
                        result.extend(IPParser.parse(line))
                    except ValueError as e:
                        print(f"⚠️  文件第{line_num}行无效：{line} - {e}")
            
            ipv4_count = sum(1 for ip in result if ip['version'] == 4)
            ipv6_count = sum(1 for ip in result if ip['version'] == 6)
            print(f"✓ 从文件读取 {len(result)} 个 IP 地址 (IPv4: {ipv4_count}, IPv6: {ipv6_count})")
            return result
        except FileNotFoundError:
            print(f"❌ 文件不存在：{filepath}")
            return []
        except Exception as e:
            print(f"❌ 读取文件失败：{e}")
            return []


if __name__ == '__main__':
    # 测试代码
    print("测试 IPv4 解析:")
    ipv4_result = ParseIPv4.parse('192.168.1.0/24')
    print(f"  解析结果数量：{len(ipv4_result)}")
    print(f"  示例：{ipv4_result[0]}")
    
    print("\n测试 IPv6 解析:")
    ipv6_result = ParseIPv6.parse('2001:db8::/126')
    print(f"  解析结果数量：{len(ipv6_result)}")
    print(f"  示例：{ipv6_result[0]}")
    
    print("\n测试统一解析器:")
    mixed = IPParser.parse_list(['192.168.1.1', '2001:db8::1', '10.0.0.0/30'])
    for ip in mixed:
        print(f"  {ip['ip']} (IPv{ip['version']})")
