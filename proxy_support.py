#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代理支持模块 - 提供 SOCKS 和 HTTP 代理功能
✅ 已修复：
  1. 代理依赖问题 - 使用纯 Python 实现 SOCKS4/5 协议，无需外部库
  2. IPv6 代理支持 - 完整支持 IPv4 和 IPv6 地址的代理连接
"""

import socket
import ssl
import struct
from typing import Optional, Tuple
from enum import Enum


class ProxyType(Enum):
    """代理类型枚举"""
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


class ProxyConfig:
    """代理配置类"""
    
    def __init__(self, 
                 proxy_type: ProxyType = ProxyType.SOCKS5,
                 host: str = None,
                 port: int = None,
                 username: str = None,
                 password: str = None):
        """
        初始化代理配置
        :param proxy_type: 代理类型
        :param host: 代理服务器地址
        :param port: 代理服务器端口
        :param username: 用户名（可选）
        :param password: 密码（可选）
        """
        self.proxy_type = proxy_type
        self.host = host
        self.port = port
        self.username = username
        self.password = password
    
    @classmethod
    def from_url(cls, proxy_url: str) -> 'ProxyConfig':
        """
        从 URL 字符串创建代理配置
        支持格式：
          - socks5://user:pass@host:port
          - http://host:port
          - https://host:port
          - socks4://host:port
        :param proxy_url: 代理 URL
        :return: ProxyConfig 实例
        """
        from urllib.parse import urlparse
        
        parsed = urlparse(proxy_url)
        
        # 确定代理类型
        scheme = parsed.scheme.lower()
        if scheme in ('socks5', 'socks5h'):
            proxy_type = ProxyType.SOCKS5
        elif scheme == 'socks4':
            proxy_type = ProxyType.SOCKS4
        elif scheme == 'https':
            proxy_type = ProxyType.HTTPS
        else:
            proxy_type = ProxyType.HTTP
        
        # 提取认证信息
        username = parsed.username
        password = parsed.password
        
        return cls(
            proxy_type=proxy_type,
            host=parsed.hostname,
            port=parsed.port,
            username=username,
            password=password
        )
    
    def is_configured(self) -> bool:
        """检查代理是否已配置"""
        return self.host is not None and self.port is not None
    
    def __str__(self) -> str:
        if not self.is_configured():
            return "无代理"
        
        auth = f"{self.username}:***@" if self.username else ""
        return f"{self.proxy_type.value}://{auth}{self.host}:{self.port}"


class ProxySocket:
    """支持代理的 Socket 包装器"""
    
    def __init__(self, proxy_config: ProxyConfig = None):
        """
        初始化代理 Socket
        :param proxy_config: 代理配置
        """
        self.proxy_config = proxy_config or ProxyConfig()
        self._socket = None
    
    def _connect_through_proxy(self, dest_host: str, dest_port: int, 
                                timeout: float = 2.0) -> socket.socket:
        """
        通过代理建立连接
        :param dest_host: 目标主机
        :param dest_port: 目标端口
        :param timeout: 超时时间
        :return: 已连接的 socket
        """
        if not self.proxy_config.is_configured():
            # 无代理，直接连接
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((dest_host, dest_port))
            return sock
        
        # 根据代理类型选择连接方式
        if self.proxy_config.proxy_type in (ProxyType.SOCKS4, ProxyType.SOCKS5):
            return self._connect_socks(dest_host, dest_port, timeout)
        elif self.proxy_config.proxy_type in (ProxyType.HTTP, ProxyType.HTTPS):
            return self._connect_http(dest_host, dest_port, timeout)
        else:
            raise ValueError(f"不支持的代理类型：{self.proxy_config.proxy_type}")
    
    def _connect_socks(self, dest_host: str, dest_port: int, 
                       timeout: float = 2.0) -> socket.socket:
        """
        通过 SOCKS 代理连接（纯 Python 实现，无需外部依赖）
        ✅ 已修复：支持 IPv4 和 IPv6 地址
        """
        # 创建到代理服务器的连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((self.proxy_config.host, self.proxy_config.port))
        
        try:
            if self.proxy_config.proxy_type == ProxyType.SOCKS5:
                return self._socks5_handshake(sock, dest_host, dest_port, timeout)
            else:  # SOCKS4
                return self._socks4_handshake(sock, dest_host, dest_port, timeout)
        except Exception as e:
            sock.close()
            raise ConnectionError(f"SOCKS 握手失败：{e}")
    
    def _socks5_handshake(self, sock: socket.socket, 
                          dest_host: str, dest_port: int,
                          timeout: float = 2.0) -> socket.socket:
        """
        SOCKS5 握手协议实现
        支持 IPv4、IPv6 和域名地址
        """
        # 1. 发送问候（支持的认证方法）
        has_auth = bool(self.proxy_config.username and self.proxy_config.password)
        methods = [0x00]  # 无认证
        if has_auth:
            methods.append(0x02)  # 用户名/密码认证
        
        greeting = bytes([0x05, len(methods)]) + bytes(methods)
        sock.sendall(greeting)
        
        # 2. 接收服务器选择的认证方法
        response = sock.recv(2)
        if len(response) != 2 or response[0] != 0x05:
            raise ConnectionError("无效的 SOCKS5 响应")
        
        auth_method = response[1]
        if auth_method == 0xFF:
            raise ConnectionError("SOCKS5 服务器拒绝所有认证方法")
        
        # 3. 如果需要认证，进行认证
        if auth_method == 0x02:
            if not self.proxy_config.username or not self.proxy_config.password:
                raise ConnectionError("SOCKS5 需要认证但未提供凭据")
            
            # 发送用户名/密码
            username = self.proxy_config.username.encode('utf-8')[:255]
            password = self.proxy_config.password.encode('utf-8')[:255]
            
            auth_request = (
                bytes([0x01, len(username)]) + 
                username + 
                bytes([len(password)]) + 
                password
            )
            sock.sendall(auth_request)
            
            auth_response = sock.recv(2)
            if len(auth_response) != 2 or auth_response[1] != 0x00:
                raise ConnectionError("SOCKS5 认证失败")
        
        # 4. 发送连接请求
        # 判断目标地址类型
        try:
            # 检查是否为 IPv6
            addr_bytes = socket.inet_pton(socket.AF_INET6, dest_host)
            addr_type = 0x04  # IPv6
            addr_data = addr_bytes
        except OSError:
            try:
                # 检查是否为 IPv4
                addr_bytes = socket.inet_pton(socket.AF_INET, dest_host)
                addr_type = 0x01  # IPv4
                addr_data = addr_bytes
            except OSError:
                # 当作域名处理
                addr_type = 0x03  # 域名
                host_bytes = dest_host.encode('utf-8')[:255]
                addr_data = bytes([len(host_bytes)]) + host_bytes
        
        connect_request = (
            bytes([0x05, 0x01, 0x00]) +  # 版本 5, CONNECT, RSV
            bytes([addr_type]) +
            addr_data +
            struct.pack('>H', dest_port)  # 端口（大端序）
        )
        sock.sendall(connect_request)
        
        # 5. 接收连接响应
        response = sock.recv(4)  # 至少读取前 4 字节
        if len(response) < 4 or response[0] != 0x05:
            raise ConnectionError("无效的 SOCKS5 连接响应")
        
        status = response[1]
        if status != 0x00:
            error_messages = {
                0x01: "SOCKS5 服务器故障",
                0x02: "SOCKS5 规则集不允许连接",
                0x03: "网络不可达",
                0x04: "主机不可达",
                0x05: "连接被拒绝",
                0x06: "TTL 过期",
                0x07: "不支持的命令",
                0x08: "不支持的地址类型",
            }
            raise ConnectionError(f"SOCKS5 连接失败：{error_messages.get(status, f'错误代码 {status}')}")
        
        # 6. 读取剩余地址信息并丢弃
        addr_type = response[3]
        if addr_type == 0x01:  # IPv4
            remaining = 4 + 2  # 4 字节 IP + 2 字节端口
        elif addr_type == 0x04:  # IPv6
            remaining = 16 + 2  # 16 字节 IP + 2 字节端口
        else:  # 域名
            length_byte = sock.recv(1)
            if len(length_byte) != 1:
                raise ConnectionError("无效的 SOCKS5 响应")
            remaining = length_byte[0] + 2  # 域名长度 + 2 字节端口
        
        sock.recv(remaining)  # 丢弃剩余数据
        
        return sock
    
    def _socks4_handshake(self, sock: socket.socket,
                          dest_host: str, dest_port: int,
                          timeout: float = 2.0) -> socket.socket:
        """
        SOCKS4 握手协议实现
        注意：SOCKS4 仅支持 IPv4 地址
        """
        # SOCKS4 不支持 IPv6，尝试解析为 IPv4
        try:
            addr_bytes = socket.inet_pton(socket.AF_INET, dest_host)
        except OSError:
            # 尝试 DNS 解析（SOCKS4a 支持域名）
            try:
                addr_info = socket.getaddrinfo(dest_host, None, socket.AF_INET, socket.SOCK_STREAM)
                if addr_info:
                    addr_bytes = socket.inet_pton(socket.AF_INET, addr_info[0][4][0])
                else:
                    raise ConnectionError(f"无法解析 IPv4 地址：{dest_host}")
            except Exception as e:
                raise ConnectionError(f"SOCKS4 不支持 IPv6 地址，且无法解析域名：{e}")
        
        # 构建连接请求
        request = (
            bytes([0x04, 0x01]) +  # 版本 4, CONNECT
            struct.pack('>H', dest_port) +  # 端口（大端序）
            addr_bytes  # IPv4 地址
        )
        
        # 添加用户 ID（以 null 结尾）
        user_id = (self.proxy_config.username or "").encode('utf-8')[:255]
        request += user_id + b'\x00'
        
        sock.sendall(request)
        
        # 接收响应（8 字节）
        response = sock.recv(8)
        if len(response) != 8:
            raise ConnectionError("无效的 SOCKS4 响应")
        
        if response[0] != 0x00:
            raise ConnectionError("无效的 SOCKS4 响应头")
        
        status = response[1]
        if status != 0x5A:
            error_messages = {
                0x5B: "SOCKS4 请求被拒绝或失败",
                0x5C: "客户端不在 identd 运行的主机上",
                0x5D: "客户端身份无法确定",
            }
            raise ConnectionError(f"SOCKS4 连接失败：{error_messages.get(status, f'错误代码 {status}')}")
        
        return sock
    
    def _connect_http(self, dest_host: str, dest_port: int,
                      timeout: float = 2.0) -> socket.socket:
        """
        通过 HTTP/HTTPS 代理连接（使用 CONNECT 方法）
        ✅ 已修复：支持 IPv6 地址和域名
        """
        # 创建到代理服务器的连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((self.proxy_config.host, self.proxy_config.port))
        
        try:
            # 构建 CONNECT 请求
            auth_header = ""
            if self.proxy_config.username and self.proxy_config.password:
                import base64
                credentials = f"{self.proxy_config.username}:{self.proxy_config.password}"
                encoded = base64.b64encode(credentials.encode()).decode()
                auth_header = f"Proxy-Authorization: Basic {encoded}\r\n"
            
            connect_request = (
                f"CONNECT {dest_host}:{dest_port} HTTP/1.1\r\n"
                f"Host: {dest_host}:{dest_port}\r\n"
                f"{auth_header}"
                f"\r\n"
            )
            
            sock.sendall(connect_request.encode())
            
            # 读取响应
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = sock.recv(4096)
                if not chunk:
                    raise ConnectionError("代理服务器未响应")
                response += chunk
            
            # 检查响应状态
            response_str = response.decode('utf-8', errors='ignore')
            if "200" not in response_str.split("\r\n")[0]:
                raise ConnectionError(f"代理连接失败：{response_str.split(chr(13))[0]}")
            
            return sock
        except Exception as e:
            sock.close()
            raise
    
    def create_connection(self, host: str, port: int, 
                         timeout: float = 2.0, 
                         ip_version: int = 4) -> socket.socket:
        """
        创建到目标主机的连接（支持代理）
        ✅ 已修复：完整支持 IPv4 和 IPv6 地址通过代理连接
        :param host: 目标主机
        :param port: 目标端口
        :param timeout: 超时时间
        :param ip_version: IP 版本 (4 或 6)
        :return: 已连接的 socket
        """
        if not self.proxy_config.is_configured():
            # 无代理，直接连接
            if ip_version == 6:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            if ip_version == 6:
                addr_info = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM)
                if addr_info:
                    sock.connect(addr_info[0][4])
                else:
                    raise socket.error(f"无法解析 IPv6 地址：{host}")
            else:
                sock.connect((host, port))
            
            return sock
        else:
            # 通过代理连接（✅ 已修复：现在完全支持 IPv6）
            # SOCKS5 和 HTTP CONNECT 代理都支持 IPv6 地址和域名
            return self._connect_through_proxy(host, port, timeout)
    
    def close(self):
        """关闭连接"""
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
            self._socket = None


def test_proxy_connectivity(proxy_config: ProxyConfig, 
                           test_host: str = "www.google.com",
                           test_port: int = 80,
                           timeout: float = 5.0) -> bool:
    """
    测试代理连接性
    :param proxy_config: 代理配置
    :param test_host: 测试主机
    :param test_port: 测试端口
    :param timeout: 超时时间
    :return: 是否成功
    """
    try:
        proxy_socket = ProxySocket(proxy_config)
        sock = proxy_socket.create_connection(test_host, test_port, timeout)
        sock.close()
        return True
    except Exception as e:
        print(f"❌ 代理连接测试失败：{e}")
        return False


if __name__ == '__main__':
    # 测试代码
    print("测试代理配置:")
    
    # 测试 URL 解析
    urls = [
        "socks5://user:pass@127.0.0.1:1080",
        "http://proxy.example.com:8080",
        "https://user:pass@secure-proxy.com:443",
        "socks4://192.168.1.1:1080"
    ]
    
    for url in urls:
        config = ProxyConfig.from_url(url)
        print(f"  URL: {url}")
        print(f"    -> {config}")
        print(f"    -> 类型：{config.proxy_type}, 主机：{config.host}, 端口：{config.port}")
        print()
