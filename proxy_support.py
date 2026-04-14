#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代理支持模块 - 提供 SOCKS 和 HTTP 代理功能
"""

import socket
import ssl
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
        通过 SOCKS 代理连接
        """
        try:
            # 尝试使用 socksio 库（纯 Python 实现，无需额外依赖）
            import socksio
            
            sock = socksio.socksioclient.SocksClient(
                proxy_addr=self.proxy_config.host,
                proxy_port=self.proxy_config.port,
                proxy_type=self.proxy_config.proxy_type.value,
                username=self.proxy_config.username,
                password=self.proxy_config.password
            )
            
            sock.connect((dest_host, dest_port), timeout=timeout)
            return sock
            
        except ImportError:
            # 如果没有 socksio，尝试使用 PySocks
            try:
                import socks
                
                sock = socks.socksocket()
                sock.settimeout(timeout)
                
                # 设置代理
                if self.proxy_config.proxy_type == ProxyType.SOCKS5:
                    proxy_type = socks.SOCKS5
                else:
                    proxy_type = socks.SOCKS4
                
                sock.set_proxy(
                    proxy_type,
                    self.proxy_config.host,
                    self.proxy_config.port,
                    username=self.proxy_config.username,
                    password=self.proxy_config.password
                )
                
                sock.connect((dest_host, dest_port))
                return sock
                
            except ImportError:
                raise ImportError(
                    "SOCKS 代理需要安装 socksio 或 PySocks 库。\n"
                    "请运行：pip install socksio 或 pip install PySocks"
                )
    
    def _connect_http(self, dest_host: str, dest_port: int,
                      timeout: float = 2.0) -> socket.socket:
        """
        通过 HTTP/HTTPS 代理连接（使用 CONNECT 方法）
        """
        # 创建到代理服务器的连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((self.proxy_config.host, self.proxy_config.port))
        
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
    
    def create_connection(self, host: str, port: int, 
                         timeout: float = 2.0, 
                         ip_version: int = 4) -> socket.socket:
        """
        创建到目标主机的连接（支持代理）
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
            # 通过代理连接（目前主要支持 IPv4）
            if ip_version == 6:
                print("⚠️  注意：代理模式下的 IPv6 支持可能有限")
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
