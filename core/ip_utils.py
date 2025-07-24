# core/ip_utils.py
import ipaddress
from typing import Dict, Set

class IPUtils:
    def __init__(self, cdn_ranges: Dict[str, list[str]]):
        self.cdn_ranges = cdn_ranges
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except:
            return False
    
    def is_cdn_ip(self, ip: str) -> bool:
        """Check if IP belongs to known CDN ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            for cdn, ranges in self.cdn_ranges.items():
                for range_str in ranges:
                    if ip_obj in ipaddress.ip_network(range_str, strict=False):
                        return True
        except:
            pass
            
        return False
    
    def is_potentially_real_ip(self, ip: str) -> bool:
        """Check if IP might be a real server (not CDN)"""
        return not self.is_cdn_ip(ip) and not self.is_private_ip(ip)
