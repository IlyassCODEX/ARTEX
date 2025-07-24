# core/dns_utils.py
import dns.resolver
import dns.reversename
from typing import List, Optional

class DNSUtils:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
    
    def query(self, domain: str, record_type: str, nameserver: str = None) -> List[str]:
        """Query DNS for a specific record type with optional nameserver"""
        resolver = self.resolver
        if nameserver:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [nameserver]
            resolver.timeout = 3
            resolver.lifetime = 3
        
        try:
            answers = resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            return []
        except Exception:
            return []
    
    def reverse_lookup(self, ip: str) -> List[str]:
        """Perform reverse DNS lookup"""
        try:
            addr = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(addr, 'PTR')
            return [str(rdata) for rdata in answers]
        except Exception:
            return []
    
    def get_spf_record(self, domain: str) -> Optional[str]:
        """Extract SPF record from TXT records"""
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                if 'v=spf1' in str(rdata):
                    return str(rdata)
        except Exception:
            pass
        return None
    
    def get_dmarc_record(self, domain: str) -> List[str]:
        """Get DMARC record"""
        try:
            answers = self.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            return [str(rdata) for rdata in answers]
        except Exception:
            return []
