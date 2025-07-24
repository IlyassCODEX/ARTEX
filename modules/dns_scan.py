# modules/dns_scan.py
import dns.query
import dns.zone
import time
import random
from typing import Dict, List, Optional, Tuple
from core.dns_utils import DNSUtils

class DNSScanner:
    def __init__(self, domain: str):
        self.domain = domain.strip().lower()
        if self.domain.startswith(('http://', 'https://')):
            self.domain = self.domain.split('//')[1].split('/')[0]
        
        self.dns_utils = DNSUtils()
    
    def check_zone_transfer(self, nameserver: str) -> Tuple[bool, List[str]]:
        """Attempt zone transfer (AXFR) from a nameserver"""
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, self.domain))
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    records.append(f"{name} {rdataset.ttl} IN {rdataset.rdtype} {' '.join(str(rdata) for rdata in rdataset)}")
            return True, records
        except Exception:
            return False, []
    
    def cache_snoop(self, hostname: str, nameserver: str = None) -> bool:
        """
        Perform DNS cache snooping by checking response time for non-existent subdomains
        Returns True if likely cached, False if not
        """
        test_subdomain = f"{random.randint(100000, 999999)}.{self.domain}"
        
        try:
            # First query (should be slow)
            start_time = time.time()
            try:
                self.dns_utils.query(test_subdomain, 'A', nameserver)
            except dns.resolver.NXDOMAIN:
                pass
            first_time = time.time() - start_time
            
            # Query for the target hostname
            start_time = time.time()
            try:
                self.dns_utils.query(hostname, 'A', nameserver)
            except Exception:
                pass
            target_time = time.time() - start_time
            
            # Second query for non-existent (should be fast if cached)
            start_time = time.time()
            try:
                self.dns_utils.query(test_subdomain, 'A', nameserver)
            except dns.resolver.NXDOMAIN:
                pass
            second_time = time.time() - start_time
            
            return target_time < first_time and (second_time < first_time/2)
        except Exception:
            return False
    
    def scan(self, aggressive: bool = False) -> Dict:
        """Perform comprehensive DNS scan and return structured results"""
        records = {}
        
        # Standard record types
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            records[record_type] = self.dns_utils.query(self.domain, record_type)
        
        # Special records
        spf = self.dns_utils.get_spf_record(self.domain)
        if spf:
            records['SPF'] = [spf]
        
        dmarc = self.dns_utils.get_dmarc_record(self.domain)
        if dmarc:
            records['DMARC'] = dmarc
        
        # Reverse DNS for A records
        if records.get('A'):
            records['PTR'] = []
            for ip in records['A']:
                ptr_records = self.dns_utils.reverse_lookup(ip)
                if ptr_records:
                    records['PTR'].extend(ptr_records)
        
        # Zone transfer attempts if in aggressive mode
        if aggressive and records.get('NS'):
            records['AXFR'] = {}
            for ns in records['NS']:
                success, zone_records = self.check_zone_transfer(ns)
                records['AXFR'][ns] = {
                    'success': success,
                    'records': zone_records if success else []
                }
        
        # Cache snooping if in aggressive mode
        if aggressive:
            records['CACHE_SNOOPING'] = {}
            records['CACHE_SNOOPING']['default_resolver'] = self.cache_snoop(self.domain)
            
            if records.get('NS'):
                for ns in records['NS']:
                    records['CACHE_SNOOPING'][ns] = self.cache_snoop(self.domain, ns)
        
        return {k: v for k, v in records.items() if v}
