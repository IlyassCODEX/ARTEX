# modules/real_ip_discovery.py
import socket
import dns.resolver
import concurrent.futures
import re
import ipaddress
from typing import Dict, List, Set
from core.http_client import HTTPClient
from core.ip_utils import IPUtils
from core.constants import CDN_RANGES, IP_HEADERS

class RealIPDiscovery:
    def __init__(self):
        self.http_client = HTTPClient()
        self.ip_utils = IPUtils(CDN_RANGES)
        
    def discover_real_ips(self, domain: str, subdomains_data: List[Dict] = None, dns_data: Dict = None) -> List[str]:
        """Main function to discover real IPs using existing scan results"""
        all_found_ips = {}  # Track which method found which IPs
        
        # Method 1: Subdomain analysis from existing results
        subdomain_ips = self._analyze_existing_subdomains(subdomains_data)
        all_found_ips['subdomains'] = subdomain_ips
        
        # Method 2: DNS records from existing results
        dns_ips = self._analyze_existing_dns(dns_data)
        all_found_ips['dns_records'] = dns_ips
        
        # Method 3: Certificate transparency logs
        ct_ips = self._check_certificate_transparency(domain)
        all_found_ips['cert_transparency'] = ct_ips
        
        # Method 4: HTTP headers analysis
        header_ips = self._analyze_http_headers(domain)
        all_found_ips['http_headers'] = header_ips
        
        # Method 5: Mail server analysis (most reliable)
        mail_ips = self._check_mail_servers(domain)
        all_found_ips['mail_servers'] = mail_ips
        
        # Combine all results
        all_ips = set()
        for method, ips in all_found_ips.items():
            all_ips.update(ips)
        
        # Enhanced filtering
        filtered_ips = self._enhanced_filtering(all_ips, all_found_ips, domain)
        
        return list(filtered_ips)
    
    def _analyze_existing_subdomains(self, subdomains_data: List[Dict]) -> Set[str]:
        """Analyze existing subdomains data to find potential real IPs"""
        real_ips = set()
        
        if not subdomains_data:
            return real_ips
            
        for subdomain_info in subdomains_data:
            if 'ip' in subdomain_info:
                ip = subdomain_info['ip']
                if self.ip_utils.is_potentially_real_ip(ip):
                    real_ips.add(ip)
        
        return real_ips
    
    def _analyze_existing_dns(self, dns_data: Dict) -> Set[str]:
        """Analyze existing DNS data to find potential real IPs"""
        real_ips = set()
        
        if not dns_data:
            return real_ips
            
        # Check A records
        if 'A' in dns_data:
            for ip in dns_data['A']:
                if self.ip_utils.is_potentially_real_ip(ip):
                    real_ips.add(ip)
        
        # Check AAAA records
        if 'AAAA' in dns_data:
            for ip in dns_data['AAAA']:
                if self.ip_utils.is_potentially_real_ip(ip):
                    real_ips.add(ip)
        
        # Check MX records (extract IPs from mail servers)
        if 'MX' in dns_data:
            for mx_record in dns_data['MX']:
                try:
                    mx_host = mx_record.split()[-1].rstrip('.')
                    ips = socket.gethostbyname_ex(mx_host)[2]
                    for ip in ips:
                        if self.ip_utils.is_potentially_real_ip(ip):
                            real_ips.add(ip)
                except:
                    continue
        
        return real_ips
    
    def _enhanced_filtering(self, all_ips: Set[str], found_by_method: Dict[str, Set[str]], domain: str) -> Set[str]:
        """Enhanced filtering with confidence scoring"""
        scored_ips = {}
        
        for ip in all_ips:
            if not self.ip_utils.is_potentially_real_ip(ip):
                continue
                
            score = 0
            methods = []
            
            # Score based on discovery method (some are more reliable)
            for method, ips in found_by_method.items():
                if ip in ips:
                    methods.append(method)
                    if method == 'mail_servers':
                        score += 10  # Mail servers are very reliable
                    elif method == 'http_headers':
                        score += 8   # Headers are quite reliable
                    elif method == 'dns_records':
                        score += 6   # DNS records are moderately reliable
                    elif method == 'cert_transparency':
                        score += 4   # CT logs can have false positives
                    elif method == 'subdomains':
                        score += 3   # Subdomains often have many false positives
            
            # Bonus points if found by multiple methods
            if len(methods) > 1:
                score += 5 * len(methods)
            
            # Verify the IP actually responds
            responds = self._verify_ip_responds(ip)
            if responds:
                score += 10
            
            scored_ips[ip] = {'score': score, 'methods': methods, 'responds': responds}
        
        # Filter by minimum score threshold
        min_score = 8
        high_confidence_ips = {
            ip: data for ip, data in scored_ips.items() 
            if data['score'] >= min_score
        }
        
        return set(high_confidence_ips.keys())
    
    def _check_certificate_transparency(self, domain: str) -> Set[str]:
        """Check certificate transparency logs for associated IPs"""
        real_ips = set()
        
        try:
            # Query CT logs API (crt.sh is a popular one)
            url = f"https://crt.sh/?q={domain}&output=json"
            response = self.http_client.get(url)
            
            if response and response.status_code == 200:
                certs = response.json()
                
                # Extract unique domain names from certificates
                ct_domains = set()
                for cert in certs[:50]:  # Limit to recent certificates
                    name_value = cert.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip()
                        if name and not name.startswith('*'):
                            ct_domains.add(name)
                
                # Resolve these domains to find potential real IPs
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_domain = {
                        executor.submit(self._resolve_and_check, domain): domain 
                        for domain in ct_domains
                    }
                    
                    for future in concurrent.futures.as_completed(future_to_domain):
                        try:
                            ips = future.result()
                            real_ips.update(ips)
                        except:
                            continue
                            
        except Exception as e:
            pass
            
        return real_ips
    
    def _analyze_http_headers(self, domain: str) -> Set[str]:
        """Analyze HTTP headers for real IP disclosure"""
        real_ips = set()
        
        try:
            # Try different request methods and paths
            test_paths = ['/', '/admin', '/test', '/.env', '/debug']
            
            for path in test_paths:
                try:
                    url = f"https://{domain}{path}"
                    response = self.http_client.get(url)
                    if not response:
                        continue
                    
                    for header_name, header_value in response.headers.items():
                        if any(ip_header.lower() in header_name.lower() for ip_header in IP_HEADERS):
                            # Extract IP patterns from header value
                            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                            found_ips = re.findall(ip_pattern, header_value)
                            
                            for ip in found_ips:
                                if self.ip_utils.is_potentially_real_ip(ip):
                                    real_ips.add(ip)
                                    
                except Exception:
                    continue
                    
        except Exception as e:
            pass
            
        return real_ips
    
    def _check_mail_servers(self, domain: str) -> Set[str]:
        """Check mail servers as they often reveal real IPs"""
        real_ips = set()
        
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            
            for mx in mx_records:
                mail_server = str(mx.exchange).rstrip('.')
                try:
                    mail_ips = socket.gethostbyname_ex(mail_server)[2]
                    for ip in mail_ips:
                        if self.ip_utils.is_potentially_real_ip(ip):
                            real_ips.add(ip)
                except:
                    continue
                    
        except Exception as e:
            pass
            
        return real_ips
    
    def _resolve_and_check(self, domain: str) -> List[str]:
        """Resolve domain and check if it's behind CDN"""
        try:
            answers = dns.resolver.resolve(domain, 'A')
            ips = [str(answer) for answer in answers]
            
            # Quick check if this might be a real server
            for ip in ips:
                if self.ip_utils.is_potentially_real_ip(ip):
                    return ips
            return []
        except:
            return []
    
    def _verify_ip_responds(self, ip: str) -> bool:
        """Verify that the IP actually responds and seems to host content"""
        try:
            # Quick TCP connection test on common ports
            import socket
            
            # Test common web ports
            for port in [80, 443, 8080, 8443]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:  # Port is open
                    return True
            
            return False
            
        except Exception:
            return False
