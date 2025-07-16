"""
Subdomain Enumeration Module

A comprehensive subdomain discovery tool that combines multiple enumeration techniques:
- Certificate Transparency logs (crt.sh)
- Passive DNS lookups
- DNS bruteforcing
- Subdomain takeover detection
- DNS cache optimization

Features:
- Multi-threaded execution
- DNS caching for performance
- Comprehensive validation
- Takeover vulnerability detection
- Configurable settings
"""

import requests
import dns.resolver
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import time
from urllib.parse import urlparse
from typing import List, Dict, Set, Optional
import random
import functools
import cachetools

class SubdomainEnumerator:
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the subdomain enumerator with configuration
        
        Args:
            config: Optional configuration dictionary with:
                   - max_workers: Thread pool size (default: 50)
                   - request_timeout: HTTP request timeout (default: 10)
                   - rate_limit_delay: Delay between requests (default: 1)
                   - bruteforce_list: Custom subdomain wordlist
        """
        self.config = config or {}
        self.found_subdomains = set()
        self.dns_cache = cachetools.TTLCache(maxsize=1000, ttl=3600)  # 1 hour cache
        self.request_timeout = self.config.get('request_timeout', 10)
        self.max_workers = self.config.get('max_workers', 50)
        self.rate_limit_delay = self.config.get('rate_limit_delay', 1)
        
        # User agent rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
        ]

    def enumerate(self, domain: str) -> List[Dict]:
        """
        Perform comprehensive subdomain enumeration
        
        Args:
            domain: Target domain (e.g., 'example.com')
            
        Returns:
            List of dictionaries containing subdomain details:
            - subdomain: Full subdomain name
            - ip: Resolved IP address
            - http_status: HTTP status code if web server
            - https_status: HTTPS status code if web server
            - title: Page title if available
            - headers: HTTP headers if available
            - takeover_vulnerable: Dict if vulnerable to takeover
        """
        print(f"[*] Starting subdomain enumeration for {domain}")
        
        # Run all enumeration methods
        sources = [
            self._crt_sh_search,
            self._dns_bruteforce,
            self._passive_dns_lookup
        ]
        
        with ThreadPoolExecutor(max_workers=len(sources)) as executor:
            futures = [executor.submit(source, domain) for source in sources]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[-] Enumeration error: {e}")
                    continue
        
        # Validate and enrich results
        validated = self._validate_subdomains(list(self.found_subdomains))
        
        # Check for takeovers
        self._check_subdomain_takeovers(validated)
        
        print(f"[+] Found {len(validated)} valid subdomains")
        return validated

    def _make_request(self, url: str) -> Optional[requests.Response]:
        """
        Make HTTP request with rate limiting and error handling
        
        Args:
            url: URL to request
            
        Returns:
            Response object or None if failed
        """
        time.sleep(self.rate_limit_delay)
        
        try:
            response = requests.get(
                url,
                headers={'User-Agent': random.choice(self.user_agents)},
                timeout=self.request_timeout,
                verify=False
            )
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            print(f"[-] Request failed for {url}: {e}")
            return None

    def _crt_sh_search(self, domain: str) -> None:
        """Query certificate transparency logs from crt.sh"""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                for cert in response.json():
                    for name in cert.get('name_value', '').split('\n'):
                        name = name.strip().lower()
                        if name and self._is_valid_subdomain(name, domain):
                            self.found_subdomains.add(name.replace('*.', ''))
        except Exception as e:
            print(f"[-] crt.sh search error: {e}")

    def _passive_dns_lookup(self, domain: str) -> None:
        """Perform passive DNS lookups using public sources"""
        try:
            sources = [
                self._dnsdumpster_lookup,
                self._hackertarget_lookup
            ]
            
            with ThreadPoolExecutor(max_workers=len(sources)) as executor:
                futures = [executor.submit(source, domain) for source in sources]
                for future in as_completed(futures):
                    try:
                        for subdomain in future.result():
                            self.found_subdomains.add(subdomain)
                    except Exception as e:
                        print(f"[-] Passive DNS error: {e}")
        except Exception as e:
            print(f"[-] Passive DNS lookup failed: {e}")

    def _dnsdumpster_lookup(self, domain: str) -> Set[str]:
        """Query DNS Dumpster for subdomains"""
        try:
            response = self._make_request("https://dnsdumpster.com/")
            if not response:
                return set()
                
            csrf_token = re.search(
                r"name='csrfmiddlewaretoken' value='([^']+)'", 
                response.text
            )
            if not csrf_token:
                return set()
                
            headers = {
                'Referer': 'https://dnsdumpster.com/',
                'Cookie': f"csrftoken={csrf_token.group(1)}"
            }
            data = {
                'csrfmiddlewaretoken': csrf_token.group(1),
                'targetip': domain
            }
            
            response = requests.post(
                "https://dnsdumpster.com/",
                headers=headers,
                data=data,
                timeout=self.request_timeout
            )
            
            if response.status_code == 200:
                subdomains = set()
                pattern = r">([a-zA-Z0-9\.\-]+" + re.escape(domain) + r")<"
                for match in re.finditer(pattern, response.text):
                    subdomain = match.group(1).lower()
                    if self._is_valid_subdomain(subdomain, domain):
                        subdomains.add(subdomain)
                return subdomains
        except Exception as e:
            print(f"[-] DNS Dumpster error: {e}")
        return set()

    def _hackertarget_lookup(self, domain: str) -> Set[str]:
        """Query HackerTarget's API for subdomains"""
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                subdomains = set()
                for line in response.text.split('\n'):
                    if line.strip():
                        subdomain = line.split(',')[0].lower()
                        if self._is_valid_subdomain(subdomain, domain):
                            subdomains.add(subdomain)
                return subdomains
        except Exception as e:
            print(f"[-] HackerTarget error: {e}")
        return set()

    def _dns_bruteforce(self, domain: str) -> None:
        """Bruteforce common subdomains"""
        wordlist = self.config.get('bruteforce_list', [
            'www', 'mail', 'ftp', 'webmail', 'admin', 'test',
            'dev', 'staging', 'api', 'blog', 'shop', 'app',
            'secure', 'portal', 'cpanel', 'whm', 'autodiscover'
        ])
        
        check_func = functools.partial(self._check_subdomain, domain=domain)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(check_func, sub): sub for sub in wordlist}
            for future in as_completed(futures):
                if result := future.result():
                    self.found_subdomains.add(result)

    def _check_subdomain(self, sub: str, domain: str) -> Optional[str]:
        """Check if subdomain exists with DNS caching"""
        subdomain = f"{sub}.{domain}"
        
        if subdomain in self.dns_cache:
            return subdomain if self.dns_cache[subdomain] else None
            
        try:
            dns.resolver.resolve(subdomain, 'A')
            self.dns_cache[subdomain] = True
            return subdomain
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            self.dns_cache[subdomain] = False
            return None
        except Exception as e:
            print(f"[-] DNS resolution error for {subdomain}: {e}")
            return None

    def _check_subdomain_takeovers(self, subdomains: List[Dict]) -> None:
        """Check for vulnerable subdomain takeovers"""
        vulnerable_services = {
            'github': [r'\.github\.io$', r'There isn\'t a GitHub Pages site here'],
            'aws/s3': [r'\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com$', r'<Code>NoSuchBucket</Code>'],
            'heroku': [r'\.herokuapp\.com$', r'No such app'],
            'shopify': [r'\.myshopify\.com$', r'Sorry, this shop is currently unavailable']
        }
        
        for subdomain in subdomains:
            if not subdomain.get('ip'):
                continue
                
            try:
                answers = dns.resolver.resolve(subdomain['subdomain'], 'CNAME')
                for answer in answers:
                    cname = str(answer.target).rstrip('.')
                    for service, (pattern, content_pattern) in vulnerable_services.items():
                        if re.search(pattern, cname, re.IGNORECASE):
                            url = f"http://{subdomain['subdomain']}"
                            try:
                                response = requests.get(url, timeout=5, verify=False)
                                if response.status_code == 404 and re.search(content_pattern, response.text):
                                    subdomain['takeover_vulnerable'] = {
                                        'service': service,
                                        'cname': cname,
                                        'confidence': 'high'
                                    }
                            except requests.RequestException:
                                pass
            except dns.resolver.NoAnswer:
                pass
            except Exception as e:
                print(f"[-] Takeover check error for {subdomain['subdomain']}: {e}")

    def _validate_subdomains(self, subdomains: List[str]) -> List[Dict]:
        """Validate subdomains and collect additional information"""
        validated = []
        
        def validate(subdomain: str) -> Optional[Dict]:
            try:
                # Get IP with caching
                if subdomain in self.dns_cache and isinstance(self.dns_cache[subdomain], dict):
                    ip = self.dns_cache[subdomain].get('ip')
                else:
                    ip = socket.gethostbyname(subdomain)
                    self.dns_cache[subdomain] = {'ip': ip}
                
                # Check web services
                http_status = None
                https_status = None
                title = ""
                headers = {}
                
                try:
                    response = requests.get(
                        f"https://{subdomain}", 
                        timeout=5,
                        verify=False,
                        headers={'User-Agent': random.choice(self.user_agents)}
                    )
                    https_status = response.status_code
                    headers = dict(response.headers)
                    
                    if 'text/html' in response.headers.get('content-type', ''):
                        if match := re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE):
                            title = match.group(1).strip()[:100]
                except:
                    try:
                        response = requests.get(
                            f"http://{subdomain}", 
                            timeout=5,
                            headers={'User-Agent': random.choice(self.user_agents)}
                        )
                        http_status = response.status_code
                        headers = dict(response.headers)
                        
                        if 'text/html' in response.headers.get('content-type', ''):
                            if match := re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE):
                                title = match.group(1).strip()[:100]
                    except:
                        pass
                
                return {
                    'subdomain': subdomain,
                    'ip': ip,
                    'http_status': http_status,
                    'https_status': https_status,
                    'title': title,
                    'headers': headers,
                    'timestamp': time.time()
                }
            except Exception as e:
                print(f"[-] Validation failed for {subdomain}: {e}")
                return None
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(validate, sub): sub for sub in subdomains}
            for future in as_completed(futures):
                if result := future.result():
                    validated.append(result)
        
        return validated

    def _is_valid_subdomain(self, subdomain: str, domain: str) -> bool:
        """Validate subdomain format and ownership"""
        return (subdomain and domain and 
                subdomain.endswith(domain) and
                re.match(r'^[a-zA-Z0-9.-]+$', subdomain) and
                not ('*' in subdomain or subdomain.startswith('.')))