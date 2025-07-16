import re
import requests
import socket
import dns.resolver
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from typing import Dict, List, Optional, Tuple
import json
import os
import warnings
import time
import random
from datetime import datetime

warnings.filterwarnings('ignore', category=UserWarning, module='bs4')

class TechnologyDetector:
    def __init__(self):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
        ]
        
        # Initialize cache first
        self.cache = {
            'dns': {},
            'ip_ranges': {},
            'js_analysis': {}
        }

        # Load databases from external files if available
        self.tech_db = self._load_database('technologies.json') or self._default_tech_db()
        self.cloud_db = self._load_database('cloud_providers.json') or self._default_cloud_db()
        self.cdn_db = self._load_database('cdn_providers.json') or self._default_cdn_db()
        self.secret_patterns = self._load_database('secret_patterns.json') or self._default_secret_patterns()
        self.exposed_files = self._load_database('exposed_files.json') or self._default_exposed_files()
        
        # Rate limiting control
        self.last_request_time = 0
        self.request_delay = 1.0  # seconds between requests
        

    def _load_database(self, filename: str) -> Optional[Dict]:
        """Load database from JSON file if exists"""
        try:
            with open(f'data/{filename}', 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def _default_tech_db(self) -> Dict:
        """Default technology fingerprint database"""
        return {
            'web_servers': {
                'nginx': {'headers': ['server'], 'pattern': r'nginx/?(\d+\.\d+\.\d+)?', 'cpe': 'cpe:/a:nginx:nginx'},
                'apache': {'headers': ['server'], 'pattern': r'Apache/?(\d+\.\d+\.\d+)?', 'cpe': 'cpe:/a:apache:http_server'},
                'iis': {'headers': ['server'], 'pattern': r'Microsoft-IIS/?(\d+\.\d+)?', 'cpe': 'cpe:/a:microsoft:iis'},
                'litespeed': {'headers': ['server'], 'pattern': r'LiteSpeed', 'cpe': 'cpe:/a:litespeed:litespeed_web_server'},
                'caddy': {'headers': ['server'], 'pattern': r'Caddy', 'cpe': 'cpe:/a:caddyserver:caddy'}
            },
            'programming': {
                'php': {'headers': ['x-powered-by'], 'pattern': r'PHP/?(\d+\.\d+\.\d+)?', 'cpe': 'cpe:/a:php:php'},
                'node.js': {'headers': ['x-powered-by'], 'pattern': r'Express|Node\.js', 'cpe': 'cpe:/a:nodejs:node.js'},
                'python': {'headers': ['x-powered-by'], 'pattern': r'Python/?(\d+\.\d+\.\d+)?', 'cpe': 'cpe:/a:python:python'},
                'ruby': {'headers': ['x-powered-by'], 'pattern': r'Ruby|Rack', 'cpe': 'cpe:/a:ruby-lang:ruby'},
                'java': {'headers': ['x-powered-by'], 'pattern': r'Java|Servlet/?(\d+\.\d+)?', 'cpe': 'cpe:/a:oracle:jre'}
            },
            'frameworks': {
                'wordpress': {'pattern': r'wp-content|wp-includes|wordpress', 'cpe': 'cpe:/a:wordpress:wordpress'},
                'django': {'headers': ['x-frame-options'], 'pattern': r'csrftoken|Django/?(\d+\.\d+\.\d+)?', 'cpe': 'cpe:/a:djangoproject:django'},
                'laravel': {'pattern': r'laravel_session|XSRF-TOKEN', 'cpe': 'cpe:/a:laravel:laravel'},
                'rails': {'pattern': r'_rails_session|Ruby on Rails', 'cpe': 'cpe:/a:rubyonrails:rails'},
                'express': {'pattern': r'Express/?(\d+\.\d+\.\d+)?', 'cpe': 'cpe:/a:expressjs:express'},
                'spring': {'pattern': r'Spring Framework|jsessionid', 'cpe': 'cpe:/a:pivotal_software:spring_framework'}
            },
            'cms': {
                'joomla': {'pattern': r'joomla', 'cpe': 'cpe:/a:joomla:joomla'},
                'drupal': {'pattern': r'drupal', 'cpe': 'cpe:/a:drupal:drupal'},
                'magento': {'pattern': r'magento', 'cpe': 'cpe:/a:magento:magento'},
                'shopify': {'pattern': r'shopify', 'cpe': 'cpe:/a:shopify:shopify'},
                'prestashop': {'pattern': r'prestashop', 'cpe': 'cpe:/a:prestashop:prestashop'}
            },
            'security': {
                'waf': {
                    'cloudflare': {'headers': ['server', 'cf-ray'], 'cpe': 'cpe:/a:cloudflare:cloudflare_waf'},
                    'akamai': {'headers': ['server', 'x-akamai'], 'cpe': 'cpe:/a:akamai:akamai_waf'},
                    'imperva': {'headers': ['x-cdn', 'x-imperva'], 'cpe': 'cpe:/a:imperva:imperva_waf'}
                }
            }
        }

    def _default_cloud_db(self) -> Dict:
        """Default cloud hosting fingerprint database"""
        return {
            'aws': {
                's3': {'dns': r's3\.amazonaws\.com', 'pattern': r'<Error><Code>AccessDenied</Code>', 'cpe': 'cpe:/a:amazon:aws_s3'},
                'ec2': {'headers': ['x-amz-id-2', 'x-amz-request-id'], 'cpe': 'cpe:/a:amazon:aws_ec2'},
                'cloudfront': {'headers': ['x-amz-cf-id'], 'cpe': 'cpe:/a:amazon:aws_cloudfront'},
                'elasticbeanstalk': {'dns': r'elasticbeanstalk\.com', 'cpe': 'cpe:/a:amazon:aws_elastic_beanstalk'}
            },
            'azure': {
                'blob': {'dns': r'blob\.core\.windows\.net', 'cpe': 'cpe:/a:microsoft:azure_blob_storage'},
                'websites': {'dns': r'azurewebsites\.net', 'cpe': 'cpe:/a:microsoft:azure_app_service'},
                'cdn': {'headers': ['x-azure-ref'], 'cpe': 'cpe:/a:microsoft:azure_cdn'}
            },
            'gcp': {
                'storage': {'dns': r'storage\.googleapis\.com', 'cpe': 'cpe:/a:google:google_cloud_storage'},
                'appengine': {'dns': r'appspot\.com', 'cpe': 'cpe:/a:google:google_app_engine'},
                'cloudrun': {'dns': r'run\.app', 'cpe': 'cpe:/a:google:google_cloud_run'}
            },
            'cloudflare': {
                'workers': {'dns': r'workers\.dev', 'cpe': 'cpe:/a:cloudflare:cloudflare_workers'}
            }
        }

    def _default_cdn_db(self) -> Dict:
        """Default CDN fingerprint database"""
        return {
            'cloudflare': {
                'headers': ['server', 'cf-ray'],
                'dns': ['cloudflare'],
                'ips': self._get_cloudflare_ips(),
                'cpe': 'cpe:/a:cloudflare:cloudflare_cdn'
            },
            'akamai': {
                'headers': ['server', 'x-akamai'],
                'dns': ['akamai'],
                'cpe': 'cpe:/a:akamai:akamai_cdn'
            },
            'fastly': {
                'headers': ['x-fastly'],
                'cpe': 'cpe:/a:fastly:fastly_cdn'
            },
            'aws cloudfront': {
                'headers': ['x-amz-cf-id'],
                'cpe': 'cpe:/a:amazon:aws_cloudfront'
            }
        }

    def _default_secret_patterns(self) -> List[Dict]:
        """Default patterns for detecting secrets in JS files"""
        return [
            {'name': 'AWS API Key', 'pattern': r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', 'severity': 'high'},
            {'name': 'AWS Secret Key', 'pattern': r'[0-9a-zA-Z/+]{40}', 'severity': 'critical'},
            {'name': 'Google API Key', 'pattern': r'AIza[0-9A-Za-z\-_]{35}', 'severity': 'high'},
            {'name': 'Database URL', 'pattern': r'(postgres|mysql|mongodb)://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9\-\.]+:[0-9]+/[a-zA-Z0-9_]+', 'severity': 'critical'},
            {'name': 'API Key', 'pattern': r'api[_-]?key[=:][a-zA-Z0-9_\-]+', 'severity': 'high'},
            {'name': 'Access Token', 'pattern': r'access[_-]?token[=:][a-zA-Z0-9_\-]+', 'severity': 'high'},
            {'name': 'OAuth Token', 'pattern': r'ya29\.[0-9A-Za-z\-_]+', 'severity': 'high'},
            {'name': 'SSH Private Key', 'pattern': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----', 'severity': 'critical'},
            {'name': 'Slack Token', 'pattern': r'xox[baprs]-([0-9a-zA-Z-]{10,48})?', 'severity': 'high'},
            {'name': 'Facebook Token', 'pattern': r'EAACEdEose0cBA[0-9A-Za-z]+', 'severity': 'high'},
            {'name': 'Twitter Token', 'pattern': r'[tT][wW][iI][tT][tT][eE][rR][0-9a-zA-Z\-_]{35,44}', 'severity': 'high'},
            {'name': 'GitHub Token', 'pattern': r'gh[pousr]_[0-9a-zA-Z]{36}', 'severity': 'high'},
            {'name': 'Stripe API Key', 'pattern': r'sk_(live|test)_[0-9a-zA-Z]{24}', 'severity': 'critical'},
            {'name': 'PayPal Braintree Token', 'pattern': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}', 'severity': 'critical'},
            {'name': 'Twilio API Key', 'pattern': r'SK[0-9a-fA-F]{32}', 'severity': 'high'},
            {'name': 'Mailgun API Key', 'pattern': r'key-[0-9a-zA-Z]{32}', 'severity': 'high'},
            {'name': 'Heroku API Key', 'pattern': r'[hH][eE][rR][oO][kK][uU][0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', 'severity': 'high'},
            {'name': 'SendGrid API Key', 'pattern': r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}', 'severity': 'high'}
        ]

    def _default_exposed_files(self) -> List[Dict]:
        """Default list of exposed files to check"""
        return [
            {'path': '/.git/HEAD', 'severity': 'high', 'description': 'Git repository metadata'},
            {'path': '/.env', 'severity': 'critical', 'description': 'Environment configuration file'},
            {'path': '/.htaccess', 'severity': 'medium', 'description': 'Apache server configuration'},
            {'path': '/robots.txt', 'severity': 'low', 'description': 'Web crawler instructions'},
            {'path': '/sitemap.xml', 'severity': 'low', 'description': 'Website structure'},
            {'path': '/phpinfo.php', 'severity': 'high', 'description': 'PHP configuration information'},
            {'path': '/admin/config.php', 'severity': 'critical', 'description': 'Admin configuration file'},
            {'path': '/.git/config', 'severity': 'high', 'description': 'Git configuration'},
            {'path': '/.gitignore', 'severity': 'low', 'description': 'Git ignore rules'},
            {'path': '/.DS_Store', 'severity': 'medium', 'description': 'macOS directory metadata'},
            {'path': '/.svn/entries', 'severity': 'high', 'description': 'SVN repository metadata'},
            {'path': '/.hg/hgrc', 'severity': 'high', 'description': 'Mercurial configuration'},
            {'path': '/.bzr/branch/branch.conf', 'severity': 'high', 'description': 'Bazaar configuration'},
            {'path': '/composer.lock', 'severity': 'medium', 'description': 'PHP dependencies'},
            {'path': '/composer.json', 'severity': 'medium', 'description': 'PHP project configuration'},
            {'path': '/package.json', 'severity': 'medium', 'description': 'Node.js project configuration'},
            {'path': '/yarn.lock', 'severity': 'medium', 'description': 'Yarn dependencies'},
            {'path': '/docker-compose.yml', 'severity': 'medium', 'description': 'Docker configuration'},
            {'path': '/Dockerfile', 'severity': 'medium', 'description': 'Docker build instructions'},
            {'path': '/config.php', 'severity': 'critical', 'description': 'Application configuration'},
            {'path': '/wp-config.php', 'severity': 'critical', 'description': 'WordPress configuration'},
            {'path': '/config.yaml', 'severity': 'high', 'description': 'Application configuration'},
            {'path': '/config.yml', 'severity': 'high', 'description': 'Application configuration'},
            {'path': '/config.json', 'severity': 'high', 'description': 'Application configuration'},
            {'path': '/database.sql', 'severity': 'critical', 'description': 'Database dump'},
            {'path': '/db.sql', 'severity': 'critical', 'description': 'Database dump'},
            {'path': '/dump.sql', 'severity': 'critical', 'description': 'Database dump'},
            {'path': '/backup.sql', 'severity': 'critical', 'description': 'Database backup'},
            {'path': '/backup.zip', 'severity': 'high', 'description': 'Application backup'},
            {'path': '/backup.tar.gz', 'severity': 'high', 'description': 'Application backup'},
            {'path': '/admin/.env', 'severity': 'critical', 'description': 'Admin environment configuration'},
            {'path': '/admin/.git/HEAD', 'severity': 'high', 'description': 'Admin Git metadata'},
            {'path': '/admin/.htpasswd', 'severity': 'critical', 'description': 'Admin password file'},
            {'path': '/admin/config.yaml', 'severity': 'critical', 'description': 'Admin configuration'},
            {'path': '/storage/.env', 'severity': 'critical', 'description': 'Storage environment configuration'},
            {'path': '/storage/config.php', 'severity': 'critical', 'description': 'Storage configuration'},
            {'path': '/api/.env', 'severity': 'critical', 'description': 'API environment configuration'},
            {'path': '/api/config.php', 'severity': 'critical', 'description': 'API configuration'},
            {'path': '/logs/error.log', 'severity': 'high', 'description': 'Error logs'},
            {'path': '/logs/access.log', 'severity': 'high', 'description': 'Access logs'},
            {'path': '/error.log', 'severity': 'high', 'description': 'Error logs'},
            {'path': '/access.log', 'severity': 'high', 'description': 'Access logs'},
            {'path': '/server-status', 'severity': 'medium', 'description': 'Apache server status'},
            {'path': '/server-info', 'severity': 'medium', 'description': 'Apache server information'}
        ]

    def _get_cloudflare_ips(self) -> List[str]:
        """Get Cloudflare IP ranges with caching"""
        if 'cloudflare' in self.cache['ip_ranges']:
            return self.cache['ip_ranges']['cloudflare']
        
        try:
            response = requests.get('https://www.cloudflare.com/ips-v4', timeout=10)
            ips = response.text.split('\n')[:-1]
            self.cache['ip_ranges']['cloudflare'] = ips
            return ips
        except Exception as e:
            return [
                '103.21.244.0/22',
                '103.22.200.0/22',
                '103.31.4.0/22',
                '104.16.0.0/13',
                '104.24.0.0/14',
                '108.162.192.0/18',
                '131.0.72.0/22',
                '141.101.64.0/18',
                '162.158.0.0/15',
                '172.64.0.0/13',
                '173.245.48.0/20',
                '188.114.96.0/20',
                '190.93.240.0/20',
                '197.234.240.0/22',
                '198.41.128.0/17'
            ]

    def _rate_limit(self):
        """Enforce rate limiting between requests"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.request_delay:
            time.sleep(self.request_delay - elapsed)
        self.last_request_time = time.time()

    def _get_random_user_agent(self) -> str:
        """Get a random user agent from the list"""
        return random.choice(self.user_agents)

    def _make_request(self, url: str) -> Optional[requests.Response]:
        """Make a HTTP request with rate limiting"""
        self._rate_limit()
        
        try:
            headers = {'User-Agent': self._get_random_user_agent()}
            return requests.get(
                url,
                headers=headers,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
        except requests.RequestException:
            return None
        
    def detect_technologies(self, url: str, html: str = None, headers: Dict = None) -> Dict:
        """Detect technologies used by a website"""
        results = {
            'technologies': [],
            'cloud': None,
            'cdn': None,
            'exposed_files': [],
            'secrets': [],
            'endpoints': []
        }

        try:
            # Make initial request if not provided
            if not headers or not html:
                response = self._make_request(url)
                if response:
                    headers = dict(response.headers)
                    html = response.text

            # Detect technologies
            results['technologies'] = self._detect_tech_from_headers(headers or {}, html or "")
            
            # Detect cloud hosting
            results['cloud'] = self._detect_cloud(url, headers or {}, html or "")
            
            # Detect CDN
            results['cdn'] = self._detect_cdn(url, headers or {})
            
            # Check for exposed files
            results['exposed_files'] = self._check_exposed_files(url)
            
            # Analyze JavaScript files
            if html:
                js_urls = self._extract_js_urls(url, html)
                for js_url in js_urls[:3]:  # Limit to 3 JS files
                    secrets, endpoints = self._analyze_js_file(js_url)
                    results['secrets'].extend(secrets)
                    results['endpoints'].extend(endpoints)
            
        except Exception:
            pass  # Silently continue on errors
        
        return results

    def _get_dns_info(self, domain: str) -> List[Dict]:
        """Get DNS information for a domain"""
        if domain in self.cache['dns']:
            return self.cache['dns'][domain]
        
        try:
            dns_info = []
            
            # Get A records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                dns_info.extend([{'type': 'A', 'value': rdata.address} for rdata in answers])
            except:
                pass
            
            # Get AAAA records
            try:
                answers = dns.resolver.resolve(domain, 'AAAA')
                dns_info.extend([{'type': 'AAAA', 'value': rdata.address} for rdata in answers])
            except:
                pass
            
            # Get MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                dns_info.extend([{'type': 'MX', 'value': str(rdata.exchange)} for rdata in answers])
            except:
                pass
            
            # Get TXT records
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                dns_info.extend([{'type': 'TXT', 'value': str(rdata.strings)} for rdata in answers])
            except:
                pass
            
            self.cache['dns'][domain] = dns_info
            return dns_info
            
        except Exception as e:
            return []

    def _get_ip_address(self, domain: str) -> Optional[str]:
        """Get IP address for a domain"""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    def _detect_tech_from_headers(self, headers: Dict, html: str) -> List[Dict]:
        """Detect technologies from HTTP headers and HTML"""
        detected = []
        
        for category, technologies in self.tech_db.items():
            for tech, patterns in technologies.items():
                tech_info = {
                    'name': tech,
                    'category': category,
                    'confidence': 0,
                    'sources': [],
                    'versions': []
                }
                
                # Check headers
                if 'headers' in patterns:
                    for header in patterns['headers']:
                        for actual_header, value in headers.items():
                            if header.lower() == actual_header.lower():
                                tech_info['sources'].append(f'header:{actual_header}')
                                tech_info['confidence'] = max(tech_info['confidence'], 90)
                                
                                # Extract version if pattern exists
                                if 'pattern' in patterns:
                                    match = re.search(patterns['pattern'], value, re.I)
                                    if match:
                                        if len(match.groups()) > 0 and match.group(1):
                                            tech_info['versions'].append(match.group(1))
                                        tech_info['confidence'] = 100
                
                # Check HTML patterns
                if html and 'pattern' in patterns:
                    if re.search(patterns['pattern'], html, re.I):
                        tech_info['sources'].append('html')
                        tech_info['confidence'] = max(tech_info['confidence'], 80)
                        
                        # Extract version if available
                        if 'version' in patterns:
                            match = re.search(patterns['version'], html, re.I)
                            if match and len(match.groups()) > 0 and match.group(1):
                                tech_info['versions'].append(match.group(1))
                
                # Add to results if confidence is above threshold
                if tech_info['confidence'] >= 70:
                    # Deduplicate versions
                    tech_info['versions'] = list(set(tech_info['versions']))
                    
                    # If we have multiple versions, keep the highest one (assuming semantic versioning)
                    if len(tech_info['versions']) > 0:
                        tech_info['versions'].sort(reverse=True)
                        tech_info['version'] = tech_info['versions'][0]
                    else:
                        tech_info['version'] = None
                    
                    # Remove the versions list from the output
                    if 'versions' in tech_info:
                        del tech_info['versions']
                    
                    detected.append(tech_info)
        
        return detected

    def _detect_cloud(self, url: str, headers: Dict, html: str) -> Optional[Dict]:
        """Detect cloud hosting provider"""
        domain = urlparse(url).netloc
        
        for provider, services in self.cloud_db.items():
            for service, patterns in services.items():
                detection = {
                    'provider': provider,
                    'service': service,
                    'confidence': 0,
                    'sources': []
                }
                
                # Check DNS
                if 'dns' in patterns:
                    if re.search(patterns['dns'], domain, re.I):
                        detection['sources'].append('dns')
                        detection['confidence'] = 100
                
                # Check headers
                if headers and 'headers' in patterns:
                    for header in patterns['headers']:
                        for actual_header in headers:
                            if header.lower() == actual_header.lower():
                                detection['sources'].append(f'header:{actual_header}')
                                detection['confidence'] = max(detection['confidence'], 90)
                
                # Check HTML patterns
                if html and 'pattern' in patterns:
                    if re.search(patterns['pattern'], html, re.I):
                        detection['sources'].append('html')
                        detection['confidence'] = max(detection['confidence'], 80)
                
                # Return if we have high confidence
                if detection['confidence'] >= 80:
                    return detection
        
        return None

    def _detect_cdn(self, url: str, headers: Dict) -> Optional[Dict]:
        """Detect CDN usage"""
        domain = urlparse(url).netloc
        
        for cdn, patterns in self.cdn_db.items():
            detection = {
                'provider': cdn,
                'confidence': 0,
                'sources': []
            }
            
            # Check headers
            if headers and 'headers' in patterns:
                for header in patterns['headers']:
                    for actual_header in headers:
                        if header.lower() == actual_header.lower():
                            detection['sources'].append(f'header:{actual_header}')
                            detection['confidence'] = max(detection['confidence'], 100)
            
            # Check DNS
            if 'dns' in patterns:
                for dns_pattern in patterns['dns']:
                    if dns_pattern in domain.lower():
                        detection['sources'].append('dns')
                        detection['confidence'] = max(detection['confidence'], 90)
            
            # Check IP ranges (for Cloudflare)
            if 'ips' in patterns:
                try:
                    ip = self._get_ip_address(domain)
                    if ip:
                        for ip_range in patterns['ips']:
                            if self._ip_in_range(ip, ip_range):
                                detection['sources'].append('ip_range')
                                detection['confidence'] = max(detection['confidence'], 95)
                except:
                    pass
            
            # Return if we have high confidence
            if detection['confidence'] >= 80:
                return detection
        
        return None

    def _ip_in_range(self, ip: str, ip_range: str) -> bool:
        """Check if IP is in a CIDR range"""
        try:
            if '/' in ip_range:
                network, netmask = ip_range.split('/')
                netmask = int(netmask)
                
                # Convert IPs to integers
                ip_int = int.from_bytes(socket.inet_aton(ip), byteorder='big')
                network_int = int.from_bytes(socket.inet_aton(network), byteorder='big')
                
                # Calculate network mask
                mask = (~((1 << (32 - netmask)) - 1)) & 0xFFFFFFFF
                
                return (ip_int & mask) == (network_int & mask)
            else:
                return ip == ip_range
        except:
            return False

    def _check_exposed_files(self, url: str) -> List[Dict]:
        """Check for common exposed files (.git, .env, etc.)"""
        exposed = []
        base_url = url.rstrip('/')
        
        for file_info in self.exposed_files:
            try:
                full_url = f"{base_url}{file_info['path']}"
                
                # Skip if we've already checked this URL
                if full_url in self.cache['js_analysis']:
                    continue
                
                response = self._make_request(full_url)
                if response and response.status_code == 200:
                    exposed.append({
                        'url': full_url,
                        'path': file_info['path'],
                        'status': response.status_code,
                        'content_type': response.headers.get('content-type', ''),
                        'severity': file_info['severity'],
                        'description': file_info['description'],
                        'size': len(response.content)
                    })
            except:
                continue
        
        return exposed

    def _extract_js_urls(self, url: str, html: str) -> List[str]:
        """Extract JavaScript file URLs from HTML"""
        js_urls = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for script in soup.find_all('script'):
            if script.get('src'):
                src = script.get('src')
                if not src.startswith(('http://', 'https://')):
                    src = self._make_absolute(url, src)
                js_urls.append(src)
        
        # Also check for dynamic imports and other JS references
        for pattern in [r'src=["\']([^"\']+\.js)', r'import\s+["\']([^"\']+\.js)']:
            matches = re.finditer(pattern, html)
            for match in matches:
                src = match.group(1)
                if not src.startswith(('http://', 'https://')):
                    src = self._make_absolute(url, src)
                if src not in js_urls:
                    js_urls.append(src)
        
        return list(set(js_urls))[:10]  # Limit to 10 unique JS files

    def _make_absolute(self, base_url: str, relative_url: str) -> str:
        """Convert relative URL to absolute"""
        base = urlparse(base_url)
        
        if relative_url.startswith('//'):
            return f"{base.scheme}:{relative_url}"
        elif relative_url.startswith('/'):
            return f"{base.scheme}://{base.netloc}{relative_url}"
        elif relative_url.startswith('../') or relative_url.startswith('./'):
            return urljoin(base_url, relative_url)
        else:
            return f"{base.scheme}://{base.netloc}/{relative_url.lstrip('/')}"

    def _analyze_js_file(self, url: str) -> Tuple[List[Dict], List[Dict]]:
        """Analyze JavaScript file for secrets and API endpoints"""
        if url in self.cache['js_analysis']:
            return self.cache['js_analysis'][url]
        
        secrets = []
        endpoints = []
        
        try:
            response = self._make_request(url)
            if response and response.status_code == 200:
                content = response.text
                
                # Detect secrets
                for pattern in self.secret_patterns:
                    matches = re.finditer(pattern['pattern'], content)
                    for match in matches:
                        secrets.append({
                            'type': pattern['name'],
                            'match': match.group(0),
                            'context': self._get_context(content, match.start(), match.end()),
                            'file': url,
                            'severity': pattern.get('severity', 'medium'),
                            'line': content[:match.start()].count('\n') + 1
                        })
                
                # Detect API endpoints
                endpoint_patterns = [
                    r'https?://[a-zA-Z0-9\-\.]+/api/v[0-9]/[a-zA-Z0-9\-_/]+',
                    r'fetch\(["\'](https?://[^"\']+)["\']\)',
                    r'axios\.(get|post|put|delete)\(["\'](https?://[^"\']+)["\']\)',
                    r'\.ajax\({\s*url:\s*["\'](https?://[^"\']+)["\']',
                    r'window\.location\s*=\s*["\'](https?://[^"\']+)["\']',
                    r'https?://[a-zA-Z0-9\-\.]+/graphql',
                    r'https?://[a-zA-Z0-9\-\.]+/rest/v[0-9]/',
                    r'https?://[a-zA-Z0-9\-\.]+/oauth2/'
                ]
                
                for pattern in endpoint_patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        if 'axios' in pattern:
                            endpoint = match.group(2)
                            method = match.group(1).upper()
                        elif 'fetch' in pattern or 'ajax' in pattern:
                            endpoint = match.group(1)
                            method = 'GET' if 'get' in pattern.lower() else 'POST'
                        else:
                            endpoint = match.group(0)
                            method = 'GET'
                        
                        endpoints.append({
                            'url': endpoint,
                            'method': method,
                            'source': url,
                            'context': self._get_context(content, match.start(), match.end()),
                            'line': content[:match.start()].count('\n') + 1
                        })
        
        except Exception:
            pass  # Silently continue on errors
                
        # Cache results
        self.cache['js_analysis'][url] = (secrets, endpoints)
        return secrets, endpoints
        
    def _get_context(self, text: str, start: int, end: int, chars: int = 50) -> str:
        """Get surrounding context for a matched pattern"""
        context_start = max(0, start - chars)
        context_end = min(len(text), end + chars)
        return text[context_start:context_end]

    def _add_cpe_information(self, results: Dict):
        """Add CPE (Common Platform Enumeration) information to detected technologies"""
        for tech in results['technologies']:
            category = tech['category']
            name = tech['name']
            
            # Check in tech_db
            if category in self.tech_db and name in self.tech_db[category] and 'cpe' in self.tech_db[category][name]:
                tech['cpe'] = self.tech_db[category][name]['cpe']
            
            # Check in cloud_db
            if results['cloud']:
                provider = results['cloud']['provider']
                service = results['cloud']['service']
                if provider in self.cloud_db and service in self.cloud_db[provider] and 'cpe' in self.cloud_db[provider][service]:
                    results['cloud']['cpe'] = self.cloud_db[provider][service]['cpe']
            
            # Check in cdn_db
            if results['cdn']:
                provider = results['cdn']['provider']
                if provider in self.cdn_db and 'cpe' in self.cdn_db[provider]:
                    results['cdn']['cpe'] = self.cdn_db[provider]['cpe']

    def _calculate_confidence_scores(self, results: Dict):
        """Calculate and adjust confidence scores based on multiple factors"""
        # Adjust technology confidence based on number of sources
        for tech in results['technologies']:
            if len(tech['sources']) > 1:
                tech['confidence'] = min(100, tech['confidence'] + 5 * len(tech['sources']))
        
        # Adjust cloud confidence based on DNS + headers
        if results['cloud'] and len(results['cloud']['sources']) > 1:
            results['cloud']['confidence'] = min(100, results['cloud']['confidence'] + 10)
        
        # Adjust CDN confidence based on multiple indicators
        if results['cdn']:
            if len(results['cdn']['sources']) > 1:
                results['cdn']['confidence'] = min(100, results['cdn']['confidence'] + 10)
            
            # If we have both CDN and cloud detection, adjust confidence
            if results['cloud'] and results['cdn']['provider'].lower() in results['cloud']['provider'].lower():
                results['cdn']['confidence'] = min(100, results['cdn']['confidence'] + 5)