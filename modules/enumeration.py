# modules/enumeration.py
import requests
import re
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Tuple
from bs4 import BeautifulSoup
import random
import time

class AuthPageScanner:
    def __init__(self):
        self.common_login_paths = [
            '/login', '/signin', '/auth', '/oauth', '/admin', 
            '/wp-login.php', '/log-in', '/sign-in', '/account/login', 
            '/user/login', '/auth/login', '/authentication/login',
            '/signin/auth', '/member/login', '/portal/login'
        ]
        
        self.password_reset_paths = [
            '/password-reset', '/reset-password', '/forgot-password',
            '/account/recovery', '/user/password', '/password/forgot',
            '/auth/reset', '/recover', '/account/forgot',
            '/wp-login.php?action=lostpassword', '/passwordreset'
        ]
        
        self.common_auth_keywords = [
            'login', 'sign in', 'username', 'password', 'email',
            'forgot password', 'reset password', 'credentials',
            'authentication', 'two-factor', '2fa', 'otp'
        ]
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
        ]
        
        self.timeout = 10
        self.max_pages_to_check = 20  # Limit for safety

    def get_random_user_agent(self):
        return random.choice(self.user_agents)

    def is_auth_page(self, url, html_content):
        """Check if page appears to be an authentication page"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Check for common elements
        password_fields = soup.find_all('input', {'type': 'password'})
        username_fields = soup.find_all('input', {'type': ['text', 'email']})
        submit_buttons = soup.find_all('input', {'type': 'submit'})
        
        # Check page content for keywords
        text = soup.get_text().lower()
        has_keywords = any(keyword in text for keyword in self.common_auth_keywords)
        
        # Check URL path
        parsed = urlparse(url)
        path = parsed.path.lower()
        has_auth_path = any(auth_path in path for auth_path in self.common_login_paths + self.password_reset_paths)
        
        # Decision logic
        return len(password_fields) > 0 or has_keywords or has_auth_path

    def find_auth_pages(self, domain: str) -> Dict:
        """Find authentication pages using multiple techniques"""
        results = {
            'login_pages': [],
            'password_reset_pages': [],
            'other_auth_pages': []
        }
    
        try:
            # Technique 1: Check common paths directly
            for path in self.common_login_paths:
                url = f"https://{domain}{path}"
                if self._check_url(url, 'login'):
                    results['login_pages'].append({
                        'url': url,
                        'type': 'standard_login',
                        'source': 'path_scan',
                        'status': 200  # Assuming success if _check_url returns True
                    })
        
            for path in self.password_reset_paths:
                url = f"https://{domain}{path}"
                if self._check_url(url, 'reset'):
                    results['password_reset_pages'].append({
                        'url': url,
                        'subdomain': domain,
                        'status': 200,
                        'source': 'path_scan'
                    })
        
            # Technique 2: Crawl the homepage and follow links
            homepage_url = f"https://{domain}"
            response = self._safe_request(homepage_url)
        
            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                links = [a.get('href') for a in soup.find_all('a', href=True)]
            
                checked_urls = set()
                for link in links[:self.max_pages_to_check]:
                    try:
                        absolute_url = urljoin(homepage_url, link)
                        if absolute_url not in checked_urls:
                            checked_urls.add(absolute_url)
                            if self.is_auth_page(absolute_url, response.text):
                                page_type = self._classify_auth_page(absolute_url, response.text)
                                if page_type == 'login':
                                    results['login_pages'].append({
                                        'url': absolute_url,
                                        'type': 'standard_login',
                                        'source': 'crawling',
                                        'status': 200
                                    })
                                elif page_type == 'reset':
                                    results['password_reset_pages'].append({
                                        'url': absolute_url,
                                        'subdomain': domain,
                                        'status': 200,
                                        'source': 'crawling'
                                    })
                    except:
                        continue
        
            # Technique 3: Check for common auth providers
            self._check_auth_providers(domain, results)
        
            # Deduplicate results while preserving all fields
            results['login_pages'] = self._deduplicate_with_fields(results['login_pages'], 'url')
            results['password_reset_pages'] = self._deduplicate_with_fields(results['password_reset_pages'], 'url')
            
        except Exception as e:
            print(f"Error scanning {domain}: {str(e)}")
    
        return results

    def _deduplicate_with_fields(self, items, key_field):
        """Deduplicate while preserving all fields"""
        seen = set()
        unique_items = []
        for item in items:
            key = item.get(key_field)
            if key not in seen:
                seen.add(key)
                unique_items.append(item)
        return unique_items

    def _check_url(self, url, page_type):
        """Check if a URL is accessible and matches the page type"""
        try:
            response = self._safe_request(url)
            if response and response.status_code == 200:
                return self.is_auth_page(url, response.text)
        except:
            return False
        return False

    def _safe_request(self, url):
        """Make a safe HTTP request with random user agent and timeout"""
        try:
            headers = {'User-Agent': self.get_random_user_agent()}
            response = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
            return response
        except:
            return None

    def _classify_auth_page(self, url, html_content):
        """Classify the type of authentication page"""
        soup = BeautifulSoup(html_content, 'html.parser')
        text = soup.get_text().lower()
        
        # Check for password reset keywords
        reset_keywords = ['reset', 'forgot', 'recover']
        if any(keyword in text for keyword in reset_keywords):
            return 'reset'
        
        # Default to login page
        return 'login'

    def _check_auth_providers(self, domain, results):
        """Check for common auth provider endpoints"""
        providers = {
            'office365': [
                f"https://login.microsoftonline.com/{domain}",
                f"https://{domain}/_forms/default.aspx",
                f"https://{domain}/_windows/default.aspx"
            ],
            'gsuite': [
                f"https://accounts.google.com/ServiceLogin?service=CPanel&passive=1209600&continue=https://admin.google.com/{domain}/AdminHome",
                f"https://admin.google.com/{domain}/AdminHome"
            ],
            'okta': [
                f"https://{domain}.okta.com",
                f"https://{domain}/login/login.htm"
            ],
            'auth0': [
                f"https://{domain}.auth0.com",
                f"https://{domain}/login/callback"
            ]
        }
        
        for provider, urls in providers.items():
            for url in urls:
                if self._check_url(url, 'login'):
                    results['login_pages'].append({
                        'url': url,
                        'type': f'{provider}_login',
                        'source': 'known_provider'
                    })

class EmailUserEnumerator:
    def __init__(self):
        self.auth_scanner = AuthPageScanner()
        self.common_email_patterns = [
            r'[\w\.-]+@[\w\.-]+\.\w+',  # Standard email pattern
            r'[\w]+\[at\][\w\.-]+\[dot\]\w+',  # Obfuscated emails
            r'[\w]+\s*\(\s*at\s*\)\s*[\w\.-]+\s*\(\s*dot\s*\)\s*\w+'  # Another obfuscation style
        ]

    def find_email_patterns(self, domain: str) -> Dict:
        """Find email patterns using multiple techniques"""
        results = {
            'email_formats': [],
            'found_emails': [],
            'login_pages': [],
            'password_reset_pages': []
        }

        # Technique 1: Web scraping for email patterns
        try:
            homepage_url = f"https://{domain}"
            response = requests.get(homepage_url, timeout=10)
            
            if response.status_code == 200:
                # Find all email patterns in the page
                for pattern in self.common_email_patterns:
                    found_emails = re.findall(pattern, response.text)
                    results['found_emails'].extend([
                        {'email': email, 'type': 'scraped', 'confidence': 70}
                        for email in set(found_emails) if domain in email
                    ])
                
                # Check for common email formats
                self._analyze_email_formats(domain, response.text, results)
                
        except Exception as e:
            print(f"Web scraping error for {domain}: {e}")

        # Technique 2: Find auth pages
        auth_results = self.auth_scanner.find_auth_pages(domain)
        results['login_pages'].extend(auth_results['login_pages'])
        results['password_reset_pages'].extend(auth_results['password_reset_pages'])

        return results

    def _analyze_email_formats(self, domain, text, results):
        """Analyze text to determine common email formats"""
        # Find all emails with the target domain
        domain_emails = [email for email in re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text) 
                        if email.endswith(domain)]
        
        if domain_emails:
            # Analyze patterns
            patterns = set()
            for email in domain_emails:
                username_part = email.split('@')[0]
                if '.' in username_part:
                    patterns.add('first.last@domain.com')
                elif '_' in username_part:
                    patterns.add('first_last@domain.com')
                elif username_part.isalpha():
                    patterns.add('firstlast@domain.com')
                elif any(char.isdigit() for char in username_part):
                    patterns.add('firstlast123@domain.com')
            
            for pattern in patterns:
                results['email_formats'].append({
                    'pattern': pattern,
                    'confidence': 80,
                    'source': 'pattern_analysis'
                })

    def enumerate_from_subdomains(self, subdomains: List[Dict]) -> Dict:
        """Enumerate email and user info from subdomains"""
        results = {
            'email_analysis': {},
            'login_pages': [],
            'password_reset_pages': []
        }

        for subdomain in subdomains:
            if not subdomain.get('http_status') and not subdomain.get('https_status'):
                continue
                
            url = f"https://{subdomain['subdomain']}" if subdomain.get('https_status') else f"http://{subdomain['subdomain']}"
            
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    # Check for common login pages
                    auth_results = self.auth_scanner.find_auth_pages(subdomain['subdomain'])
                    results['login_pages'].extend(auth_results['login_pages'])
                    results['password_reset_pages'].extend(auth_results['password_reset_pages'])
                    
            except Exception as e:
                continue

        return results