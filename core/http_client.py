# core/http_client.py
import requests
import time
import random
from typing import Optional, Dict, Any
from urllib.parse import urlparse, urljoin

class HTTPClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = 5
        self.last_request_time = 0
        self.request_delay = 1.0
        
    def _rate_limit(self):
        """Enforce rate limiting between requests"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.request_delay:
            time.sleep(self.request_delay - elapsed)
        self.last_request_time = time.time()
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a HTTP GET request with rate limiting"""
        self._rate_limit()
        try:
            return self.session.get(url, timeout=self.timeout, **kwargs)
        except requests.RequestException:
            return None
    
    def make_absolute(self, base_url: str, relative_url: str) -> str:
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
