# helpers.py
import re
from urllib.parse import urlparse
import socket
import json
from datetime import datetime
import ipaddress

def validate_domain(domain):
    """Validate if the provided string is a valid domain"""
    if not domain:
        return False
    
    # Remove protocol if present
    if domain.startswith(('http://', 'https://')):
        domain = urlparse(domain).netloc
    
    # Basic domain validation regex (more comprehensive than before)
    domain_pattern = re.compile(
        r'^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}|localhost)$'
    )
    
    if not domain_pattern.match(domain):
        return False
    
    # Check length
    if len(domain) > 253:
        return False
    
    # Check each label (part between dots)
    labels = domain.split('.')
    for label in labels:
        if len(label) > 63:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False
    
    return True

def sanitize_domain(domain):
    """Sanitize and normalize domain input"""
    if not domain:
        return ""
    
    # Remove protocol if present
    if domain.startswith(('http://', 'https://')):
        domain = urlparse(domain).netloc
    
    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    
    # Remove path/query if present
    if '/' in domain:
        domain = domain.split('/')[0]
    
    # Convert to lowercase and strip whitespace
    domain = domain.lower().strip()
    
    # Remove trailing dot
    domain = domain.rstrip('.')
    
    return domain

def is_ip_address(address):
    """Check if the given string is an IPv4 or IPv6 address"""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def format_timestamp(timestamp, format_str='%Y-%m-%d %H:%M:%S'):
    """Format timestamp for display with flexible format"""
    if isinstance(timestamp, (int, float)):
        return datetime.fromtimestamp(timestamp).strftime(format_str)
    elif isinstance(timestamp, str):
        try:
            # Handle various timestamp formats
            if timestamp.endswith('Z'):
                timestamp = timestamp[:-1] + '+00:00'
            dt = datetime.fromisoformat(timestamp)
            return dt.strftime(format_str)
        except ValueError:
            return timestamp
    elif isinstance(timestamp, datetime):
        return timestamp.strftime(format_str)
    return str(timestamp)

def get_status_color(status_code):
    """Get color class for HTTP status codes with more granularity"""
    if not status_code:
        return 'secondary'
    
    try:
        status_code = int(status_code)
    except (ValueError, TypeError):
        return 'secondary'
    
    if 100 <= status_code < 200:
        return 'info'
    elif 200 <= status_code < 300:
        return 'success'
    elif 300 <= status_code < 400:
        return 'primary'
    elif 400 <= status_code < 500:
        if status_code == 401:
            return 'warning'
        elif status_code == 403:
            return 'danger'
        elif status_code == 404:
            return 'secondary'
        return 'danger'
    elif 500 <= status_code < 600:
        return 'dark'
    return 'secondary'

def get_risk_color(risk_level):
    """Get color class for risk levels with more options"""
    risk_colors = {
        'low': 'success',
        'medium': 'warning', 
        'high': 'danger',
        'critical': 'dark',
        'unknown': 'secondary',
        'info': 'info',
        'severe': 'danger',
        'elevated': 'warning'
    }
    return risk_colors.get(risk_level.lower(), 'secondary')

def truncate_text(text, max_length=50, ellipsis='...'):
    """Truncate text to specified length with customizable ellipsis"""
    if not text:
        return ""
    
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(ellipsis)] + ellipsis

def safe_json_loads(json_str, default=None):
    """Safely load JSON string with better error handling"""
    if not json_str:
        return default or {}
    
    try:
        if isinstance(json_str, (dict, list)):
            return json_str
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError, ValueError) as e:
        return default or {}

def format_file_size(size_bytes, precision=1):
    """Format file size in human readable format with configurable precision"""
    if not isinstance(size_bytes, (int, float)):
        return "0B"
    
    if size_bytes == 0:
        return "0B"
    
    size_names = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    
    while size_bytes >= 1024 and i < len(size_names)-1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.{precision}f}{size_names[i]}"

def extract_domain_from_url(url):
    """Extract domain from URL with better error handling"""
    if not url:
        return ""
    
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc
        # Handle cases where URL might be just a domain
        if not parsed.scheme and not parsed.path.startswith('/'):
            return parsed.path.split('/')[0]
        return url
    except Exception:
        return url

def is_subdomain_of(subdomain, domain):
    """Check if subdomain belongs to the main domain with improved logic"""
    if not subdomain or not domain:
        return False
    
    subdomain = subdomain.lower().strip('.')
    domain = domain.lower().strip('.')
    
    if subdomain == domain:
        return True
    
    # Handle wildcard subdomains
    if subdomain.startswith('*.'):
        subdomain = subdomain[2:]
    
    return subdomain.endswith('.' + domain)

def categorize_subdomain(subdomain):
    """Categorize subdomain based on its name with more categories"""
    if not subdomain:
        return 'other'
    
    subdomain = subdomain.lower()
    
    categories = {
        'admin': ['admin', 'administrator', 'manage', 'management', 'control', 'panel', 'cpanel', 'whm', 'plesk'],
        'development': ['dev', 'development', 'test', 'testing', 'staging', 'stage', 'beta', 'alpha', 'demo', 'sandbox'],
        'api': ['api', 'rest', 'graphql', 'service', 'services', 'ws', 'webservice', 'endpoint', 'gateway'],
        'mail': ['mail', 'smtp', 'pop', 'imap', 'webmail', 'email', 'mx', 'exchange', 'owa'],
        'database': ['db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'phpmyadmin', 'adminer', 'dba'],
        'cdn': ['cdn', 'static', 'assets', 'media', 'img', 'images', 'js', 'css', 'files', 'content'],
        'security': ['vpn', 'ssh', 'ssl', 'secure', 'security', 'auth', 'oauth', 'sso', 'login', 'authz'],
        'monitoring': ['monitor', 'monitoring', 'metrics', 'logs', 'analytics', 'stats', 'grafana', 'kibana', 'prometheus'],
        'backup': ['backup', 'bak', 'archive', 'dump', 'backup1', 'backup2', 'snapshot'],
        'internal': ['internal', 'intranet', 'corp', 'office', 'local', 'private', 'staff'],
        'legacy': ['old', 'legacy', 'deprecated', 'archive', 'historical']
    }
    
    for category, keywords in categories.items():
        if any(keyword in subdomain for keyword in keywords):
            return category
    
    return 'other'

def get_category_icon(category):
    """Get icon for subdomain category with more options"""
    icons = {
        'admin': '🔐',
        'development': '🔧', 
        'api': '🔌',
        'mail': '📧',
        'database': '🗄️',
        'cdn': '🌐',
        'security': '🛡️',
        'monitoring': '📊',
        'backup': '💾',
        'internal': '🏢',
        'legacy': '🕰️',
        'other': '🔍'
    }
    return icons.get(category.lower(), '🔍')

def calculate_scan_duration(start_time, end_time=None):
    """Calculate scan duration with improved formatting"""
    if not start_time:
        return "Unknown"
    
    try:
        if isinstance(start_time, str):
            if start_time.endswith('Z'):
                start_time = start_time[:-1] + '+00:00'
            start_time = datetime.fromisoformat(start_time)
        
        if end_time is None:
            end_time = datetime.now()
        elif isinstance(end_time, str):
            if end_time.endswith('Z'):
                end_time = end_time[:-1] + '+00:00'
            end_time = datetime.fromisoformat(end_time)
        
        duration = end_time - start_time
        seconds = duration.total_seconds()
        
        if seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            remaining_seconds = int(seconds % 60)
            return f"{minutes}m {remaining_seconds}s"
        else:
            hours = int(seconds / 3600)
            remaining_minutes = int((seconds % 3600) / 60)
            return f"{hours}h {remaining_minutes}m"
    except Exception:
        return "Unknown"

def is_public_ip(ip_address):
    """Check if an IP address is public/routable"""
    try:
        ip = ipaddress.ip_address(ip_address)
        return not ip.is_private
    except ValueError:
        return False