import requests
from typing import Dict, List


class TechImport:
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
