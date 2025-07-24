from urllib.parse import urlparse
import requests
from Wappalyzer import Wappalyzer, WebPage
import warnings
import random
from typing import Dict, Optional, List

warnings.filterwarnings('ignore', category=UserWarning)

class TechnologyDetector:
    def __init__(self):
        # Initialize Wappalyzer
        self.wappalyzer = Wappalyzer.latest()
        
        # User agents for requests
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
        ]

    def _get_random_user_agent(self) -> str:
        """Get a random user agent from the list"""
        return random.choice(self.user_agents)

    def _make_request(self, url: str) -> Optional[requests.Response]:
        """Make a HTTP request"""
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

    def detect_technologies(self, url: str) -> Dict:
        """Detect technologies using Wappalyzer"""
        results = {
            'technologies': [],
            'cloud': None,
            'cdn': None,
            'exposed_files': [],
            'secrets': [],
            'endpoints': []
        }

        try:
            response = self._make_request(url)
            if not response:
                return results

            # Create WebPage object for Wappalyzer
            webpage = WebPage.new_from_response(response)

            # Analyze with Wappalyzer - returns a set of technology names
            detected_tech = self.wappalyzer.analyze(webpage)
            
            # Get categories for each technology
            categories_map = self._get_technology_categories()
            
            # Format the results
            results['technologies'] = self._format_wappalyzer_results(detected_tech, categories_map)
            
            # Check for cloud and CDN providers
            results['cloud'] = self._detect_cloud_provider(detected_tech)
            results['cdn'] = self._detect_cdn_provider(detected_tech)

        except Exception as e:
            print(f"Error detecting technologies: {e}")

        return results

    def _get_technology_categories(self) -> Dict[str, List[str]]:
        """Get technology categories from Wappalyzer"""
        categories_map = {}
        for tech_name, tech_data in self.wappalyzer.technologies.items():
            categories_map[tech_name] = tech_data.get('categories', ['Unknown'])
        return categories_map

    def _format_wappalyzer_results(self, detected_tech: set, categories_map: dict) -> list:
        """Format Wappalyzer results into our standard format"""
        formatted = []
        
        for tech_name in detected_tech:
            formatted.append({
                'name': tech_name,
                'category': categories_map.get(tech_name, ['Unknown'])[0],
                'confidence': 100,  # Wappalyzer doesn't provide confidence scores
                'version': None,    # Version detection would need additional implementation
                'sources': ['wappalyzer']
            })
        
        return formatted

    def _detect_cloud_provider(self, detected_tech: set) -> Optional[Dict]:
        """Detect cloud hosting provider from Wappalyzer results"""
        cloud_providers = {
            'Amazon Web Services': 'AWS',
            'Google Cloud Platform': 'GCP',
            'Microsoft Azure': 'Azure',
            'DigitalOcean': 'DigitalOcean',
            'Heroku': 'Heroku',
            'Cloudflare': 'Cloudflare',
            'Linode': 'Linode'
        }
        
        for tech_name in detected_tech:
            provider = cloud_providers.get(tech_name)
            if provider:
                return {
                    'provider': provider,
                    'service': tech_name,
                    'confidence': 100,
                    'sources': ['wappalyzer']
                }
        
        return None

    def _detect_cdn_provider(self, detected_tech: set) -> Optional[Dict]:
        """Detect CDN provider from Wappalyzer results"""
        cdn_providers = {
            'Cloudflare': 'Cloudflare',
            'Akamai': 'Akamai',
            'Fastly': 'Fastly',
            'Amazon CloudFront': 'CloudFront',
            'Microsoft Azure CDN': 'Azure CDN',
            'Google Cloud CDN': 'Google CDN'
        }
        
        for tech_name in detected_tech:
            provider = cdn_providers.get(tech_name)
            if provider:
                return {
                    'provider': provider,
                    'confidence': 100,
                    'sources': ['wappalyzer']
                }
        
        return None
