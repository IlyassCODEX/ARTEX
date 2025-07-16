# AI_analyst.py
import requests
import json
from typing import Dict, List, Optional
import logging
from datetime import datetime
import time

class AIAnalyst:
    def __init__(self, groq_api_key: str = None):
        """
        Initialize the AI analyst with Groq API integration
        
        Args:
            groq_api_key: Optional Groq API key (if not provided, will use rule-based analysis only)
        """
        self.groq_api_key = "" #Add your groq_api_key here
        self.logger = logging.getLogger(__name__)
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        
        # Templates for when Groq is not available
        self.owner_template = {
            'summary': "Security assessment completed with rule-based analysis",
            'key_findings': [
                "No critical vulnerabilities detected through automated scanning",
                "Standard security headers evaluation completed",
                "Subdomain enumeration analysis performed"
            ],
            'protection_recommendations': [
                "Implement comprehensive security headers (CSP, HSTS, X-Frame-Options)",
                "Enable Web Application Firewall (WAF) protection",
                "Schedule regular automated vulnerability scans",
                "Implement proper SSL/TLS configuration"
            ],
            'immediate_actions': [
                "Review and update security configurations",
                "Monitor access logs for suspicious activity",
                "Verify SSL certificate validity"
            ],
            'risk_score': 0,
            'perspective': 'owner',
            'ai_model': 'Rule-based Analysis',
            'generated_at': datetime.now().isoformat()
        }

        self.hunter_template = {
            'summary': "Bug bounty hunting analysis completed using automated reconnaissance",
            'promising_targets': [
                {
                    'target': 'Admin interfaces',
                    'reason': 'Potential authentication bypass opportunities'
                },
                {
                    'target': 'API endpoints',
                    'reason': 'Possible injection vulnerabilities'
                }
            ],
            'attack_vectors': [
                {
                    'type': 'Web Application',
                    'description': 'Standard web application attack surface'
                },
                {
                    'type': 'Subdomain Takeover',
                    'description': 'Check for dangling DNS records'
                }
            ],
            'research_areas': [
                {
                    'technology': 'Web Server',
                    'note': 'Investigate server configuration and version'
                },
                {
                    'technology': 'Framework',
                    'note': 'Research framework-specific vulnerabilities'
                }
            ],
            'high_value_findings': [
                "Authentication bypass vulnerabilities",
                "Business logic flaws",
                "Insecure direct object references",
                "Server-side request forgery",
                "Sensitive data exposure"
            ],
            'perspective': 'hunter',
            'ai_model': 'Rule-based Analysis',
            'generated_at': datetime.now().isoformat()
        }

    def analyze_results(self, scan_results: Dict) -> Dict:
        """
        Analyze scan results and generate dual-perspective insights using AI (Groq) or rule-based fallback
        
        Args:
            scan_results: Dictionary containing all scan results
            
        Returns:
            Dictionary with both owner and hunter perspectives
        """
        try:
            self.logger.info("Starting AI analysis...")
            
            if self.groq_api_key:
                self.logger.info("Using Groq API for analysis")
                
                # Analyze owner perspective
                self.logger.info("Analyzing owner perspective...")
                owner_analysis = self._analyze_with_groq(scan_results, perspective="owner")
                
                # Add delay between API calls
                time.sleep(2)
                
                # Analyze hunter perspective
                self.logger.info("Analyzing hunter perspective...")
                hunter_analysis = self._analyze_with_groq(scan_results, perspective="hunter")
                
            else:
                self.logger.info("Using rule-based analysis")
                owner_analysis = self._rule_based_owner_analysis(scan_results)
                hunter_analysis = self._rule_based_hunter_analysis(scan_results)
            
            # Ensure proper structure for template
            owner_analysis = self._ensure_owner_structure(owner_analysis)
            hunter_analysis = self._ensure_hunter_structure(hunter_analysis)
            
            result = {
                'owner_analysis': owner_analysis,
                'hunter_analysis': hunter_analysis,
                'generated_at': datetime.now().isoformat()
            }
            
            self.logger.info("AI analysis completed successfully")
            return result
            
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return {
                'owner_analysis': self._rule_based_owner_analysis(scan_results),
                'hunter_analysis': self._rule_based_hunter_analysis(scan_results),
                'generated_at': datetime.now().isoformat()
            }

    def _analyze_with_groq(self, scan_results: Dict, perspective: str) -> Dict:
        """
        Use Groq API to analyze the results from a specific perspective
        """
        try:
            # Prepare the appropriate prompt
            prompt = self._prepare_prompt(scan_results, perspective)
            
            # Call Groq API with retry logic
            headers = {
                "Authorization": f"Bearer {self.groq_api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": "llama3-70b-8192",
                "messages": [{
                    "role": "user",
                    "content": prompt
                }],
                "temperature": 0.7,
                "max_tokens": 1500
            }
            
            # Retry logic for API calls
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    self.logger.info(f"Making Groq API call for {perspective} perspective (attempt {attempt + 1})")
                    
                    response = requests.post(
                        "https://api.groq.com/openai/v1/chat/completions",
                        headers=headers,
                        json=payload,
                        timeout=45
                    )
                    
                    self.logger.info(f"API response status: {response.status_code}")
                    
                    if response.status_code == 200:
                        ai_response = response.json()
                        content = ai_response['choices'][0]['message']['content']
                        
                        self.logger.info(f"Received AI response for {perspective}: {content[:200]}...")
                        
                        # Try to parse JSON response
                        try:
                            if content.strip().startswith('{'):
                                analysis = json.loads(content)
                                analysis['perspective'] = perspective
                                analysis['ai_model'] = 'Groq Llama3-70B'
                                return analysis
                            else:
                                # Handle non-JSON response
                                return self._parse_unstructured_response(content, perspective)
                        except json.JSONDecodeError as e:
                            self.logger.error(f"JSON decode error: {e}")
                            return self._parse_unstructured_response(content, perspective)
                    
                    else:
                        self.logger.error(f"API call failed with status {response.status_code}: {response.text}")
                        if response.status_code == 429:  # Rate limit
                            if attempt < max_retries - 1:
                                self.logger.info("Rate limited, waiting 10 seconds...")
                                time.sleep(10)
                                continue
                        
                        # For other errors, raise to try fallback
                        response.raise_for_status()
                        
                except requests.exceptions.Timeout:
                    self.logger.warning(f"API call timed out for {perspective} (attempt {attempt + 1})")
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)
                        continue
                    else:
                        raise
                        
                except requests.exceptions.RequestException as e:
                    self.logger.error(f"Request error for {perspective}: {e}")
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)
                        continue
                    else:
                        raise
                        
        except Exception as e:
            self.logger.error(f"Failed to get AI analysis for {perspective}: {e}")
            
        # Fallback to rule-based analysis
        if perspective == "owner":
            return self._rule_based_owner_analysis(scan_results)
        else:
            return self._rule_based_hunter_analysis(scan_results)

    def _prepare_prompt(self, scan_results: Dict, perspective: str) -> str:
        """
        Prepare the prompt for Groq API based on scan results and perspective
        """
        # Create a condensed version of results for the prompt
        condensed = {
            'domain': scan_results.get('domain', 'Unknown'),
            'subdomains_count': len(scan_results.get('subdomains', [])),
            'active_subdomains': len([s for s in scan_results.get('subdomains', []) 
                                   if s.get('http_status') or s.get('https_status')]),
            'vulnerabilities_found': len(scan_results.get('vulnerability_scan', [])),
            'technologies_detected': len(scan_results.get('tech_detection', {}))
        }
        
        # Get sample vulnerabilities
        sample_vulns = []
        for scan in scan_results.get('vulnerability_scan', [])[:3]:
            for vuln in scan.get('vulnerabilities', [])[:2]:
                sample_vulns.append({
                    'type': vuln.get('type', 'Unknown'),
                    'risk': vuln.get('risk', 'medium'),
                    'description': vuln.get('description', '')[:150]
                })
        
        # Get sample technologies
        sample_tech = []
        for url, tech_data in list(scan_results.get('tech_detection', {}).items())[:3]:
            for tech in tech_data.get('technologies', [])[:2]:
                sample_tech.append({
                    'name': tech.get('name', 'Unknown'),
                    'version': tech.get('version', 'Unknown')
                })
        
        if perspective == "owner":
            return f"""You are a senior cybersecurity consultant. Analyze this website security scan and provide actionable recommendations for the website owner.

Scan Summary:
- Domain: {condensed['domain']}
- Subdomains found: {condensed['subdomains_count']}
- Active subdomains: {condensed['active_subdomains']}
- Vulnerabilities detected: {condensed['vulnerabilities_found']}
- Technologies identified: {condensed['technologies_detected']}

Key Vulnerabilities Found:
{json.dumps(sample_vulns, indent=2)}

Technologies Detected:
{json.dumps(sample_tech, indent=2)}

Provide a JSON response with these exact keys:
- "summary": Brief overview of security posture
- "key_findings": Array of 3-5 critical security issues
- "protection_recommendations": Array of 3-5 specific security improvements
- "immediate_actions": Array of 3-5 urgent steps to take

Return only valid JSON, no additional text."""

        else:  # hunter perspective
            return f"""You are an experienced bug bounty hunter. Analyze this website security scan and identify the most promising attack opportunities.

Scan Summary:
- Domain: {condensed['domain']}
- Subdomains found: {condensed['subdomains_count']}
- Active subdomains: {condensed['active_subdomains']}
- Vulnerabilities detected: {condensed['vulnerabilities_found']}
- Technologies identified: {condensed['technologies_detected']}

Key Vulnerabilities Found:
{json.dumps(sample_vulns, indent=2)}

Technologies Detected:
{json.dumps(sample_tech, indent=2)}

Provide a JSON response with these exact keys:
- "summary": Brief overview of attack surface
- "promising_targets": Array of objects with "target" and "reason" keys
- "attack_vectors": Array of objects with "type" and "description" keys  
- "research_areas": Array of objects with "technology" and "note" keys
- "high_value_findings": Array of 3-5 vulnerability types to look for

Return only valid JSON, no additional text."""

    def _parse_unstructured_response(self, text: str, perspective: str) -> Dict:
        """
        Parse unstructured AI response into our format
        """
        # Try to extract JSON from the response
        try:
            start = text.find('{')
            end = text.rfind('}') + 1
            if start != -1 and end != -1:
                json_str = text[start:end]
                parsed = json.loads(json_str)
                parsed['perspective'] = perspective
                parsed['ai_model'] = 'Groq Llama3-70B'
                return parsed
        except:
            pass
        
        # Fallback to template
        if perspective == "owner":
            return self._rule_based_owner_analysis({})
        else:
            return self._rule_based_hunter_analysis({})

    def _ensure_owner_structure(self, analysis: Dict) -> Dict:
        """Ensure owner analysis has the correct structure for the template"""
        if not isinstance(analysis.get('key_findings'), list):
            analysis['key_findings'] = []
        if not isinstance(analysis.get('protection_recommendations'), list):
            analysis['protection_recommendations'] = []
        if not isinstance(analysis.get('immediate_actions'), list):
            analysis['immediate_actions'] = []
        
        # Ensure we have at least some data
        if not analysis['key_findings']:
            analysis['key_findings'] = ["No critical vulnerabilities detected in automated scan"]
        if not analysis['protection_recommendations']:
            analysis['protection_recommendations'] = ["Implement security headers", "Enable HTTPS", "Regular security audits"]
        if not analysis['immediate_actions']:
            analysis['immediate_actions'] = ["Review security configurations", "Monitor access logs"]
            
        return analysis

    def _ensure_hunter_structure(self, analysis: Dict) -> Dict:
        """Ensure hunter analysis has the correct structure for the template"""
        # Ensure promising_targets is a list of objects
        if not isinstance(analysis.get('promising_targets'), list):
            analysis['promising_targets'] = []
        
        for i, target in enumerate(analysis['promising_targets']):
            if isinstance(target, str):
                analysis['promising_targets'][i] = {
                    'target': target,
                    'reason': 'Identified during reconnaissance'
                }
            elif not isinstance(target, dict):
                analysis['promising_targets'][i] = {
                    'target': str(target),
                    'reason': 'Automated detection'
                }
        
        # Ensure attack_vectors is a list of objects
        if not isinstance(analysis.get('attack_vectors'), list):
            analysis['attack_vectors'] = []
        
        for i, vector in enumerate(analysis['attack_vectors']):
            if isinstance(vector, str):
                analysis['attack_vectors'][i] = {
                    'type': vector,
                    'description': 'Standard attack vector'
                }
            elif not isinstance(vector, dict):
                analysis['attack_vectors'][i] = {
                    'type': str(vector),
                    'description': 'Automated detection'
                }
        
        # Ensure research_areas is a list of objects
        if not isinstance(analysis.get('research_areas'), list):
            analysis['research_areas'] = []
        
        for i, area in enumerate(analysis['research_areas']):
            if isinstance(area, str):
                analysis['research_areas'][i] = {
                    'technology': area,
                    'note': 'Requires manual investigation'
                }
            elif not isinstance(area, dict):
                analysis['research_areas'][i] = {
                    'technology': str(area),
                    'note': 'Automated detection'
                }
        
        # Ensure high_value_findings is a list
        if not isinstance(analysis.get('high_value_findings'), list):
            analysis['high_value_findings'] = []
        
        # Ensure we have at least some data
        if not analysis['promising_targets']:
            analysis['promising_targets'] = [{'target': 'Main application', 'reason': 'Primary attack surface'}]
        if not analysis['attack_vectors']:
            analysis['attack_vectors'] = [{'type': 'Web Application', 'description': 'Standard web app testing'}]
        if not analysis['research_areas']:
            analysis['research_areas'] = [{'technology': 'Web Server', 'note': 'Check for misconfigurations'}]
        if not analysis['high_value_findings']:
            analysis['high_value_findings'] = ["Authentication bypass", "Injection vulnerabilities"]
            
        return analysis

    def _rule_based_owner_analysis(self, scan_results: Dict) -> Dict:
        """
        Fallback rule-based analysis for website owners
        """
        analysis = self.owner_template.copy()
        
        # Update with actual scan data if available
        if scan_results:
            # Extract vulnerabilities
            vulnerabilities = []
            for scan in scan_results.get('vulnerability_scan', []):
                for vuln in scan.get('vulnerabilities', []):
                    if vuln.get('risk') in ['critical', 'high']:
                        vulnerabilities.append(f"{vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")
            
            if vulnerabilities:
                analysis['key_findings'] = vulnerabilities[:5]
            
            # Calculate risk score
            analysis['risk_score'] = self._calculate_risk_score(scan_results)
        
        return analysis

    def _rule_based_hunter_analysis(self, scan_results: Dict) -> Dict:
        """
        Fallback rule-based analysis for bug bounty hunters
        """
        analysis = self.hunter_template.copy()
        
        # Update with actual scan data if available
        if scan_results:
            # Find interesting subdomains
            promising_targets = []
            for subdomain in scan_results.get('subdomains', [])[:5]:
                if subdomain.get('http_status') in [401, 403, 500] or subdomain.get('https_status') in [401, 403, 500]:
                    promising_targets.append({
                        'target': subdomain['subdomain'],
                        'reason': f"Interesting HTTP status: {subdomain.get('http_status') or subdomain.get('https_status')}"
                    })
            
            if promising_targets:
                analysis['promising_targets'] = promising_targets
            
            # Extract attack vectors from vulnerabilities
            attack_vectors = []
            for scan in scan_results.get('vulnerability_scan', []):
                for vuln in scan.get('vulnerabilities', []):
                    if vuln.get('risk') in ['critical', 'high']:
                        attack_vectors.append({
                            'type': vuln.get('type', 'Unknown'),
                            'description': vuln.get('description', 'No description')
                        })
            
            if attack_vectors:
                analysis['attack_vectors'] = attack_vectors[:5]
            
            # Extract research areas from tech detection
            research_areas = []
            for url, tech_data in scan_results.get('tech_detection', {}).items():
                for tech in tech_data.get('technologies', []):
                    if tech.get('version'):
                        research_areas.append({
                            'technology': f"{tech['name']} {tech['version']}",
                            'note': f"Check for known vulnerabilities in this version"
                        })
            
            if research_areas:
                analysis['research_areas'] = research_areas[:5]
        
        return analysis

    def _calculate_risk_score(self, scan_results: Dict) -> int:
        """Calculate a risk score (0-100) based on scan results"""
        score = 0
        
        # Critical vulnerabilities
        crit_vulns = sum(1 for scan in scan_results.get('vulnerability_scan', [])
                     for vuln in scan.get('vulnerabilities', [])
                     if vuln.get('risk') == 'critical')
        score += crit_vulns * 20
        
        # High vulnerabilities
        high_vulns = sum(1 for scan in scan_results.get('vulnerability_scan', [])
                    for vuln in scan.get('vulnerabilities', [])
                    if vuln.get('risk') == 'high')
        score += high_vulns * 10
        
        # Subdomain exposure
        subdomains = len(scan_results.get('subdomains', []))
        if subdomains > 100:
            score += 30
        elif subdomains > 50:
            score += 20
        elif subdomains > 20:
            score += 10
        
        return min(100, score)
