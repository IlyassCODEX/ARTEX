from flask import Flask, render_template, request, jsonify, session
import uuid
import threading
import time
from datetime import datetime
from modules.subdomains import SubdomainEnumerator
from modules.real_ip_discovery import RealIPDiscovery
from modules.port_scanner import PortScanner
from modules.dns_scan import DNSScanner
from modules.ssl_scanner import SSLScanner
from modules.tech_detector import TechnologyDetector
from modules.enumeration import EmailUserEnumerator
from modules.bypass_403 import Bypass403Scanner
from modules.db_file_hunter import DBFileHunter
from modules.vhost_fuzzer import VHostFuzzer
from modules.dir_bruteforce import DirectoryBruteforcer
from modules.web_vuln_scanner import WebVulnScanner
from modules.shodan_probe import ShodanProbe
from modules.reverse_whois import ReverseWhois
from modules.cache_poisoning_probe import CachePoisoningProbe
from modules.websocket_scanner import WebSocketScanner
from modules.ai_db_exfil_agent import AIDNExfilAgent
from modules.http_smuggling_probe import HTTPSmugglingProbe
from modules.ssti_scanner import SSTIScanner
from modules.network_range_mapper import NetworkRangeMapper
from modules.jwt_analyzer import JWTAnalyzer
from modules.smtp_enum import SMTPEnumerator
from modules.snmp_scan import SNMPScanner
from modules.FastAnalyst import FastSecurityAnalyst
from modules.AI_analyst import AIAnalyst
from modules.AI_header_analyzer import AIHeaderAnalyzer
from modules.AI_subdomain_takeover_analyzer import AISubdomainTakeoverAnalyzer
from modules.AI_vuln_prioritizer import AIVulnPrioritizer
from modules.AI_attack_path_planner import AIAttackPathPlanner
from modules.AI_osint_correlator import AIOSINTCorrelator
from modules.AI_payload_generator import AIPayloadGenerator
from modules.AI_report_narrator import AIReportNarrator
from modules.AI_api_fuzzer import AIAPIFuzzer
from modules.AI_cross_target_correlator import AICrossTargetCorrelator
from utils.reporting import ReportGenerator
from utils.helpers import validate_domain, sanitize_domain
from utils.header_injector import run_header_injection
from utils.waf_fingerprinter import run_waf_fingerprint
from utils.js_secret_extractor import run_js_secret_extraction
from utils.credential_sprayer import run_credential_spray
from utils.cors_auditor import run_cors_audit
from utils.ai_mouse_agent import run_ai_mouse_agent
from utils.redirect_tracer import run_redirect_trace
from utils.ai_recon_orchestrator import run_recon_orchestrator
from utils.ai_payload_mutator import run_payload_mutator
from utils.ai_vuln_scorer import run_vuln_scorer
from utils.ai_session_manager import run_session_manager, SessionCommand
from utils.ai_decision_engine import run_decision_engine
from utils.ai_exfil_planner import run_exfil_planner
from utils.ai_lateral_mover import run_lateral_mover
from utils.ai_persistence_agent import run_persistence_agent
from core.exploit_chain import ExploitChain
from core.auth_bypass import AuthBypass
from core.cve_matcher import CveMatcher
from core.session_hijack import SessionHijack
from core.xxe_injector import XxeInjector
from core.lfi_rfi import LfiRfi
from core.ssrf_probe import SsrfProbe
from core.vuln_scanner import VulnScanner
from core.ratelimit_bypass import RateLimitBypass
from core.cors_tester import CorsTester
from core.batch_manager import batch_manager, BatchManager
from core.evidence_manager import evidence_manager
from modules.AI_batch_orchestrator import AIBatchOrchestrator
from modules.AI_remediation_engine import AIRemediationEngine
from modules.AI_waf_fingerprinter import AIWAFFingerprinter
import threading
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    if isinstance(value, str):
        # If it's already a string, parse it to datetime first
        value = datetime.fromisoformat(value)
    return value.strftime(format)

# Add Groq API key configuration (or load from environment)
GROQ_API_KEY = os.getenv('GROQ_API_KEY')

_orchestrator = AIBatchOrchestrator(groq_api_key=GROQ_API_KEY)

scan_results = {}
scan_status = {}

@app.context_processor
def inject_now():
    return {'now': datetime.now}

@app.route('/')
def index():
    return render_template('scan.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    domain = data.get('domain', '').strip()
    options = data.get('options', {
        'subdomains': True,
        'ports': True,
        'port_scan_choice': 'all_subdomains', # New option for port scan
        'dns': True,
        'ssl': True,
        'header_injection': True,
        'waf_fingerprint': True,
        'js_secret': True,
        'credential_spray': True,
        'cors_audit': True,
        'tech': True,
        'email': True,
        'security': True,
        'ai': True,
        'ai_mouse_agent': False,
        'redirect_trace': True,
        'orchestrator': False,
        'payload_mutator': False,
        'vuln_score': True,
        'session_manager': False,
        'session_commands': [
            SessionCommand.ELEVATE_PRIVILEGE.value,
            SessionCommand.MAINTAIN_ACCESS.value,
            SessionCommand.ESCALATE_HEADERS.value,
            SessionCommand.PIVOT_ENDPOINT.value,
        ],
        'decision_engine': False,
        'engine_mode': 'balanced',   # aggressive / stealth / balanced / fast / thorough
        'engine_max_cycles': 12,
        'exfil_plan': False,
        'oob_domain': 'OOB_SERVER_PLACEHOLDER.com',
        'exfil_noise_budget': 0.6,
        'exfil_stealth': False,
        'lateral_move': False,
        'lateral_fast_mode': False,
        'lateral_delay': 0.15,
        'persistence': False,
        'c2_host': '',
        'c2_port': 4444,
        'persistence_stealth': True,
        'orchestrator_mode': 'full_recon',
        'intensity': 'normal',
        'web_vuln': True,
        'dir_bruteforce': True,
        'vhost_fuzzer': True,
        'db_file_hunter': True,
        'bypass_403': True,
        'shodan_probe': True,
        'reverse_whois': True,
        'cache_poisoning': True,
        'websocket_scanner': True,
        'ai_db_exfil': True,
        'http_smuggling': True,
        'ssti_scanner': True,
        'network_mapper': True,
        'jwt_analyzer': True,
        'smtp_enum': True,
        'snmp_scan': True,
    })
    
    if not validate_domain(domain):
        return jsonify({'error': 'Invalid domain format'}), 400
    
    domain = sanitize_domain(domain)
    scan_id = str(uuid.uuid4())
    
    # Initialize scan status
    scan_status[scan_id] = {
        'status': 'running',
        'progress': 0,
        'current_task': 'Initializing scan...',
        'start_time': datetime.now(),
        'domain': domain,
        'options': options
    }
    
    # Initialize results structure
    scan_results[scan_id] = {
        'domain': domain,
        'subdomains': [],
        'port_scan': [],
        'dns_records': {},
        'ssl_scan': {},
        'header_injection': {},
        'waf_fingerprint': {},
        'js_secrets': {},
        'credential_spray': {},
        'cors_audit': {},
        'tech_detection': {},
        'email_enumeration': {},
        'security_analysis': {},
        'ai_analysis': {},
        'web_vuln': {},
        'dir_bruteforce': {},
        'vhost_fuzzer': {},
        'db_file_hunter': {},
        'bypass_403': {},
        'redirect_trace': {},
        'orchestrator': {},
        'payload_mutator': {},
        'vuln_score': {},
        'session_manager': {},
        'decision_engine': {},
        'exfil_plan': {},
        'lateral_move': {},
        'shodan_probe': {},
        'reverse_whois': {},
        'cache_poisoning': {},
        'websocket_scanner': {},
        'ai_db_exfil': {},
        'http_smuggling': {},
        'ssti_scanner': {},
        'network_mapper': {},
        'jwt_analyzer': {},
        'smtp_enum': {},
        'snmp_scan': {},
        'scan_id': scan_id,
        'timestamp': datetime.now().isoformat(),
        'options': options,
    }
    
    # Start background scan
    thread = threading.Thread(target=run_scan, args=(scan_id, domain, options))
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id})


def run_scan(scan_id, domain, options):
    try:
            # Create application context for the background thread
            total_steps = sum(1 for opt in options.values() if isinstance(opt, bool) and opt)
            completed_steps = 0
        
            # Configure scan intensity
            max_subdomains = {
                'light': 10,
                'normal': 30,
                'aggressive': 100
            }.get(options.get('intensity', 'normal'), 30)

            subdomains = [] # Initialize subdomains list
            if options.get('subdomains', True):
                # Update status
                scan_status[scan_id]['current_task'] = 'Enumerating subdomains...'
                scan_status[scan_id]['progress'] = 10
            
                # Run subdomain enumeration
                subdomain_enum = SubdomainEnumerator()
                subdomains = subdomain_enum.enumerate(domain)
                scan_results[scan_id]['subdomains'] = subdomains
                takeover_analyzer = AISubdomainTakeoverAnalyzer(groq_api_key=GROQ_API_KEY)
                scan_results[scan_id]['takeover_analysis'] = takeover_analyzer.analyze(
                    domain, subdomains=subdomains, max_targets=50
                )
                scan_status[scan_id]['progress'] = 20

            # Run email enumeration if selected
            email_results = {} # Initialize email_results
            if options.get('email', True):
                # Run email enumeration
                scan_status[scan_id]['current_task'] = 'Enumerating email patterns...'
                email_enum = EmailUserEnumerator()
                email_results = email_enum.find_email_patterns(domain)
                scan_results[scan_id]['email_enumeration'] = email_results
                scan_status[scan_id]['progress'] = 30

            # Run port scanning on active subdomains
            if options.get('ports', True):
                scan_status[scan_id]['current_task'] = 'Scanning ports...'
                
                # Determine targets based on port_scan_choice
                port_scan_choice = options.get('port_scan_choice', 'all_subdomains')
                targets_for_port_scan = []

                if port_scan_choice == 'critical_only':
                    scan_status[scan_id]['current_task'] = 'Identifying critical subdomains for port scan...'
                    security_analyst = FastSecurityAnalyst()
                    # Perform a preliminary analysis to get critical subdomains
                    analysis_data = security_analyst._prepare_analysis_data(domain, subdomains)
                    critical_subdomains_data = analysis_data['categories']['critical']
                    
                    for category_list in critical_subdomains_data.values():
                        for s in category_list:
                            targets_for_port_scan.append(s['subdomain'])
                    
                    scan_status[scan_id]['current_task'] = f'Scanning ports on {len(targets_for_port_scan)} critical subdomains...'
                    print(f"Critical subdomains for port scan: {targets_for_port_scan}")

                else: # Default to 'all_subdomains'
                    active_subdomains = [s for s in subdomains if s.get('http_status') or s.get('https_status')]
                    targets_for_port_scan = [s['subdomain'] for s in active_subdomains]
                    scan_status[scan_id]['current_task'] = f'Scanning ports on {len(targets_for_port_scan)} active subdomains...'
                    print(f"All active subdomains for port scan: {targets_for_port_scan}")
            
                port_scanner = PortScanner()
                port_results = port_scanner.batch_scan(targets_for_port_scan, ports='21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017')
                print(f"Port scan raw results: {port_results}")
                scan_results[scan_id]['port_scan'] = [r for r in port_results if r is not None]
                scan_status[scan_id]['progress'] = 40
            
            # Run DNS scanning
            if options.get('dns', True):
                scan_status[scan_id]['current_task'] = 'Scanning DNS records...'
            
                dns_scanner = DNSScanner(domain)
                # Use aggressive mode if intensity is set to aggressive
                aggressive = options.get('intensity', 'normal') == 'aggressive'
                scan_results[scan_id]['dns_records'] = dns_scanner.scan(aggressive=aggressive)
                scan_status[scan_id]['progress'] = 50
                
            if options.get('reverse_whois', True):
                scan_status[scan_id]['current_task'] = 'Running reverse WHOIS pivot...'
                try:
                    rw = ReverseWhois(
                        domain=domain,
                        whoisxml_api_key=os.getenv('WHOISXML_API_KEY'),
                        sectrails_api_key=os.getenv('SECURITYTRAILS_API_KEY'),
                    )
                    scan_results[scan_id]['reverse_whois'] = rw.scan()
                except Exception as e:
                    print(f"[reverse_whois] error: {e}")
                    scan_results[scan_id]['reverse_whois'] = {'error': str(e)}
                    
            if options.get('websocket_scanner', True):
                scan_status[scan_id]['current_task'] = 'Scanning WebSocket endpoints...'
                try:
                    ws = WebSocketScanner(
                        target_url=f"https://{domain}",
                        rate_delay=0.2,
                        max_workers=10,
                    )
                    scan_results[scan_id]['websocket_scanner'] = ws.scan()
                except Exception as e:
                    print(f"[websocket_scanner] error: {e}")
                    scan_results[scan_id]['websocket_scanner'] = {'error': str(e)}


            if options.get('real_ip', True):
                scan_status[scan_id]['current_task'] = 'Discovering real IPs...'
                real_ip_discovery = RealIPDiscovery()
    
                # Pass existing data instead of doing new scans
                subdomains_data = scan_results[scan_id].get('subdomains', [])
                dns_data = scan_results[scan_id].get('dns_records', {})
    
                # Run discovery and get the filtered IPs
                real_ips = real_ip_discovery.discover_real_ips(domain, subdomains_data, dns_data)
    
                # Prepare results for JSON serialization
                ip_results = []
                for ip in real_ips:
                    ip_results.append({
                        'ip': ip,
                        'score': 10,  # Default score
                        'responds': True,  # Default status
                        'methods': ['multiple']  # Default methods
                    })
    
                scan_results[scan_id]['real_ip'] = {
                    'origin_ips': ip_results,
                    # Fix: Access CDN ranges through the ip_utils attribute
                    'techniques_used': list(real_ip_discovery.ip_utils.cdn_ranges.keys())
                }
                correlator = AIOSINTCorrelator(
                    groq_api_key=GROQ_API_KEY,
                    shodan_key=os.getenv('SHODAN_API_KEY'),
                    vt_key=os.getenv('VIRUSTOTAL_API_KEY'),
                    hunter_key=os.getenv('HUNTER_API_KEY'),
                    sectrails_key=os.getenv('SECURITYTRAILS_API_KEY'),
                    github_token=os.getenv('GITHUB_TOKEN'),
                )
                scan_results[scan_id]['osint_correlation'] = correlator.correlate(
                    domain=domain,
                    scan_results=scan_results[scan_id],
                    deep=options.get('intensity') == 'aggressive',
                )
                scan_status[scan_id]['progress'] = 60  # Updated progress value
                
            if options.get('shodan_probe', True):
                scan_status[scan_id]['current_task'] = 'Running Shodan deep probe...'
                try:
                    real_ip_data = scan_results[scan_id].get('real_ip', {})
                    known_ips = {
                        entry['ip']
                        for entry in real_ip_data.get('origin_ips', [])
                        if entry.get('ip')
                    }
                    probe = ShodanProbe(
                        domain=domain,
                        api_key=os.getenv('SHODAN_API_KEY'),
                        known_ips=known_ips,
                        target_url=f"https://{domain}",
                    )
                    scan_results[scan_id]['shodan_probe'] = probe.scan()
                except Exception as e:
                    print(f"[shodan_probe] error: {e}")
                    scan_results[scan_id]['shodan_probe'] = {'error': str(e)}
                    
            if options.get('network_range_mapper', True):
                scan_status[scan_id]['current_task'] = 'Mapping network ranges and ASNs...'
                try:
                    real_ip_data = scan_results[scan_id].get('real_ip', {})
                    seed_ips = {
                        entry['ip']
                        for entry in real_ip_data.get('origin_ips', [])
                        if entry.get('ip')
                    }
                    # Also pull IPs from port scan results
                    for ps in scan_results[scan_id].get('port_scan', []):
                        if ps.get('ip'):
                            seed_ips.add(ps['ip'])
                    mapper = NetworkRangeMapper(
                        domain=domain,
                        seed_ips=seed_ips,
                        shodan_api_key=os.getenv('SHODAN_API_KEY'),
                        enumerate_hosts=True,
                        fetch_history=True,
                    )
                    scan_results[scan_id]['network_range_mapper'] = mapper.scan()
                except Exception as e:
                    print(f"[network_range_mapper] error: {e}")
                    scan_results[scan_id]['network_range_mapper'] = {'error': str(e)}
                    
            if options.get('jwt_analyzer', True):
                scan_status[scan_id]['current_task'] = 'Analysing JWT tokens...'
                try:
                    # Feed known tokens from web_vuln results
                    web_vuln = scan_results[scan_id].get('web_vuln', {})
                    known_tokens = []
                    for f in web_vuln.get('findings', []):
                        if f.get('attack_type') == 'jwt' and f.get('evidence'):
                            import re as _re
                            m = _re.search(
                                r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
                                f['evidence'],
                            )
                            if m:
                                known_tokens.append(m.group(0))
                    jwt = JWTAnalyzer(
                        target_url=f"https://{domain}",
                        known_tokens=known_tokens,
                        rate_delay=0.2,
                        max_workers=15,
                    )
                    scan_results[scan_id]['jwt_analyzer'] = jwt.scan()
                except Exception as e:
                    print(f"[jwt_analyzer] error: {e}")
                    scan_results[scan_id]['jwt_analyzer'] = {'error': str(e)}
                    
            if options.get('smtp_enum', True):
                scan_status[scan_id]['current_task'] = 'Enumerating SMTP users...'
                try:
                    smtp = SMTPEnumerator(
                        domain=domain,
                        rate_delay=0.1,
                        max_workers=15,
                    )
                    scan_results[scan_id]['smtp_enum'] = smtp.scan()
                except Exception as e:
                    print(f"[smtp_enum] error: {e}")
                    scan_results[scan_id]['smtp_enum'] = {'error': str(e)}
                    
            if options.get('snmp_scan', True):
                scan_status[scan_id]['current_task'] = 'Scanning SNMP services...'
                try:
                    snmp = SNMPScanner(
                        domain=domain,
                        timeout=2.0,
                        max_workers=25,
                        walk_enabled=True,
                    )
                    scan_results[scan_id]['snmp_scan'] = snmp.scan()
                except Exception as e:
                    print(f"[snmp_scan] error: {e}")
                    scan_results[scan_id]['snmp_scan'] = {'error': str(e)}

            # In the run_scan function, update the SSL scan section:
            if options.get('ssl', True):
                scan_status[scan_id]['current_task'] = 'Scanning SSL/TLS configuration...'
                ssl_scanner = SSLScanner()
    
                # Scan both the main domain and active subdomains
                ssl_results = {
                    'main_domain': ssl_scanner.scan(domain)
                    }
    
                # Scan active subdomains that support HTTPS
                active_https_subdomains = [s for s in subdomains if s.get('https_status')]
                for subdomain in active_https_subdomains[:15]:  # Limit to 5 for performance
                    try:
                        ssl_results[subdomain['subdomain']] = ssl_scanner.scan(subdomain['subdomain'])
                    except Exception as e:
                        print(f"SSL scan failed for {subdomain['subdomain']}: {e}")
                        ssl_results[subdomain['subdomain']] = {'error': str(e)}
    
                scan_results[scan_id]['ssl_scan'] = ssl_results
                scan_status[scan_id]['progress'] = 70
                
                cvm = CveMatcher()
                scan_results[scan_id]['cve_matches'] = cvm.run(
                    domain=domain,
                    scan_results=scan_results[scan_id],
                )
                
            if options.get('http_smuggling', True):
                scan_status[scan_id]['current_task'] = 'Probing HTTP request smuggling...'
                try:
                    smuggle = HTTPSmugglingProbe(
                        target_url=f"https://{domain}",
                        rate_delay=0.5,
                        max_workers=6,
                    )
                    scan_results[scan_id]['http_smuggling'] = smuggle.scan()
                except Exception as e:
                    print(f"[http_smuggling] error: {e}")
                    scan_results[scan_id]['http_smuggling'] = {'error': str(e)}

            # Run technology detection
            if options.get('tech', True):
                active_subdomains = [s for s in subdomains if s.get('http_status') or s.get('https_status')]
                scan_status[scan_id]['current_task'] = 'Detecting technologies...'
                tech_detector = TechnologyDetector()
                tech_results = {}
            
                for subdomain in active_subdomains[:15]:  # Limit to 5 for demo
                    url = f"https://{subdomain['subdomain']}" if subdomain.get('https_status') else f"http://{subdomain['subdomain']}"
                    try:
                        tech_data = tech_detector.detect_technologies(url)
                        tech_results[url] = tech_data
                    except Exception as e:
                        print(f"Tech detection failed for {url}: {e}")
                        continue
                    
                scan_results[scan_id]['tech_detection'] = tech_results
                scan_status[scan_id]['progress'] = 80
                
                generator = AIPayloadGenerator(groq_api_key=GROQ_API_KEY)
                scan_results[scan_id]['payload_analysis'] = generator.generate(
                    domain=domain,
                    scan_results=scan_results[scan_id],
                )
                scan_status[scan_id]['progress'] = 88
                
                waf_fp = AIWAFFingerprinter(groq_api_key=GROQ_API_KEY)
                scan_results[scan_id]['waf_fingerprint'] = waf_fp.fingerprint(
                    domain=domain,
                    scan_results=scan_results[scan_id],
                )
                scan_status[scan_id]['progress'] = 72
                
                fuzzer = AIAPIFuzzer(groq_api_key=GROQ_API_KEY)
                scan_results[scan_id]['api_fuzz_results'] = fuzzer.fuzz(
                    domain=domain,
                    scan_results=scan_results[scan_id],
                )
                scan_status[scan_id]['progress'] = 90
                
                lr = LfiRfi()
                scan_results[scan_id]['lfi_rfi'] = lr.run(domain=domain, scan_results=scan_results[scan_id])
                
                sp = SsrfProbe()
                scan_results[scan_id]['ssrf_probe'] = sp.run(domain=domain, scan_results=scan_results[scan_id])
                
                vs = VulnScanner()
                scan_results[scan_id]['vuln_scan'] = vs.run(
                    domain=domain,
                    scan_results=scan_results[scan_id],
                )
                
                rl = RateLimitBypass()
                scan_results[scan_id]['ratelimit_bypass'] = rl.run(
                    domain=domain,
                    scan_results=scan_results[scan_id],
                )
                
                xi = XxeInjector()
                scan_results[scan_id]['xxe_injection'] = xi.run(
                    domain=domain,
                    scan_results=scan_results[scan_id],
                )
                
                ab = AuthBypass()
                scan_results[scan_id]['auth_bypass'] = ab.run(
                    domain=domain,
                    scan_results=scan_results[scan_id],
                )
                
                chain = ExploitChain()
                scan_results[scan_id]['exploit_chain'] = chain.run(
                    domain=domain,
                    scan_results=scan_results[scan_id],
                )
                
                ct = CorsTester()
                scan_results[scan_id]['cors_tester'] = ct.run(
                    domain=domain,
                    scan_results=scan_results[scan_id],
                )
                
            if options.get('headers', True):
                scan_status[scan_id]['current_task'] = 'Analyzing security headers...'
                header_analyzer = AIHeaderAnalyzer(groq_api_key=GROQ_API_KEY)
                scan_results[scan_id]['header_analysis'] = header_analyzer.analyze(
                    domain, subdomains=subdomains, max_targets=10
                )
                scan_status[scan_id]['progress'] = 85
                
            sh = SessionHijack()
            scan_results[scan_id]['session_hijack'] = sh.run(
                domain=domain,
                scan_results=scan_results[scan_id],
            )
            
            target_base_url = f"https://{domain}"
            
            if options.get('waf_fingerprint'):
                scan_status[scan_id]['current_task'] = 'WAF Fingerprinting...'
                try:
                    scan_results[scan_id]['waf_fingerprint'] = run_waf_fingerprint(target_base_url)
                except Exception as e:
                    scan_results[scan_id]['waf_fingerprint'] = {'error': str(e)}
                    
            if opions.get('header_injection'):
                scan_status[scan_id]['current_task'] = 'Header Injection Probing...'
                try:
                    scan_results[scan_id]['header_injection'] = run_header_injection(target_base_url)
                except Exception as e:
                    scan_results[scan_id]['header_injection'] = {'error': str(e)}
                    
            if options.get('cors_audit'):
                scan_status[scan_id]['current_task'] = 'CORS Auditing...'
                try:
                    scan_results[scan_id]['cors_audit'] = run_cors_audit(target_base_url)
                except Exception as e:
                    scan_results[scan_id]['cors_audit'] = {'error': str(e)}
                    
            if options.get('js_secrets'):
                scan_status[scan_id]['current_task'] = 'JS Secret Extraction...'
                try:
                    scan_results[scan_id]['js_secrets'] = run_js_secret_extraction(target_base_url)
                except Exception as e:
                    scan_results[scan_id]['js_secrets'] = {'error': str(e)}
                    
            if options.get('credential_spray'):
                scan_status[scan_id]['current_task'] = 'Credential Spraying...'
                try:
                    login_url = options.get('credential_spray_url', target_base_url + '/login')
                    scan_results[scan_id]['credential_spray'] = run_credential_spray(
                        login_url,
                        delay=options.get('spray_delay', 2.0),
                        stop_on_success=True,
                    )
                except Exception as e:
                    scan_results[scan_id]['credential_spray'] = {'error': str(e)}
                    
            if options.get('session_manager'):
                scan_status[scan_id]['current_task'] = 'AI Session Management...'
                creds_to_use = options.get('credentials', [])
                spray_result = scan_results[scan_id].get('credential_spray', {})
                spray_hits = spray_result.get('successful_logins', [])
                if spray_hits:
                    creds_to_use = [{'username': h['username'], 'password': h['password']} for h in spray_hits[:5]]
                try:
                    scan_results[scan_id]['session_manager'] = run_session_manager(
                        target_url=target_base_url,
                        credentials=creds_to_use,
                        commands=options.get('session_commands'),
                        delay=options.get('session_delay', 0.3),
                        proxy=options.get('proxy'),
                    )
                except Exception as e:
                    scan_results[scan_id]['session_manager'] = {'error': str(e)}
                    
            if options.get('ai_mouse_agent'):
                scan_status[scan_id]['current_task'] = 'AI Mouse Agent...'
                try:
                    creds = options.get('ai_mouse_credentials', [("admin", "admin")])
                    scan_results[scan_id]['ai_mouse_agent'] = run_ai_mouse_agent(
                        target_url=options.get('ai_mouse_url', target_base_url + '/login'),
                        credentials=creds,
                        max_attempts=options.get('ai_mouse_max_attempts', 5),
                        headless=options.get('ai_mouse_headless', True),
                        capture_screenshots=options.get('ai_mouse_screenshots', True),
                    )
                except Exception as e:
                    scan_results[scan_id]['ai_mouse_agent'] = {'error': str(e)}
                    
            if options.get('redirect_trace'):
                scan_status[scan_id]['current_task'] = 'Redirect Tracing...'
                try:
                    scan_results[scan_id]['redirect_trace'] = run_redirect_trace(target_base_url)
                except Exception as e:
                    scan_results[scan_id]['redirect_trace'] = {'error': str(e)}
                    
            if options.get('orchestrator'):
                scan_status[scan_id]['current_task'] = 'AI Recon Orchestrator...'
                
                def _orch_status(msg: str):
                    scan_status[scan_id]['current_task'] = f'Orchestrator: {msg}'
                    
                try:
                    scan_results[scan_id]['orchestrator'] = run_recon_orchestrator(
                        target_url=target_base_url,
                        instruction_mode=options.get('orchestrator_mode', 'full_recon'),
                        credentials=options.get('orchestrator_credentials'),
                        credential_spray_url=options.get('credential_spray_url'),
                        mouse_agent_url=options.get('ai_mouse_url'),
                        status_callback=_orch_status,
                    )
                except Exception as e:
                    scan_results[scan_id]['orchestrator'] = {'error': str(e)}
                    
            if options.get('payload_mutator'):
                scan_status[scan_id]['current_task'] = 'AI Payload Mutator...'
                try:
                    waf_vendor = scan_results[scan_id].get('waf_fingerprint', {}).get('vendor', '')
                    scan_results[scan_id]['payload_mutator'] = run_payload_mutator(
                        target_url=target_base_url,
                        param=options.get('mutator_param', 'q'),
                        category=options.get('mutator_category', 'xss'),
                        evolution_target=options.get('mutator_target', 'waf_bypass'),
                        generations=options.get('mutator_generations', 5),
                        population_size=options.get('mutator_population', 10),
                        waf_vendor=waf_vendor,
                    )
                except Exception as e:
                    scan_results[scan_id]['payload_mutator'] = {'error': str(e)}
                    
            if options.get('ssti_scanner', True):
                scan_status[scan_id]['current_task'] = 'Scanning for SSTI vulnerabilities...'
                try:
                    # Feed known params from web_vuln results if available
                    web_vuln_data = scan_results[scan_id].get('web_vuln', {})
                    known_params: Dict[str, List[str]] = {}
                    for finding in web_vuln_data.get('findings', []):
                        if finding.get('parameter'):
                            url = finding.get('url', f"https://{domain}")
                            known_params.setdefault(url, [])
                            if finding['parameter'] not in known_params[url]:
                                known_params[url].append(finding['parameter'])
                    ssti = SSTIScanner(
                        target_url=f"https://{domain}",
                        known_params=known_params,
                        rate_delay=0.2,
                        max_workers=12,
                    )
                    scan_results[scan_id]['ssti_scanner'] = ssti.scan()
                except Exception as e:
                    print(f"[ssti_scanner] error: {e}")
                    scan_results[scan_id]['ssti_scanner'] = {'error': str(e)}
                    
            if options.get('vuln_score'):
                scan_status[scan_id]['current_task'] = 'AI Vuln Scoring...'
                try:
                    scan_results[scan_id]['vuln_score'] = run_vuln_scorer(
                        scan_results=scan_results[scan_id],
                        target_url=target_base_url,
                    )
                except Exception as e:
                    scan_results[scan_id]['vuln_score'] = {'error': str(e)}
                    
            if options.get('decision_engine'):
                scan_status[scan_id]['current_task'] = 'AI Decision Engine...'
                try:
                    scan_results[scan_id]['decision_engine'] = run_decision_engine(
                        target_url=target_base_url,
                        scan_results=scan_results[scan_id],
                        mode=options.get('engine_mode', 'balanced'),
                        max_cycles=options.get('engine_max_cycles', 12),
                        max_actions_per_cycle=4,
                        cycle_delay=0.2,
                    )
                except Exception as e:
                    scan_results[scan_id]['decision_engine'] = {'error': str(e)}
                    
            if options.get('lateral_move'):
                scan_status[scan_id]['current_task'] = 'AI Lateral Movement...'
                try:
                    scan_results[scan_id]['lateral_move'] = run_lateral_mover(
                        target_url=target_base_url,
                        scan_results=scan_results[scan_id],
                        delay=options.get('lateral_delay', 0.15),
                        proxy=options.get('proxy'),
                        fast_mode=options.get('lateral_fast_mode', False),
                    )
                except Exception as e:
                    scan_results[scan_id]['lateral_move'] = {'error': str(e)}
                    
            if options.get('persistence') and options.get('c2_host'):
                scan_status[scan_id]['current_task'] = 'AI Persistence Planning...'
                try:
                    scan_results[scan_id]['persistence'] = run_persistence_agent(
                        target_url=target_base_url,
                        scan_results=scan_results[scan_id],
                        c2_host=options.get('c2_host', 'attacker.example.com'),
                        c2_port=int(options.get('c2_port', 4444)),
                        stealth_mode=options.get('persistence_stealth', True),
                    )
                except Exception as e:
                    scan_results[scan_id]['persistence'] = {'error': str(e)}
                    
            if options.get('exfil_plan'):
                scan_status[scan_id]['current_task'] = 'AI Exfil Planning...'
                try:
                    scan_results[scan_id]['exfil_plan'] = run_exfil_planner(
                        target_url=target_base_url,
                        scan_results=scan_results[scan_id],
                        oob_domain=options.get('oob_domain', 'OOB_SERVER_PLACEHOLDER.com'),
                        noise_budget=options.get('exfil_noise_budget', 0.6),
                        stealth_mode=options.get('exfil_stealth', False),
                    )
                except Exception as e:
                    scan_results[scan_id]['exfil_plan'] = {'error': str(e)}
                    
            # ── Offensive modules ──────────────────────────────────────────
            if options.get('web_vuln', True):
                scan_status[scan_id]['current_task'] = 'Running web vulnerability scan...'
                try:
                    web_scanner = WebVulnScanner(
                        target_url=f"https://{domain}",
                    )
                    scan_results[scan_id]['web_vuln'] = web_scanner.scan(domain)
                except Exception as e:
                    print(f"[web_vuln] error: {e}")
                    scan_results[scan_id]['web_vuln'] = {'error': str(e)}
                    
            if options.get('dir_bruteforce', True):
                scan_status[scan_id]['current_task'] = 'Brute-forcing directories...'
                try:
                    brute = DirectoryBruteforcer(
                        target_url=f"https://{domain}",
                        recursive=False,
                        max_workers=20,
                    )
                    scan_results[scan_id]['dir_bruteforce'] = brute.scan()
                except Exception as e:
                    print(f"[dir_bruteforce] error: {e}")
                    scan_results[scan_id]['dir_bruteforce'] = {'error': str(e)}
                    
            if options.get('vhost_fuzzer', True):
                scan_status[scan_id]['current_task'] = 'Fuzzing virtual hosts...'
                try:
                    # Reuse real IP if already discovered by real_ip module
                    real_ip_data = scan_results[scan_id].get('real_ip', {})
                    origin_ips   = real_ip_data.get('origin_ips', [])
                    target_ip    = origin_ips[0]['ip'] if origin_ips else None
                    fuzzer = VHostFuzzer(
                        domain=domain,
                        target_ip=target_ip,
                        port=443,
                        scheme='https',
                    )
                    scan_results[scan_id]['vhost_fuzzer'] = fuzzer.scan()
                except Exception as e:
                    print(f"[vhost_fuzzer] error: {e}")
                    scan_results[scan_id]['vhost_fuzzer'] = {'error': str(e)}
                    
            if options.get('db_file_hunter', True):
                scan_status[scan_id]['current_task'] = 'Hunting exposed database files...'
                try:
                    hunter = DBFileHunter(
                        target_url=f"https://{domain}",
                        enable_mutations=True,
                        enable_dir_variants=True,
                        max_workers=16,
                    )
                    scan_results[scan_id]['db_file_hunter'] = hunter.scan()
                except Exception as e:
                    print(f"[db_file_hunter] error: {e}")
                    scan_results[scan_id]['db_file_hunter'] = {'error': str(e)}
                    
            if options.get('bypass_403', True):
                scan_status[scan_id]['current_task'] = 'Attempting 403 bypass...'
                try:
                    # Feed known 403 URLs from dir_bruteforce results if available
                    brute_results = scan_results[scan_id].get('dir_bruteforce', {})
                    known_403 = [
                        r['url'] for r in brute_results.get('results', [])
                        if r.get('status') == 403
                    ]
                    bypass = Bypass403Scanner(
                        target_url=f"https://{domain}",
                        known_403_urls=known_403,
                        max_workers=20,
                    )
                    scan_results[scan_id]['bypass_403'] = bypass.scan()
                except Exception as e:
                    print(f"[bypass_403] error: {e}")
                    scan_results[scan_id]['bypass_403'] = {'error': str(e)}
                    
            if options.get('ai_db_exfil', True):
                scan_status[scan_id]['current_task'] = 'Running AI database exfiltration assessment...'
                try:
                    agent = AIDBExfilAgent(
                        target_url=f"https://{domain}",
                        groq_api_key=os.getenv('GROQ_API_KEY'),
                    )
                    scan_results[scan_id]['ai_db_exfil'] = agent.scan()
                except Exception as e:
                    print(f"[ai_db_exfil] error: {e}")
                    scan_results[scan_id]['ai_db_exfil'] = {'error': str(e)}
                    
            if options.get('cache_poisoning', True):
                scan_status[scan_id]['current_task'] = 'Probing cache poisoning vectors...'
                try:
                    probe = CachePoisoningProbe(
                        target_url=f"https://{domain}",
                        rate_delay=0.3,
                        max_workers=10,
                    )
                    scan_results[scan_id]['cache_poisoning'] = probe.scan()
                except Exception as e:
                    print(f"[cache_poisoning] error: {e}")
                    scan_results[scan_id]['cache_poisoning'] = {'error': str(e)}
            
            # Run security analysis
            scan_status[scan_id]['current_task'] = 'Running security analysis...'
            security_analyst = FastSecurityAnalyst()
            security_analysis = security_analyst.analyze_subdomains(domain, subdomains)
            
            # Add email enumeration results to security analysis
            if options.get('email', True):
                security_analysis['email_analysis'] = email_results
                scan_results[scan_id]['security_analysis'] = security_analysis
                
            prioritizer = AIVulnPrioritizer(groq_api_key=GROQ_API_KEY)
            scan_results[scan_id]['vuln_prioritization'] = prioritizer.prioritize(
                domain=domain,
                scan_results=scan_results[scan_id],
            )
            scan_status[scan_id]['progress'] = 92
            
            planner = AIAttackPathPlanner(groq_api_key=GROQ_API_KEY)
            scan_results[scan_id]['attack_path_graph'] = planner.plan(
                domain=domain,
                scan_results=scan_results[scan_id],
            )
            scan_status[scan_id]['progress'] = 95
            
            engine = AIRemediationEngine(groq_api_key=GROQ_API_KEY)
            scan_results[scan_id]['remediation_plan'] = engine.build(
                domain=domain,
                scan_results=scan_results[scan_id],
            )
            scan_status[scan_id]['progress'] = 97
            
            narrator = AIReportNarrator(groq_api_key=GROQ_API_KEY)
            scan_results[scan_id]['narrative_report'] = narrator.narrate(
                domain=domain,
                scan_results=scan_results[scan_id],
                batch_id=scan_id,
            )
            scan_status[scan_id]['progress'] = 98
            
            # Run AI analysis
            scan_status[scan_id]['current_task'] = 'Generating AI insights...'
            ai_analyst = AIAnalyst(GROQ_API_KEY)
            ai_analysis = ai_analyst.analyze_results(scan_results[scan_id])
            scan_results[scan_id]['ai_analysis'] = ai_analysis
            
            scan_status[scan_id]['progress'] = 100
            scan_status[scan_id]['status'] = 'completed'
            scan_status[scan_id]['current_task'] = 'Scan completed'
            scan_status[scan_id]['end_time'] = datetime.now()

            duration = scan_status[scan_id]['end_time'] - scan_status[scan_id]['start_time']
            total_seconds = int(duration.total_seconds())
            hours, remainder = divmod(total_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            scan_status[scan_id]['duration'] = f"{hours}h {minutes}m {seconds}s"
            
    except Exception as e:
        scan_status[scan_id]['status'] = 'error'
        scan_status[scan_id]['error'] = str(e)
        scan_status[scan_id]['progress'] = 0
        print(f"Scan error for {scan_id}: {e}")


@app.route('/scan_status/<scan_id>')
def get_scan_status(scan_id):
    if scan_id not in scan_status:
        return jsonify({'error': 'Scan not found'}), 404
    
    status = scan_status[scan_id].copy()
    
    # Convert datetime objects to strings
    if 'start_time' in status:
        status['start_time'] = status['start_time'].isoformat()
    if 'end_time' in status:
        status['end_time'] = status['end_time'].isoformat()
    
    return jsonify(status)

@app.route('/results/<scan_id>')
def get_results(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    # Add duration to results if available
    if scan_id in scan_status and 'duration' in scan_status[scan_id]:
        scan_results[scan_id]['duration'] = scan_status[scan_id]['duration']
    
    return render_template('results.html', 
                         results=scan_results[scan_id], 
                         scan_id=scan_id,
                        scan_status=scan_status)

@app.route('/api/results/<scan_id>')
def api_results(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/export/<scan_id>')
def export_results(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    format_type = request.args.get('format', 'json')
    
    report_gen = ReportGenerator()
    
    if format_type == 'pdf':
        pdf_content = report_gen.generate_pdf(scan_results[scan_id])
        return pdf_content, 200, {
            'Content-Type': 'application/pdf',
            'Content-Disposition': f'attachment; filename=security_report_{scan_id}.pdf'
        }
    else:
        json_content = report_gen.generate_json(scan_results[scan_id])
        return json_content, 200, {
            'Content-Type': 'application/json',
            'Content-Disposition': f'attachment; filename=security_report_{scan_id}.json'
        }
        
@app.route('/batch/upload', methods=['POST'])
def batch_upload():
    """Parse uploaded TXT file, return preview without starting scan."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
        
    f = request.files['file']
    if not f.filename.endwith('.txt'):
        return jsonify({'error': 'Only .txt files accepted'}), 400
        
    context = f.read().decode('utf-8', errors='replace')
    report  = batch_manager.parse_txt_file(content)
    
    # Store raw content in session for /batch/start
    import tempfile, os
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.txt', mode='w')
    tmp.write(content)
    tmp.close()
    
    return jsonify({
        'filename':      f.filename,
        'valid_count':   len(report['valid_urls']),
        'invalid_count': len(report['invalid_urls']),
        'duplicate_count': len(report['duplicates']),
        'total_lines':   report['total_lines'],
        'preview':       report['valid_urls'][:20],
        'errors':        report['parse_errors'][:10],
        'tmp_path':      tmp.name,
    })
    
    
@app.route('/batch/start', methods=['POST'])
def batch_start():
    """Create and start a batch assessment."""
    data     = request.get_json()
    tmp_path = data.get('tmp_path', '')
    options  = data.get('options', {})
    filename = data.get('filename', 'targets.txt')

    # Concurrency / timeout options
    concurrency   = int(data.get('concurrency', 3))
    target_timeout = int(data.get('target_timeout', 600))
    allow_private  = bool(data.get('allow_private', False))

    # Read temp file
    try:
        import os
        with open(tmp_path, 'r') as fh:
            content = fh.read()
        os.unlink(tmp_path)
    except Exception as e:
        return jsonify({'error': f'Could not read temp file: {e}'}), 400

    # Create batch manager with requested settings
    bm = BatchManager(
        concurrency    = concurrency,
        target_timeout = target_timeout,
        allow_private  = allow_private,
    )
    # Persist in global registry too
    batch_manager._batches.update(bm._batches)

    batch_op, parse_report = bm.create_batch(content, filename, options)
    if not batch_op:
        return jsonify({
            'error':        'No valid in-scope targets found',
            'parse_report': parse_report,
        }), 400

    # Merge into global batch_manager
    batch_manager._batches[batch_op.batch_id] = batch_op

    # Start background thread
    worker = _orchestrator.get_worker()
    thread = threading.Thread(
        target  = bm.run_batch,
        args    = (batch_op.batch_id, worker),
        daemon  = True,
        name    = f"batch_{batch_op.batch_id[:8]}",
    )
    thread.start()

    return jsonify({
        'batch_id':     batch_op.batch_id,
        'total_targets': batch_op.total,
        'parse_report':  parse_report,
    })


@app.route('/batch/status/<batch_id>')
def batch_status(batch_id):
    status = batch_manager.get_batch_status(batch_id)
    if not status:
        return jsonify({'error': 'Batch not found'}), 404
    return jsonify(status)


@app.route('/batch/stop/<batch_id>', methods=['POST'])
def batch_stop(batch_id):
    ok = batch_manager.stop_batch(batch_id)
    return jsonify({'stopped': ok})


@app.route('/batch/execution_log/<batch_id>')
def batch_execution_log(batch_id):
    limit = int(request.args.get('limit', 100))
    log   = batch_manager.get_execution_log(batch_id, limit)
    return jsonify({'log': log, 'count': len(log)})


@app.route('/batch/target/<batch_id>/<target_id>')
def batch_target_detail(batch_id, target_id):
    target = batch_manager.get_target(batch_id, target_id)
    if not target:
        return jsonify({'error': 'Target not found'}), 404
    result = target.to_dict()
    result['scan_results'] = target.scan_results
    return jsonify(result)


@app.route('/batch/list')
def batch_list():
    return jsonify({'batches': batch_manager.list_batches()})


@app.route('/batch/export/<batch_id>')
def batch_export(batch_id):
    batch = batch_manager.get_batch(batch_id)
    if not batch:
        return jsonify({'error': 'Batch not found'}), 404

    fmt = request.args.get('format', 'json')

    if fmt == 'json':
        payload = json.dumps(batch.to_dict(), indent=2, default=str)
        return payload, 200, {
            'Content-Type': 'application/json',
            'Content-Disposition': f'attachment; filename=batch_{batch_id[:8]}.json',
        }

    if fmt == 'csv':
        import csv, io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(['url', 'status', 'severity', 'findings', 'technologies', 'duration'])
        for t in batch.targets:
            w.writerow([
                t.url, t.status, t.highest_severity or '',
                t.findings_count, '|'.join(t.technologies[:5]), t.duration or '',
            ])
        return buf.getvalue(), 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': f'attachment; filename=batch_{batch_id[:8]}.csv',
        }

    if fmt == 'txt':
        lines = [f"ARTEX Batch Report — {batch.batch_id}", "=" * 60]
        lines.append(f"File: {batch.filename} | Status: {batch.status}")
        lines.append(f"Total: {batch.total} | Done: {batch.completed} | Failed: {batch.failed}")
        lines.append(f"Duration: {batch.duration or 'in progress'}\n")
        for t in batch.targets:
            lines.append(f"  [{t.status.upper():10}] {t.url}")
            lines.append(f"    Severity: {t.highest_severity or 'n/a'} | "
                         f"Findings: {t.findings_count} | "
                         f"Duration: {t.duration or '...'}")
            if t.error:
                lines.append(f"    Error: {t.error}")
        return "\n".join(lines), 200, {
            'Content-Type': 'text/plain',
            'Content-Disposition': f'attachment; filename=batch_{batch_id[:8]}.txt',
        }

    return jsonify({'error': 'Unknown format — use json, csv, or txt'}), 400

        
@app.route('/history')
def history():
    return render_template('history.html')
    
@app.route('/history_data')
def history_data():
    scans = []
    for sid, status in scan_status.items():
        entry = dict(status)
        if 'start_time' in entry:
            entry['start_time'] = entry['start_time'].isoformat()
        if 'end_time' in entry:
            entry['end_time'] = entry['end_time'].isoformat()
        entry['scan_id'] = sid
        scans.append(entry)
    scans.sort(key=lambda x: x.get('start_time',''), reverse=True)
    return jsonify({'scans': scans})
    
@app.route('/loading/<scan_id>')
def loading(scan_id):
    domain = scan_status.get(scan_id, {}).get('domain', '')
    return render_template('loading.html', scan_id=scan_id, domain=domain)
    
@app.route('/export_ui/<scan_id>')
def export_ui(scan_id):
    if scan_id not in scan_results:
        abort(404)
    r = scan_results[scan_id]
    if scan_id in scan_status and 'duration' in scan_status[scan_id]:
        r['duration'] = scan_status[scan_id]['duration']
    return render_template('export.html', results=r, scan_id=scan_id)
    
@app.route('/export_narrative/<scan_id>')
def export_narrative(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Not found'}), 404
    fmt = request.args.get('format', 'pdf')
    domain = scan_results[scan_id].get('domain', 'unknown')
    narrator = AIReportNarrator(groq_api_key=GROQ_API_KEY)
    if fmt == 'pdf':
        pdf = narrator.generate_pdf(domain, scan_results[scan_id], scan_id)
        return pdf, 200, {
            'Content-Type': 'application/pdf',
            'Content-Disposition': f'attachment; filename=narrative_{scan_id[:8]}.pdf',
        }
    if fmt == 'txt':
        txt = narrator.generate_txt(domain, scan_results[scan_id], scan_id)
        return txt, 200, {
            'Content-Type': 'text/plain',
            'Content-Disposition': f'attachment; filename=narrative_{scan_id[:8]}.txt',
        }
    return narrator.generate_json(domain, scan_results[scan_id], scan_id), 200, {
        'Content-Type': 'application/json',
        'Content-Disposition': f'attachment; filename=narrative_{scan_id[:8]}.json',
    }
    
@app.route('/evidence/<batch_id>')
def evidence_list(batch_id):
    limit  = int(request.args.get('limit', 200))
    offset = int(request.args.get('offset', 0))
    sev    = request.args.get('severity')
    verdict = request.args.get('verdict')
    recs   = evidence_manager.query(
        batch_id=batch_id, severity=sev,
        verdict=verdict, limit=limit, offset=offset,
    )
    return jsonify({
        'records': [r.to_dict(include_raw=False) for r in recs],
        'count':   len(recs),
        'stats':   evidence_manager.stats(batch_id),
        'chain':   evidence_manager.verify_chain(batch_id),
    })
    
@app.route('/evidence/<batch_id>/<evidence_id>')
def evidence_detail(batch_id, evidence_id):
    rec = evidence_manager.get(evidence_id)
    if not rec or rec.batch_id != batch_id:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(rec.to_dict(include_raw=True))

@app.route('/evidence/export/<batch_id>')
def evidence_export(batch_id):
    fmt = request.args.get('format', 'json')
    if fmt == 'csv':
        return evidence_manager.export_csv(batch_id=batch_id), 200, {
            'Content-Type':        'text/csv',
            'Content-Disposition': f'attachment; filename=evidence_{batch_id[:8]}.csv',
        }
    if fmt == 'txt':
        return evidence_manager.export_txt(batch_id=batch_id), 200, {
            'Content-Type':        'text/plain',
            'Content-Disposition': f'attachment; filename=evidence_{batch_id[:8]}.txt',
        }
    return evidence_manager.export_json(batch_id=batch_id), 200, {
        'Content-Type':        'application/json',
        'Content-Disposition': f'attachment; filename=evidence_{batch_id[:8]}.json',
    }

@app.route('/evidence/chain/verify/<batch_id>')
def evidence_chain_verify(batch_id):
    return jsonify(evidence_manager.verify_chain(batch_id))
    
@app.route('/batch/correlate/<batch_id>', methods=['POST'])
def batch_correlate(batch_id):
    batch = batch_manager.get_batch(batch_id)
    if not batch:
        return jsonify({'error': 'Batch not found'}), 404
    correlator = AICrossTargetCorrelator(groq_api_key=GROQ_API_KEY)
    result = correlator.correlate_batch(batch)
    return jsonify(result)
    
@app.route('/about')
def about():
    return render_template('about.html')
    
@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error_code=404), 404
    
@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error_code=500), 500

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', error_code=403), 403

@app.errorhandler(429)
def too_many(e):
    return render_template('error.html', error_code=429, error_message=str(e)), 429

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'analysis_type': 'Comprehensive Security Analysis'
    })

@app.route('/api/capabilities')
def get_capabilities():
    return jsonify({
        'analysis_type': 'Comprehensive Security Analysis',
        'features': [
            'Subdomain enumeration',
            'Port scanning',
            'Technology detection',
            'Email/user enumeration',
            'Security risk assessment'
        ],
        'modules': [
            'SubdomainEnumerator',
            'PortScanner',
            'TechnologyDetector',
            'EmailUserEnumerator',
            'FastSecurityAnalyst'
        ]
    })

if __name__ == '__main__':
    print("🌐 Server: http://127.0.0.1:5000")
    print("-" * 50)
    
    app.run(debug=True, host='127.0.0.1', port=5000)