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
from modules.db_file_hunter import DBFileHunter
from modules.vhost_fuzzer import VHostFuzzer
from modules.dir_bruteforce import DirectoryBruteforcer
from modules.web_vuln_scanner import WebVulnScanner
from modules.FastAnalyst import FastSecurityAnalyst # Import FastSecurityAnalyst
from modules.AI_analyst import AIAnalyst
from modules.AI_header_analyzer import AIHeaderAnalyzer
from modules.AI_subdomain_takeover_analyzer import AISubdomainTakeoverAnalyzer
from modules.AI_vuln_prioritizer import AIVulnPrioritizer
from modules.AI_attack_path_planner import AIAttackPathPlanner
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
from modules.AI_osint_correlator import AIOSINTCorrelator
from modules.AI_payload_generator import AIPayloadGenerator
from core.exploit_chain import ExploitChain
from core.auth_bypass import AuthBypass
from core.cve_matcher import CveMatcher
from core.session_hijack import SessionHijack
from core.xxe_injector import XxeInjector
from core.lfi_rfi import LfiRfi
from core.ssrf_probe import SsrfProbe
from core.vuln_scanner import VulnScanner
from core.ratelimit_bypass import RateLimitBypass
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
        'orchestrator_mode': 'full_recon',
        'intensity': 'normal'
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
        'redirect_trace': {},
        'orchestrator': {},
        'scan_id': scan_id,
        'timestamp': datetime.now().isoformat(),
        'options': options
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
