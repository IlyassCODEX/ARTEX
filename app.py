from flask import Flask, render_template, request, jsonify, session
import uuid
import threading
import time
from datetime import datetime
from modules.subdomains import SubdomainEnumerator
from modules.port_scanner import PortScanner
from modules.tech_detector import TechnologyDetector
from modules.enumeration import EmailUserEnumerator
from modules.FastAnalyst import FastSecurityAnalyst
from modules.AI_analyst import AIAnalyst
from utils.reporting import ReportGenerator
from utils.helpers import validate_domain, sanitize_domain
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
        'tech': True,
        'email': True,
        'security': True,
        'ai': True,
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
        'tech_detection': {},
        'email_enumeration': {},
        'security_analysis': {},
        'ai_analysis': {},
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

            if options.get('subdomains', True):
                # Update status
                scan_status[scan_id]['current_task'] = 'Enumerating subdomains...'
                scan_status[scan_id]['progress'] = 10
            
                # Run subdomain enumeration
                subdomain_enum = SubdomainEnumerator()
                subdomains = subdomain_enum.enumerate(domain)
                scan_results[scan_id]['subdomains'] = subdomains
                scan_status[scan_id]['progress'] = 20
            
            # Run email enumeration if selected
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
                active_subdomains = [s for s in subdomains if s.get('http_status') or s.get('https_status')]
                print(f"Active subdomains: {active_subdomains}")
                targets = [s['subdomain'] for s in active_subdomains]  # Removed the [:5] limit
            
                port_scanner = PortScanner()
                port_results = port_scanner.batch_scan(targets, ports='21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017')  # Scan full range
                print(f"Port scan raw results: {port_results}")  # Debug outputscan_results[scan_id]['port_scan'] = [r for r in port_results if r]  # Filter None results
                scan_results[scan_id]['port_scan'] = [r for r in port_results if r is not None]
                scan_status[scan_id]['progress'] = 50
            
            # Run technology detection
            if options.get('tech', True):
                active_subdomains = [s for s in subdomains if s.get('http_status') or s.get('https_status')]
                scan_status[scan_id]['current_task'] = 'Detecting technologies...'
                tech_detector = TechnologyDetector()
                tech_results = {}
            
                for subdomain in active_subdomains[:5]:  # Limit to 5 for demo
                    url = f"https://{subdomain['subdomain']}" if subdomain.get('https_status') else f"http://{subdomain['subdomain']}"
                    try:
                        tech_data = tech_detector.detect_technologies(url)
                        tech_results[url] = tech_data
                    except Exception as e:
                        print(f"Tech detection failed for {url}: {e}")
                        continue
                    
                scan_results[scan_id]['tech_detection'] = tech_results
                scan_status[scan_id]['progress'] = 70
            
            # Run security analysis
            scan_status[scan_id]['current_task'] = 'Running security analysis...'
            security_analyst = FastSecurityAnalyst()
            security_analysis = security_analyst.analyze_subdomains(domain, subdomains)
            
            # Add email enumeration results to security analysis
            if options.get('email', True):
                security_analysis['email_analysis'] = email_results
                scan_results[scan_id]['security_analysis'] = security_analysis
            
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
            scan_status[scan_id]['duration'] = str(duration)
            
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