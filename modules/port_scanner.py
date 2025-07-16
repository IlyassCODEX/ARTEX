# Fixed port_scanner.py
import nmap
import time
import socket
from concurrent.futures import ThreadPoolExecutor

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.risky_ports = {
            22: ('high', 'SSH', 'Brute force, weak credentials'),
            21: ('high', 'FTP', 'Anonymous auth, data leaks'),
            3389: ('high', 'RDP', 'BlueKeep, brute force'),
            445: ('critical', 'SMB', 'EternalBlue, ransomware'),
            6379: ('high', 'Redis', 'Unauthenticated access'),
            27017: ('high', 'MongoDB', 'No auth by default'),
            9200: ('medium', 'Elasticsearch', 'Data exposure'),
            5984: ('medium', 'CouchDB', 'Misconfigurations'),
            1433: ('high', 'MSSQL', 'Brute force, injection'),
            3306: ('medium', 'MySQL', 'Weak credentials'),
            5432: ('medium', 'PostgreSQL', 'Injection attacks'),
            8080: ('medium', 'HTTP-Alt', 'Web app vulnerabilities')
        }
        self.common_web_ports = [80, 443, 8080, 8443, 8000, 8888]

    def is_valid_target(self, target):
        """Check if target is valid for scanning"""
        try:
            # Remove http/https prefixes
            clean_target = target.replace('http://', '').replace('https://', '')
            clean_target = clean_target.split('/')[0]  # Remove path
            
            # Try to resolve the domain
            socket.gethostbyname(clean_target)
            return True
        except Exception:
            return False

    def scan_target(self, target, ports='1-1000', vuln_scan=False):
        """Scan a single target with specified ports"""
        # Clean the target
        clean_target = target.replace('http://', '').replace('https://', '')
        clean_target = clean_target.split('/')[0]  # Remove path
        
        if not self.is_valid_target(clean_target):
            print(f"Invalid target: {target}")
            return None

        # Always use fallback method for more reliable results
        print(f"Scanning {clean_target} on ports {ports}...")
        
        # Try nmap first, but always fall back to socket scanning
        nmap_result = None
        try:
            # Use basic TCP scan that doesn't require root
            scan_args = '-sT --open --host-timeout 3s --max-rtt-timeout 1s -T4'  # TCP connect scan with timeout
            if vuln_scan:
                scan_args += ' --script=banner'  # Basic banner grabbing
                
            self.nm.scan(hosts=clean_target, ports=ports, arguments=scan_args)
            nmap_result = self._parse_results(clean_target, vuln_scan)
        except Exception as e:
            print(f"Nmap scan failed for {clean_target}: {str(e)}")
        
        # If nmap failed or returned no results, use socket scanning
        if not nmap_result:
            print(f"Falling back to socket scan for {clean_target}")
            return self._basic_port_check(clean_target, ports)
        
        return nmap_result


    def _basic_port_check(self, target, ports):
        """Fallback method using socket connections with threading"""
        print(f"Starting socket-based port scan for {target}")
    
        # Parse ports string
        if '-' in ports:
            start, end = map(int, ports.split('-'))
            port_list = range(start, min(end + 1, 51))  # Limit to 50 ports max
        else:
            port_list = [int(p) for p in ports.split(',') if p.strip()]
    
        open_ports = []
    
        # Use threading for socket checks
        with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_port = {
                executor.submit(self._check_port, target, port): port 
                for port in port_list
            }
        
        for future in future_to_port:
                port = future_to_port[future]
                try:
                    if future.result(timeout=3):  # 3 second timeout per port
                        print(f"Port {port} is open on {target}")
                        open_ports.append({
                            'port': port,
                            'protocol': 'tcp',
                            'state': 'open',
                            'service': self._guess_service(port),
                            'version': '',
                            'risk': self._get_port_risk(port)
                        })
                except Exception as e:
                    continue
    
        print(f"Found {len(open_ports)} open ports on {target}")
    
        if open_ports:
            return {
                'target': target,
                'ports': open_ports,
                'services': [p['service'] for p in open_ports],
                'risky_ports': [p for p in open_ports if p['risk']['level'] in ['high', 'critical']],
                'vulnerabilities': [],
                'os_guess': 'Unknown',
                'scan_time': time.time()
            }
    
        # Return empty result instead of None to indicate scan completed but no ports found
        return {
                'target': target,
                'ports': [],
                'services': [],
                'risky_ports': [],
                'vulnerabilities': [],
                'os_guess': 'Unknown',
                'scan_time': time.time()
        }

    def _check_port(self, host, port, timeout=1):
        """Check if a port is open using socket with shorter timeout"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)  # Reduced to 1 second
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _guess_service(self, port):
        """Guess service based on port number"""
        service_map = {
            80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp',
            25: 'smtp', 53: 'dns', 110: 'pop3', 143: 'imap',
            993: 'imaps', 995: 'pop3s', 3389: 'rdp', 445: 'smb',
            8080: 'http-alt', 8443: 'https-alt'
        }
        return service_map.get(port, 'unknown')

    def _parse_results(self, target, vuln_scan=False):
        """Parse nmap scan results into structured data"""
        if target not in self.nm.all_hosts():
            return None

        host_data = {
            'target': target,
            'ports': [],
            'services': [],
            'risky_ports': [],
            'vulnerabilities': [],
            'os_guess': self.nm[target].get('osmatch', [{}])[0].get('name', 'Unknown'),
            'scan_time': time.time()
        }

        for proto in self.nm[target].all_protocols():
            ports = self.nm[target][proto].keys()
            for port in ports:
                port_data = {
                    'port': port,
                    'protocol': proto,
                    'state': self.nm[target][proto][port]['state'],
                    'service': self.nm[target][proto][port]['name'],
                    'version': self.nm[target][proto][port].get('version', ''),
                    'risk': self._get_port_risk(port)
                }
                
                host_data['ports'].append(port_data)

                if port_data['service'] not in host_data['services']:
                    host_data['services'].append(port_data['service'])

                if port_data['risk']['level'] in ['high', 'critical']:
                    host_data['risky_ports'].append(port_data)

        return host_data

    def _get_port_risk(self, port):
        """Determine risk level for a given port"""
        if port in self.risky_ports:
            level, service, vulns = self.risky_ports[port]
            return {
                'level': level,
                'service': service,
                'vulnerabilities': vulns
            }
        return {
            'level': 'low',
            'service': '',
            'vulnerabilities': ''
        }
    def get_common_ports_string(self):
        """Get string of most common ports for faster scanning"""
        common = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 
                  1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017]
        return ','.join(map(str, common))

    def batch_scan(self, targets, ports=None, vuln_scan=False, max_workers=5):
        """Scan multiple targets efficiently with parallel processing"""
        if ports is None:
            ports = self.get_common_ports_string()  # Use common ports by default
    
        results = []
        print(f"Starting parallel scan for {len(targets)} targets")
    
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scan tasks
            future_to_target = {
                executor.submit(self.scan_target, target, ports, vuln_scan): target 
                for target in targets
            }
        
            # Collect results as they complete
            for future in future_to_target:
                target = future_to_target[future]
                try:
                    result = future.result(timeout=30)  # 30 second timeout per target
                    if result:
                        results.append(result)
                        print(f"Completed scan for {target}: {len(result['ports'])} ports")
                except Exception as e:
                    print(f"Error scanning {target}: {e}")
                    continue
    
        print(f"Parallel scan completed. Total results: {len(results)}")
        return results


    def quick_web_scan(self, target, vuln_scan=False):
        """Fast scan for common web ports"""
        return self.scan_target(target=target, ports=','.join(map(str, self.common_web_ports)), vuln_scan=vuln_scan)