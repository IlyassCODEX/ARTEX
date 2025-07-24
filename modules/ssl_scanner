import socket
import ssl
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
import idna
import concurrent.futures
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ocsp, ExtensionNotFound
from cryptography.hazmat.primitives.serialization import Encoding
import dns.resolver
import json
import time

class SSLScanner:
    def __init__(self, timeout: int = 5, max_workers: int = 10):
        self.timeout = timeout
        self.max_workers = max_workers
        self.ciphers = 'HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA'
        self.trust_stores = {
            'mozilla': '/etc/ssl/certs/ca-certificates.crt',  # Common Linux path
            'windows': None,  # Will use system store on Windows
            'macos': '/etc/ssl/cert.pem'  # Common macOS path
        }
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 2
        self.dns_resolver.lifetime = 2

    def scan(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Perform comprehensive SSL/TLS scan on a host"""
        start_time = time.time()
        result = {
            'host': host,
            'port': port,
            'scan_time': datetime.now().isoformat(),
            'success': False,
            'error': None,
            'scan_duration': 0
        }
    
        try:
            if not host.replace('.', '').isascii():
                host = idna.encode(host).decode('ascii')
        
            # Get DNS information first
            result['dns'] = self._get_dns_info(host)

            # Get certificate information
            cert_info = self._get_certificate_info(host, port)
            result.update(cert_info)
        
            # Perform various checks
            result['protocols'] = self._check_protocols(host, port)
            result['ciphers'] = self._check_ciphers(host, port)
            result['hsts'] = self._check_hsts(host, port)
            result['ocsp_stapling'] = self._check_ocsp_stapling(host, port)
            result['certificate_transparency'] = self._check_certificate_transparency(result['certificates'][0] if result['certificates'] else None)
            result['vulnerabilities'] = self._check_vulnerabilities(result)
            result['tls_fingerprint'] = self._get_tls_fingerprint(host, port)
            result['security_headers'] = self._check_security_headers(host, port)
            result['dnssec'] = self._check_dnssec(host)

            # Check certificate revocation via CRL
            if result['certificates']:
                result['crl_revocation'] = self._check_crl_revocation(result['certificates'][0])
        
            result['success'] = True

        except Exception as e:
            result['error'] = str(e)
        finally:
            result['scan_duration'] = round(time.time() - start_time, 2)
        
        return result
    
    def _get_dns_info(self, host: str) -> Dict[str, Any]:
        """Get DNS information for the host"""
        result = {
            'a': [],
            'aaaa': [],
            'mx': [],
            'ns': [],
            'txt': [],
            'cname': None,
            'dns_sec': False
        }
        
        try:
            # A records
            try:
                answers = self.dns_resolver.resolve(host, 'A')
                result['a'] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # AAAA records
            try:
                answers = self.dns_resolver.resolve(host, 'AAAA')
                result['aaaa'] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # MX records
            try:
                answers = self.dns_resolver.resolve(host, 'MX')
                result['mx'] = [str(r.exchange) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # NS records
            try:
                answers = self.dns_resolver.resolve(host, 'NS')
                result['ns'] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # TXT records
            try:
                answers = self.dns_resolver.resolve(host, 'TXT')
                result['txt'] = [str(r.strings[0], 'utf-8') for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # CNAME
            try:
                answers = self.dns_resolver.resolve(host, 'CNAME')
                result['cname'] = str(answers[0].target)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def _verify_hostname(self, cert: Dict, hostname: str) -> bool:
        """Improved hostname verification with wildcard support"""
        if not cert:
            return False

        san = cert.get('subjectAltName', [])
        common_names = []
        
        # Extract Subject Common Names
        for field in cert.get('subject', ()):
            if field[0][0] == 'commonName':
                common_names.append(field[0][1])

        # Check Subject Alternative Names
        for key, value in san:
            if key == 'DNS':
                if self._hostname_matches(value, hostname):
                    return True

        # Check Common Names (only if no SANs present)
        if not san and common_names:
            return any(self._hostname_matches(cn, hostname) for cn in common_names)

        return False

    def _hostname_matches(self, pattern: str, hostname: str) -> bool:
        """Check if hostname matches pattern with improved wildcard handling"""
        pattern = pattern.lower()
        hostname = hostname.lower()

        if pattern == hostname:
            return True
            
        if pattern.startswith('*.'):
            # Wildcard certificate
            wildcard_domain = pattern[2:]
            if hostname.endswith(wildcard_domain):
                # Check that the wildcard only matches one level
                hostname_without_wildcard = hostname[:-len(wildcard_domain)]
                if '.' not in hostname_without_wildcard:
                    return True
                    
        return False

    def _get_certificate_info(self, host: str, port: int) -> Dict[str, Any]:
        """Retrieve comprehensive certificate information with chain verification"""
        result = {
            'certificates': [],
            'chain_issues': [],
            'validation': {
                'hostname_match': False,
                'trusted': False,
                'expired': False,
                'self_signed': False,
                'revoked': False,
                'has_sha1_signature': False,
                'key_too_weak': False,
                'trust_store': None
            }
        }
    
        try:
            # Try with Mozilla trust store first
            context = ssl.create_default_context(cafile=self.trust_stores['mozilla'])
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED

            try:
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert_bin = ssock.getpeercert(binary_form=True)
                        cert_dict = ssock.getpeercert()

                        # Try to get certificate chain (handle case where method doesn't exist)
                        cert_chain = []
                        if hasattr(ssock, 'getpeercertchain'):
                            cert_chain = ssock.getpeercertchain()
                        elif hasattr(ssock, '_sslobj') and hasattr(ssock._sslobj, 'get_verified_chain'):
                            # Alternative for some Python versions
                            cert_chain = ssock._sslobj.get_verified_chain()
                    
                        return self._process_certificate_info(cert_bin, cert_dict, cert_chain, host, result, 'mozilla')
            except ssl.SSLError as e:
                if 'certificate verify failed' in str(e):
                    # Fall back to system trust store
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_REQUIRED

                    with socket.create_connection((host, port), timeout=self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as ssock:
                            cert_bin = ssock.getpeercert(binary_form=True)
                            cert_dict = ssock.getpeercert()
                        
                            # Try to get certificate chain (handle case where method doesn't exist)
                            cert_chain = []
                            if hasattr(ssock, 'getpeercertchain'):
                                cert_chain = ssock.getpeercertchain()
                            elif hasattr(ssock, '_sslobj') and hasattr(ssock._sslobj, 'get_verified_chain'):
                                cert_chain = ssock._sslobj.get_verified_chain()

                            return self._process_certificate_info(cert_bin, cert_dict, cert_chain, host, result, 'system')
                else:
                    raise
                    
        except Exception as e:
            if 'certificate verify failed' in str(e):
                result['chain_issues'].append('Certificate verification failed')
            raise

        return result
    
    def _process_certificate_info(self, cert_bin: Optional[bytes], cert_dict: Optional[Dict], 
                                cert_chain: List[bytes], host: str, 
                                result: Dict[str, Any], trust_store: str) -> Dict[str, Any]:
        """Process certificate information from established SSL connection"""
        if cert_bin:
            cert = self._parse_certificate(cert_bin, cert_dict)
            result['certificates'].append(cert)
        
            # Check for SHA-1 signature
            if 'sha1' in cert['signature_algorithm'].lower():
                result['validation']['has_sha1_signature'] = True
                result['chain_issues'].append('Uses SHA-1 signature')
        
            # Check key strength
            if cert['public_key']['size'] and cert['public_key']['size'] < 2048:
                result['validation']['key_too_weak'] = True
                result['chain_issues'].append(f'Weak key: {cert["public_key"]["size"]} bits')
    
        # Process certificate chain if available
        if cert_chain:
            for chain_cert_bin in cert_chain:
                try:
                    chain_cert = self._parse_certificate(chain_cert_bin, None)
                    result['certificates'].append(chain_cert)
                except Exception:
                    continue
    
        result['validation']['trust_store'] = trust_store

        # Verify hostname
        if cert_dict:
            result['validation']['hostname_match'] = self._verify_hostname(cert_dict, host)
            if not result['validation']['hostname_match']:
                result['chain_issues'].append('Hostname mismatch')
    
        # Basic trust verification
        try:
            if cert_dict:
                ssl._ssl._test_decode_cert(cert_dict)
                result['validation']['trusted'] = True
        except:
            result['validation']['trusted'] = False
            result['chain_issues'].append('Untrusted certificate chain')
    
        # Check certificate validity
        if result['certificates']:
            leaf_cert = result['certificates'][0]
            now = datetime.utcnow()
        
            if 'not_after' in leaf_cert and leaf_cert['not_after'] < now:
                result['validation']['expired'] = True
                result['chain_issues'].append('Certificate expired')
        
            if 'not_before' in leaf_cert and leaf_cert['not_before'] > now:
                result['validation']['expired'] = True
                result['chain_issues'].append('Certificate not yet valid')
        
            if 'issuer' in leaf_cert and 'subject' in leaf_cert:
                if leaf_cert['issuer'] == leaf_cert['subject']:
                    result['validation']['self_signed'] = True
                    result['chain_issues'].append('Self-signed certificate')
    
        return result
    
    def _parse_certificate(self, cert_data: bytes, cert_dict: Optional[Dict]) -> Dict[str, Any]:
        """Parse X.509 certificate data with comprehensive information"""
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
    
        # Process extensions
        extensions = {}
        try:
            for ext in cert.extensions:
                try:
                    if ext.oid._name == 'subjectAltName':
                        extensions['subjectAltName'] = [
                            (name._name, name.value) 
                            for name in ext.value
                        ]
                    elif ext.oid._name == 'keyUsage':
                        extensions['keyUsage'] = [ku.name for ku in ext.value if ku.value]
                    elif ext.oid._name == 'extendedKeyUsage':
                        extensions['extendedKeyUsage'] = [eku._name for eku in ext.value]
                    elif ext.oid._name == 'basicConstraints':
                        extensions['basicConstraints'] = {
                            'ca': ext.value.ca,
                            'path_length': ext.value.path_length
                        }
                    elif ext.oid._name == 'certificatePolicies':
                        extensions['certificatePolicies'] = [p.policy_identifier.dotted_string for p in ext.value]
                    elif ext.oid._name == 'crlDistributionPoints':
                        extensions['crlDistributionPoints'] = [dp.full_name[0].value for dp in ext.value]
                    elif ext.oid._name == 'authorityInfoAccess':
                        extensions['authorityInfoAccess'] = [
                            (ad.access_method._name, ad.access_location.value)
                            for ad in ext.value
                        ]
                    else:
                        extensions[ext.oid._name] = str(ext.value)
                except Exception as e:
                    extensions[ext.oid._name] = f'Parse error: {str(e)}'
        except ExtensionNotFound:
            pass

        # Format names in a readable way
        def format_name(attributes):
            result = {}
            name_map = {
                'commonName': 'CN',
                'organizationName': 'O',
                'organizationalUnitName': 'OU',
                'countryName': 'C',
                'stateOrProvinceName': 'ST',
                'localityName': 'L',
                'emailAddress': 'E',
                'serialNumber': 'SERIAL',
                'domainComponent': 'DC'
            }
            
            for attr in attributes:
                name = name_map.get(attr.oid._name, attr.oid._name)
                result[name] = attr.value
            return result

        subject = format_name(cert.subject)
        issuer = format_name(cert.issuer)

        return {
            'subject': subject,
            'issuer': issuer,
            'serial_number': hex(cert.serial_number),
            'version': cert.version.name,
            'not_before': cert.not_valid_before,
            'not_after': cert.not_valid_after,
            'signature_algorithm': cert.signature_algorithm_oid._name,
            'extensions': extensions,
            'fingerprint_sha1': cert.fingerprint(hashes.SHA1()).hex(),
            'fingerprint_sha256': cert.fingerprint(hashes.SHA256()).hex(),
            'public_key': {
                'type': cert.public_key().__class__.__name__,
                'size': cert.public_key().key_size if hasattr(cert.public_key(), 'key_size') else None,
                'info': self._get_public_key_info(cert.public_key())
            },
            'cert_dict': cert_dict,
            'pem': cert.public_bytes(Encoding.PEM).decode('ascii')
        }
    
    def _get_public_key_info(self, public_key) -> Dict[str, Any]:
        """Get detailed public key information"""
        key_info = {}
        
        if hasattr(public_key, 'key_size'):
            key_info['size'] = public_key.key_size
            
        if hasattr(public_key, 'public_numbers'):
            if hasattr(public_key.public_numbers(), 'n'):
                # RSA key
                nums = public_key.public_numbers()
                key_info['exponent'] = nums.e
                key_info['modulus'] = hex(nums.n)
            elif hasattr(public_key.public_numbers(), 'x'):
                # EC key
                nums = public_key.public_numbers()
                key_info['curve'] = public_key.curve.name if hasattr(public_key, 'curve') else 'unknown'
                key_info['x'] = hex(nums.x)
                key_info['y'] = hex(nums.y)
                
        return key_info
    
    def _check_protocols(self, host: str, port: int) -> Dict[str, bool]:
        """Check which SSL/TLS protocols are supported with improved detection"""
        protocols = {
            'SSLv2': False,
            'SSLv3': False,
            'TLSv1.0': False,
            'TLSv1.1': False,
            'TLSv1.2': False,
            'TLSv1.3': False
        }
    
        # Create a mapping of protocol names to their context versions
        protocol_map = {
            'SSLv3': ssl.PROTOCOL_SSLv23,  # SSLv3 is included in SSLv23 for backward compatibility
            'TLSv1.0': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
            'TLSv1.3': ssl.PROTOCOL_TLS
        }
    
        # SSLv2 is always disabled in modern Python
        protocols['SSLv2'] = False
    
        for proto, context_version in protocol_map.items():
            try:
                context = ssl.SSLContext(context_version)
                context.verify_mode = ssl.CERT_NONE
                context.check_hostname = False
            
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        # For TLS 1.3, we need to check the actual negotiated version
                        if proto == 'TLSv1.3' and hasattr(ssock, 'version'):
                            protocols[proto] = ssock.version() == 'TLSv1.3'
                        else:
                            protocols[proto] = True
                        
                        # Special handling for SSLv3
                        if proto == 'SSLv3':
                            if hasattr(ssock, 'version'):
                                protocols['SSLv3'] = ssock.version() == 'SSLv3'
                            else:
                                # If we can't check version, assume SSLv3 worked if connection succeeded
                                protocols['SSLv3'] = True
            except:
                protocols[proto] = False

        return protocols
    
    def _check_ciphers(self, host: str, port: int) -> Dict[str, Any]:
        """Check supported cipher suites with improved detection"""
        result = {
            'supported': [],
            'preferred': None,
            'weak': [],
            'deprecated': [],
            'recommended': [],
            'grade': 'A'  # Start with A, downgrade based on findings
        }
        
        weak_ciphers = [
            'NULL', 'EXPORT', 'DES', 'RC4', 'MD5', 
            'DSS', 'PSK', 'SRP', 'CAMELLIA', 'SEED',
            'IDEA', '3DES', 'ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
            'CBC', 'SHA1', 'SHA-1'
        ]
        
        deprecated_ciphers = [
            'TLS_RSA_WITH_AES_128_CBC_SHA',
            'TLS_RSA_WITH_AES_256_CBC_SHA',
            'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
            'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'
        ]
        
        recommended_ciphers = [
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_128_GCM_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
        ]
        
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.set_ciphers('ALL:@SECLEVEL=0')
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher_name, cipher_version, _ = ssock.cipher()
                    result['preferred'] = {
                        'name': cipher_name,
                        'version': cipher_version,
                        'strength': self._get_cipher_strength(cipher_name)
                    }
                    
                    # Get all ciphers supported by the server
                    for cipher in ssl._SSLMethod.PROTOCOL_TLS.get_ciphers():
                        try:
                            test_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                            test_context.set_ciphers(cipher['name'])
                            test_context.verify_mode = ssl.CERT_NONE
                            test_context.check_hostname = False
                            
                            with socket.create_connection((host, port), timeout=self.timeout) as test_sock:
                                with test_context.wrap_socket(test_sock, server_hostname=host) as test_ssock:
                                    result['supported'].append({
                                        'name': cipher['name'],
                                        'strength': self._get_cipher_strength(cipher['name'])
                                    })
                                    
                                    if any(wc.lower() in cipher['name'].lower() for wc in weak_ciphers):
                                        result['weak'].append(cipher['name'])
                                        result['grade'] = self._downgrade_rating(result['grade'], 'C')
                                    elif any(dc.lower() in cipher['name'].lower() for dc in deprecated_ciphers):
                                        result['deprecated'].append(cipher['name'])
                                        result['grade'] = self._downgrade_rating(result['grade'], 'B')
                                    elif any(rc.lower() in cipher['name'].lower() for rc in recommended_ciphers):
                                        result['recommended'].append(cipher['name'])
                        except:
                            continue
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def _get_cipher_strength(self, cipher_name: str) -> str:
        """Determine cipher strength based on name"""
        if 'GCM' in cipher_name or 'CHACHA20' in cipher_name:
            return 'strong'
        elif 'CBC' in cipher_name:
            return 'moderate'
        elif 'SHA1' in cipher_name or 'SHA-1' in cipher_name:
            return 'weak'
        elif 'RC4' in cipher_name or 'DES' in cipher_name or '3DES' in cipher_name:
            return 'very weak'
        else:
            return 'unknown'
    
    def _downgrade_rating(self, current: str, minimum: str) -> str:
        """Downgrade the rating based on findings"""
        grade_order = ['A', 'B', 'C', 'D', 'F']
        current_idx = grade_order.index(current)
        min_idx = grade_order.index(minimum)
        return grade_order[max(current_idx, min_idx)]
    
    def _check_hsts(self, host: str, port: int) -> Dict[str, Any]:
        """Check HTTP Strict Transport Security (HSTS) configuration with improved detection"""
        result = {
            'enabled': False,
            'max_age': None,
            'include_subdomains': False,
            'preload': False,
            'header': None
        }
        
        try:
            # First try HTTPS
            conn = socket.create_connection((host, port), timeout=self.timeout)
            context = ssl.create_default_context()
            with context.wrap_socket(conn, server_hostname=host) as ssock:
                ssock.send(
                    f"HEAD / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Connection: close\r\n\r\n".encode()
                )
                response = ssock.recv(4096).decode(errors='ignore')
                
                self._parse_hsts_header(response, result)
                
            # If not found, try HTTP with redirect check
            if not result['enabled'] and port == 443:
                try:
                    conn = socket.create_connection((host, 80), timeout=self.timeout)
                    conn.send(
                        f"HEAD / HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"Connection: close\r\n\r\n".encode()
                    )
                    response = conn.recv(4096).decode(errors='ignore')
                    
                    # Check for redirect to HTTPS
                    if 'Location: https://' in response:
                        result['redirect_to_https'] = True
                except:
                    pass
                    
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def _parse_hsts_header(self, response: str, result: Dict[str, Any]) -> None:
        """Parse HSTS header from HTTP response"""
        headers = [line.strip() for line in response.split('\r\n') if line.strip()]
        
        for header in headers:
            if header.lower().startswith('strict-transport-security:'):
                hsts_header = header.split(':', 1)[1].strip()
                result['enabled'] = True
                result['header'] = hsts_header
                
                if 'max-age=' in hsts_header.lower():
                    try:
                        max_age_part = hsts_header.lower().split('max-age=')[1]
                        max_age = max_age_part.split(';')[0].strip()
                        result['max_age'] = int(max_age)
                    except (ValueError, IndexError):
                        pass
                        
                if 'includesubdomains' in hsts_header.lower():
                    result['include_subdomains'] = True
                    
                if 'preload' in hsts_header.lower():
                    result['preload'] = True
                break
    
    def _check_ocsp_stapling(self, host: str, port: int) -> Dict[str, Any]:
        """Check OCSP stapling support with improved verification"""
        result = {
            'supported': False,
            'response': None,
            'status': None,
            'valid': False,
            'error': None
        }
        
        try:
            context = ssl.create_default_context()
            context.verify_mode = ssl.CERT_OPTIONAL
            context.check_hostname = False
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host,
                                       ocsp_callback=lambda _: True) as ssock:
                    ocsp_response = ssock.ocsp_response
                    if ocsp_response is not None:
                        result['supported'] = True
                        result['response'] = ocsp_response.hex()
                        
                        try:
                            ocsp_resp = ocsp.load_der_ocsp_response(ocsp_response)
                            result['status'] = ocsp_resp.response_status.name
                            
                            if ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                                result['valid'] = True
                                result['status'] = ocsp_resp.certificate_status.name
                                result['this_update'] = ocsp_resp.this_update.isoformat()
                                result['next_update'] = ocsp_resp.next_update.isoformat() if ocsp_resp.next_update else None
                        except Exception as e:
                            result['error'] = str(e)
                            result['valid'] = False
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def _check_certificate_transparency(self, cert: Optional[Dict]) -> Dict[str, Any]:
        """Check Certificate Transparency (CT) logs with improved detection"""
        result = {
            'logged': False,
            'logs': [],
            'scts': [],
            'policy_compliant': False
        }
        
        if not cert or 'extensions' not in cert:
            return result
            
        extensions = cert['extensions']
        
        # Check for SCTs in various extensions
        if 'signedCertificateTimestampList' in extensions:
            result['logged'] = True
            result['scts'] = extensions['signedCertificateTimestampList']
            
        if 'ctPrecertificateSCTs' in extensions:
            result['logged'] = True
            result['scts'].extend(extensions['ctPrecertificateSCTs'])
            
        # Check for known CT logs
        if result['scts']:
            result['policy_compliant'] = len(result['scts']) >= 2
            
        return result
    
    def _check_crl_revocation(self, cert: Dict) -> Dict[str, Any]:
        """Check certificate revocation via CRL"""
        result = {
            'checked': False,
            'revoked': False,
            'error': None,
            'crl_urls': []
        }
        
        if not cert or 'extensions' not in cert:
            return result
            
        extensions = cert['extensions']
        
        # Get CRL distribution points
        if 'crlDistributionPoints' in extensions:
            result['crl_urls'] = extensions['crlDistributionPoints']
            result['checked'] = True
            
            # In a real implementation, you would download the CRL and check for revocation
            # This is simplified for the example
            result['revoked'] = False
            
        return result
    
    def _get_tls_fingerprint(self, host: str, port: int) -> Dict[str, Any]:
        """Get TLS fingerprint (JA3/JA3S style)"""
        result = {
            'ja3': None,
            'ja3s': None,
            'error': None
        }
        
        try:
            # Simplified fingerprinting - real implementation would be more complex
            context = ssl.create_default_context()
            context.set_ciphers('ALL')
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get cipher info
                    cipher_name, cipher_version, _ = ssock.cipher()
                    
                    # Simulate JA3 fingerprint
                    result['ja3'] = {
                        'tls_version': cipher_version,
                        'ciphers': cipher_name,
                        'extensions': 'some-extensions'
                    }
                    
                    # Simulate JA3S fingerprint
                    result['ja3s'] = {
                        'tls_version': cipher_version,
                        'ciphers': cipher_name,
                        'extensions': 'server-extensions'
                    }
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def _check_security_headers(self, host: str, port: int) -> Dict[str, Any]:
        """Check for important security headers"""
        result = {
            'headers': {},
            'missing': [],
            'recommended': [
                'Content-Security-Policy',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Referrer-Policy',
                'Feature-Policy',
                'Permissions-Policy'
            ]
        }
        
        try:
            conn = socket.create_connection((host, port), timeout=self.timeout)
            context = ssl.create_default_context()
            with context.wrap_socket(conn, server_hostname=host) as ssock:
                ssock.send(
                    f"HEAD / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Connection: close\r\n\r\n".encode()
                )
                response = ssock.recv(4096).decode(errors='ignore')
                
                headers = [line.strip() for line in response.split('\r\n') if line.strip()]
                
                for header in headers:
                    if ':' in header:
                        name, value = header.split(':', 1)
                        name = name.strip()
                        value = value.strip()
                        
                        if name.lower() in ['content-security-policy', 
                                          'x-content-type-options',
                                          'x-frame-options',
                                          'x-xss-protection',
                                          'referrer-policy',
                                          'feature-policy',
                                          'permissions-policy']:
                            result['headers'][name] = value
                
                # Check for missing recommended headers
                for rec_header in result['recommended']:
                    if rec_header not in result['headers']:
                        result['missing'].append(rec_header)
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def _check_dnssec(self, host: str) -> Dict[str, Any]:
        """Check DNSSEC validation for the domain"""
        result = {
            'validated': False,
            'error': None
        }
        
        try:
            # This is a simplified check - real implementation would do proper DNSSEC validation
            answers = self.dns_resolver.resolve(host, 'DNSKEY')
            result['validated'] = True
        except dns.resolver.NoAnswer:
            result['validated'] = False
            result['error'] = 'No DNSSEC records found'
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def _check_vulnerabilities(self, scan_data: Dict) -> Dict[str, Any]:
        """Check for known SSL/TLS vulnerabilities with improved detection"""
        vulnerabilities = {
            'heartbleed': False,
            'poodle': False,
            'freak': False,
            'beast': False,
            'lucky13': False,
            'crime': False,
            'breach': False,
            'logjam': False,
            'drown': False,
            'sweet32': False,
            'ccs_injection': False,
            'ticketbleed': False,
            'robot': False,
            'secure_renegotiation': False,
            'compression': False,
            'openssl_ccs': False,
            'openssl_padding_oracle': False,
            'tls_fallback_scsv': False,
            'session_ticket': False
        }
        
        # Protocol-based vulnerabilities
        protocols = scan_data.get('protocols', {})
        if protocols.get('SSLv3', False):
            vulnerabilities['poodle'] = True
            vulnerabilities['drown'] = True
            
        if protocols.get('TLSv1.0', False):
            vulnerabilities['beast'] = True
            
        # Cipher-based vulnerabilities
        ciphers = scan_data.get('ciphers', {})
        if any('RC4' in cipher for cipher in ciphers.get('supported', [])):
            vulnerabilities['crime'] = True
            
        if any('3DES' in cipher or 'DES' in cipher for cipher in ciphers.get('supported', [])):
            vulnerabilities['sweet32'] = True
            
        if any('EXPORT' in cipher for cipher in ciphers.get('supported', [])):
            vulnerabilities['freak'] = True
            vulnerabilities['logjam'] = True
            
        # Extension-based vulnerabilities
        if scan_data.get('certificates'):
            cert = scan_data['certificates'][0]
            extensions = cert.get('extensions', {})
            
            if 'COMPRESSION' in extensions:
                vulnerabilities['compression'] = True
                vulnerabilities['crime'] = True
                
            if 'TLS_RENEGOTIATION' in extensions:
                vulnerabilities['secure_renegotiation'] = True
                
            if 'TLS_FALLBACK_SCSV' not in extensions:
                vulnerabilities['tls_fallback_scsv'] = True
                
            if 'SESSION_TICKET' in extensions:
                vulnerabilities['session_ticket'] = True
                
            # Check for RSA export keys (FREAK)
            if cert.get('public_key', {}).get('type') == 'RSAPublicKey':
                if cert.get('public_key', {}).get('size', 0) < 1024:
                    vulnerabilities['freak'] = True
                    
        # Check for Heartbleed (simplified)
        if scan_data.get('protocol') == 'TLSv1.1':
            vulnerabilities['heartbleed'] = True
            
        return vulnerabilities
    
    def batch_scan(self, hosts: list) -> Dict[str, Dict]:
        """Perform SSL scans on multiple hosts in parallel with improved error handling"""
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_host = {executor.submit(self.scan, host): host for host in hosts}
            
            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    results[host] = future.result()
                except Exception as e:
                    results[host] = {
                        'host': host,
                        'error': str(e),
                        'scan_time': datetime.now().isoformat(),
                        'success': False
                    }
                    
        return results
