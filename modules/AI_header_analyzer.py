# AI_header_analyzer.py
import requests
import json
import time
import random
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Security header definitions — ground truth for rule-based pass
# ---------------------------------------------------------------------------

SECURITY_HEADERS: Dict[str, Dict] = {
    "Strict-Transport-Security": {
        "risk": "high",
        "description": "HSTS not set — allows protocol downgrade and MITM attacks.",
        "required_directives": ["max-age"],
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "attack_class": ["MITM", "Protocol Downgrade", "SSL Stripping"],
    },
    "Content-Security-Policy": {
        "risk": "high",
        "description": "CSP absent — XSS and data injection vectors fully open.",
        "required_directives": ["default-src"],
        "weak_values": ["unsafe-inline", "unsafe-eval", "*"],
        "attack_class": ["XSS", "Data Injection", "Clickjacking"],
    },
    "X-Frame-Options": {
        "risk": "medium",
        "description": "X-Frame-Options missing — clickjacking attack surface exposed.",
        "valid_values": ["DENY", "SAMEORIGIN"],
        "attack_class": ["Clickjacking", "UI Redressing"],
    },
    "X-Content-Type-Options": {
        "risk": "medium",
        "description": "MIME sniffing not blocked — MIME confusion attacks possible.",
        "valid_values": ["nosniff"],
        "attack_class": ["MIME Sniffing", "Drive-by Download"],
    },
    "Referrer-Policy": {
        "risk": "low",
        "description": "Referrer-Policy absent — sensitive URL paths leak to third parties.",
        "recommended_values": [
            "no-referrer",
            "strict-origin",
            "strict-origin-when-cross-origin",
        ],
        "attack_class": ["Information Disclosure"],
    },
    "Permissions-Policy": {
        "risk": "low",
        "description": "Permissions-Policy missing — browser features unrestricted.",
        "attack_class": ["Browser Feature Abuse", "Fingerprinting"],
    },
    "X-XSS-Protection": {
        "risk": "low",
        "description": "X-XSS-Protection not set (legacy but still checked by scanners).",
        "recommended": "1; mode=block",
        "attack_class": ["XSS"],
    },
    "Cache-Control": {
        "risk": "low",
        "description": "Cache-Control absent on potentially sensitive responses.",
        "sensitive_hint": True,
        "attack_class": ["Sensitive Data Exposure"],
    },
}

LEAK_HEADERS: Dict[str, Dict] = {
    "Server": {
        "risk": "medium",
        "description": "Server header exposes web server version — fingerprinting aid.",
        "attack_class": ["Fingerprinting", "Version-based Exploit"],
    },
    "X-Powered-By": {
        "risk": "medium",
        "description": "X-Powered-By reveals backend framework and version.",
        "attack_class": ["Fingerprinting", "Framework CVE"],
    },
    "X-AspNet-Version": {
        "risk": "medium",
        "description": "ASP.NET version disclosed — narrows exploit search space.",
        "attack_class": ["Fingerprinting", ".NET CVE"],
    },
    "X-AspNetMvc-Version": {
        "risk": "medium",
        "description": "MVC version exposed.",
        "attack_class": ["Fingerprinting"],
    },
    "X-Generator": {
        "risk": "low",
        "description": "CMS/generator fingerprint exposed.",
        "attack_class": ["Fingerprinting"],
    },
    "X-Drupal-Cache": {
        "risk": "low",
        "description": "Drupal platform fingerprinted.",
        "attack_class": ["CMS Fingerprinting"],
    },
    "X-Varnish": {
        "risk": "info",
        "description": "Varnish cache layer identified — internal IPs may leak.",
        "attack_class": ["Infrastructure Disclosure"],
    },
    "Via": {
        "risk": "info",
        "description": "Proxy/cache layer disclosed via Via header.",
        "attack_class": ["Infrastructure Disclosure"],
    },
}

CSP_DANGEROUS_DIRECTIVES = [
    "unsafe-inline",
    "unsafe-eval",
    "unsafe-hashes",
    "data:",
    "http:",
    "*",
]

CORS_DANGEROUS_VALUES = ["*", "null"]

RISK_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class AIHeaderAnalyzer:
    """
    Two-pass HTTP header security analyzer.

    Pass 1 — rule-based: collect all header findings deterministically.
    Pass 2 — AI (Groq): receive the full finding set, return attack chain
             narrative, exploit priority ranking, and remediation roadmap.

    Integrates with ARTEX scan_results dict:
        scan_results[scan_id]['header_analysis'] = analyzer.analyze(domain, subdomains)
    """

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    ]

    def __init__(self, groq_api_key: Optional[str] = None, timeout: int = 10):
        self.groq_api_key = groq_api_key
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)s] %(name)s — %(message)s")
            )
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    
    def analyze(
        self,
        domain: str,
        subdomains: Optional[List[Dict]] = None,
        max_targets: int = 10,
    ) -> Dict:
        """
        Analyze HTTP security headers for domain + active subdomains.

        Args:
            domain:       Primary domain string (e.g. "example.com").
            subdomains:   List of subdomain dicts from SubdomainEnumerator —
                          each must have 'subdomain', optionally 'http_status'
                          and 'https_status'.
            max_targets:  Cap on how many additional subdomains to probe
                          (main domain always included).

        Returns:
            {
              'targets':        { url: per_target_findings },
              'aggregate':      aggregated_risk_summary,
              'ai_analysis':    AI narrative + chain + remediation (or None),
              'scan_metadata':  timing, counts, model used,
            }
        """
        self.logger.info(f"Header analysis starting — domain: {domain}")
        start = time.time()

        # Build target list
        targets = self._build_target_list(domain, subdomains, max_targets)

        # Pass 1 — rule-based collection
        target_results: Dict[str, Dict] = {}
        for url in targets:
            self.logger.info(f"Fetching headers: {url}")
            raw_headers, status_code, error = self._fetch_headers(url)
            if error and not raw_headers:
                target_results[url] = {"error": error, "reachable": False}
                continue
            findings = self._rule_based_analysis(url, raw_headers, status_code)
            target_results[url] = findings

        # Aggregate across all targets
        aggregate = self._aggregate_findings(target_results)

        # Pass 2 — AI enrichment
        ai_result = None
        if self.groq_api_key:
            ai_result = self._ai_analysis(domain, target_results, aggregate)

        duration = round(time.time() - start, 2)
        self.logger.info(f"Header analysis complete in {duration}s")

        return {
            "targets": target_results,
            "aggregate": aggregate,
            "ai_analysis": ai_result,
            "scan_metadata": {
                "domain": domain,
                "targets_scanned": len(targets),
                "targets_reachable": sum(
                    1 for v in target_results.values() if v.get("reachable", True)
                ),
                "scan_duration_seconds": duration,
                "timestamp": datetime.now().isoformat(),
                "ai_model": "Groq Llama3-70B" if ai_result else "Rule-based only",
            },
        }

    # ------------------------------------------------------------------
    # Target building
    # ------------------------------------------------------------------
    
    def _build_target_list(
        self,
        domain: str,
        subdomains: Optional[list[Dict]],
        max_targets: int,
    ) -> List[str]:
        targets: List[str] = []
        
        # Always include main domain — prefer HTTPS
        for scheme in ("https", "http"):
            targets.append(f"{scheme}://{domain}")
            break  # just https first; fallback handled in _fetch_headers
            
        if not subdomains:
            return targets
            
        active = [
            s for s in subdomains
            if s.get("http_status") or s.get("https_status")
        ]

        for sub in active[:max_targets]:
            name = sub.get("subdomain", "")
            if not name or name == domain:
                continue
            scheme = "https" if sub.get("https_status") else "http"
            url = f"{scheme}://{name}"
            if url not in targets:
                targets.append(url)

        return targets

    # ------------------------------------------------------------------
    # HTTP fetching — headers only, no body
    # ------------------------------------------------------------------

    def _fetch_headers(
        self, url: str
    ) -> Tuple[Dict[str, str], Optional[int], Optional[str]]:
        headers_out: Dict[str, str] = {}
        try:
            resp = requests.head(
                url,
                headers={"User-Agent": random.choice(self.USER_AGENTS)},
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            # Some servers return empty on HEAD — fallback to GET
            if not resp.headers or len(resp.headers) < 3:
                resp = requests.get(
                    url,
                    headers={"User-Agent": random.choice(self.USER_AGENTS)},
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                    stream=True,  # don't download body
                )
                resp.close()

            headers_out = {k.strip(): v.strip() for k, v in resp.headers.items()}
            return headers_out, resp.status_code, None

        except requests.exceptions.SSLError:
            # Retry with HTTP if HTTPS cert is broken
            if url.startswith("https://"):
                fallback = url.replace("https://", "http://", 1)
                return self._fetch_headers(fallback)
            return {}, None, "SSLError"

        except requests.exceptions.ConnectionError as e:
            return {}, None, f"ConnectionError: {e}"
        except requests.exceptions.Timeout:
            return {}, None, "Timeout"
        except Exception as e:
            return {}, None, str(e)

    # ------------------------------------------------------------------
    # Pass 1 — rule-based analysis
    # ------------------------------------------------------------------

    def _rule_based_analysis(
        self, url: str, headers: Dict[str, str], status_code: Optional[int]
    ) -> Dict:
        # Normalise header keys to Title-Case for consistent lookup
        norm = {k.title(): v for k, v in headers.items()}

        missing_security   = self._check_missing_security_headers(norm)
        weak_security      = self._check_weak_security_headers(norm)
        leaking_headers    = self._check_leak_headers(norm)
        cors_issues        = self._check_cors(norm)
        cookie_issues      = self._check_cookies(norm)
        csp_issues         = self._check_csp(norm)
        interesting        = self._collect_interesting_headers(norm)

        all_findings = (
            missing_security + weak_security + leaking_headers
            + cors_issues + cookie_issues + csp_issues
        )

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        risk_score = self._calculate_risk_score(all_findings)

        return {
            "reachable": True,
            "url": url,
            "status_code": status_code,
            "raw_headers_sample": dict(list(norm.items())[:30]),
            "findings": all_findings,
            "finding_counts": severity_counts,
            "risk_score": risk_score,
            "interesting_headers": interesting,
            "missing_security_count": len(missing_security),
            "leak_header_count": len(leaking_headers),
        }

    def _check_missing_security_headers(self, norm: Dict) -> List[Dict]:
        findings = []
        for header, meta in SECURITY_HEADERS.items():
            if header.title() not in norm:
                findings.append({
                    "type": "missing_security_header",
                    "header": header,
                    "severity": meta["risk"],
                    "description": meta["description"],
                    "attack_class": meta["attack_class"],
                    "recommendation": f"Add: {header}: {meta.get('recommended', 'see OWASP guidance')}",
                })
        return findings

    def _check_weak_security_headers(self, norm: Dict) -> List[Dict]:
        findings = []

        # HSTS — check max-age value
        hsts_val = norm.get("Strict-Transport-Security", "")
        if hsts_val:
            try:
                max_age = int(
                    next(
                        (p.split("=")[1] for p in hsts_val.split(";") if "max-age" in p.lower()),
                        "0",
                    )
                )
                if max_age < 31536000:
                    findings.append({
                        "type": "weak_hsts",
                        "header": "Strict-Transport-Security",
                        "severity": "medium",
                        "description": f"HSTS max-age={max_age} is below recommended 31536000 (1 year).",
                        "current_value": hsts_val,
                        "attack_class": ["Protocol Downgrade"],
                        "recommendation": "Set max-age=31536000; includeSubDomains; preload",
                    })
                if "includesubdomains" not in hsts_val.lower():
                    findings.append({
                        "type": "weak_hsts_no_subdomains",
                        "header": "Strict-Transport-Security",
                        "severity": "low",
                        "description": "HSTS does not include subdomains — subdomain SSL strip still possible.",
                        "current_value": hsts_val,
                        "attack_class": ["SSL Stripping"],
                        "recommendation": "Add includeSubDomains directive.",
                    })
            except (ValueError, StopIteration):
                pass

        # X-Frame-Options — invalid value
        xfo_val = norm.get("X-Frame-Options", "")
        if xfo_val and xfo_val.upper() not in ["DENY", "SAMEORIGIN"]:
            findings.append({
                "type": "invalid_x_frame_options",
                "header": "X-Frame-Options",
                "severity": "medium",
                "description": f"X-Frame-Options value '{xfo_val}' is non-standard; browsers may ignore it.",
                "current_value": xfo_val,
                "attack_class": ["Clickjacking"],
                "recommendation": "Use DENY or SAMEORIGIN.",
            })

        # X-Content-Type-Options — wrong value
        xcto_val = norm.get("X-Content-Type-Options", "")
        if xcto_val and xcto_val.lower() != "nosniff":
            findings.append({
                "type": "invalid_x_content_type_options",
                "header": "X-Content-Type-Options",
                "severity": "medium",
                "description": f"X-Content-Type-Options='{xcto_val}' is not 'nosniff' — MIME sniffing not blocked.",
                "current_value": xcto_val,
                "attack_class": ["MIME Sniffing"],
                "recommendation": "Set X-Content-Type-Options: nosniff",
            })

        return findings

    def _check_leak_headers(self, norm: Dict) -> List[Dict]:
        findings = []
        for header, meta in LEAK_HEADERS.items():
            val = norm.get(header.title(), "")
            if val:
                findings.append({
                    "type": "information_disclosure",
                    "header": header,
                    "severity": meta["risk"],
                    "description": meta["description"],
                    "exposed_value": val,
                    "attack_class": meta["attack_class"],
                    "recommendation": f"Remove or suppress the '{header}' response header at the server/proxy level.",
                })
        return findings

    def _check_cors(self, norm: Dict) -> List[Dict]:
        findings = []
        acao = norm.get("Access-Control-Allow-Origin", "")
        if not acao:
            return findings

        if acao.strip() == "*":
            findings.append({
                "type": "cors_wildcard",
                "header": "Access-Control-Allow-Origin",
                "severity": "high",
                "description": "CORS wildcard (*) allows any origin to read responses — combined with "
                               "credentialed requests this enables cross-origin data theft.",
                "exposed_value": acao,
                "attack_class": ["CORS Misconfiguration", "Cross-Origin Data Theft"],
                "recommendation": "Restrict to a whitelist of trusted origins. Never combine * with credentials.",
            })

        if acao.strip().lower() == "null":
            findings.append({
                "type": "cors_null_origin",
                "header": "Access-Control-Allow-Origin",
                "severity": "high",
                "description": "ACAO: null accepted — sandboxed iframes and file:// origins can bypass SOP.",
                "exposed_value": acao,
                "attack_class": ["CORS Misconfiguration", "SOP Bypass"],
                "recommendation": "Remove null from allowed origins.",
            })

        acac = norm.get("Access-Control-Allow-Credentials", "")
        if acac.lower() == "true" and acao.strip() == "*":
            findings.append({
                "type": "cors_credentials_wildcard",
                "header": "Access-Control-Allow-Credentials",
                "severity": "critical",
                "description": "CORS credentials=true with wildcard origin — browsers block this per spec, "
                               "but misconfigured proxies may not. Full session theft if bypassed.",
                "exposed_value": f"ACAO: {acao} / ACAC: {acac}",
                "attack_class": ["Credential Theft", "Session Hijacking"],
                "recommendation": "Never combine ACAC: true with a wildcard or dynamic unvalidated origin.",
            })

        return findings

    def _check_cookies(self, norm: Dict) -> List[Dict]:
        findings = []
        set_cookie = norm.get("Set-Cookie", "")
        if not set_cookie:
            return findings

        cookies = [set_cookie] if "\n" not in set_cookie else set_cookie.split("\n")
        for cookie_str in cookies:
            low = cookie_str.lower()
            cookie_name = cookie_str.split("=")[0].strip()

            if "secure" not in low:
                findings.append({
                    "type": "cookie_missing_secure_flag",
                    "header": "Set-Cookie",
                    "severity": "medium",
                    "description": f"Cookie '{cookie_name}' lacks Secure flag — transmitted over plain HTTP.",
                    "exposed_value": cookie_str[:80],
                    "attack_class": ["Session Hijacking", "Cookie Theft"],
                    "recommendation": "Add Secure flag to all session/auth cookies.",
                })

            if "httponly" not in low:
                findings.append({
                    "type": "cookie_missing_httponly_flag",
                    "header": "Set-Cookie",
                    "severity": "medium",
                    "description": f"Cookie '{cookie_name}' lacks HttpOnly flag — accessible via document.cookie in XSS.",
                    "exposed_value": cookie_str[:80],
                    "attack_class": ["XSS Cookie Theft"],
                    "recommendation": "Add HttpOnly flag to all session/auth cookies.",
                })

            if "samesite" not in low:
                findings.append({
                    "type": "cookie_missing_samesite",
                    "header": "Set-Cookie",
                    "severity": "low",
                    "description": f"Cookie '{cookie_name}' has no SameSite attribute — CSRF attack surface open.",
                    "exposed_value": cookie_str[:80],
                    "attack_class": ["CSRF"],
                    "recommendation": "Add SameSite=Strict or SameSite=Lax.",
                })

        return findings

    def _check_csp(self, norm: Dict) -> List[Dict]:
        findings = []
        csp_val = norm.get("Content-Security-Policy", "")
        if not csp_val:
            return findings  # already caught by missing-header check

        for directive in CSP_DANGEROUS_DIRECTIVES:
            if directive in csp_val:
                findings.append({
                    "type": "weak_csp_directive",
                    "header": "Content-Security-Policy",
                    "severity": "high",
                    "description": f"CSP contains dangerous directive '{directive}' — XSS protection degraded.",
                    "exposed_value": csp_val[:200],
                    "attack_class": ["XSS", "Script Injection"],
                    "recommendation": f"Remove '{directive}' from CSP; use nonces or hashes instead.",
                })

        if "default-src" not in csp_val and "script-src" not in csp_val:
            findings.append({
                "type": "incomplete_csp",
                "header": "Content-Security-Policy",
                "severity": "medium",
                "description": "CSP present but missing default-src and script-src — partial protection only.",
                "exposed_value": csp_val[:200],
                "attack_class": ["XSS"],
                "recommendation": "Add default-src 'self' as a fallback baseline directive.",
            })

        return findings

    def _collect_interesting_headers(self, norm: Dict) -> Dict[str, str]:
        interesting_keys = {
            "X-Request-Id", "X-Correlation-Id", "X-Trace-Id",
            "X-Runtime", "X-Response-Time",
            "X-Robots-Tag", "X-Permitted-Cross-Domain-Policies",
            "Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
            "Cf-Ray", "Cf-Cache-Status",           # Cloudflare
            "X-Cache", "X-Cache-Hits",              # Varnish/CDN
            "X-Amz-Cf-Id", "X-Amz-Request-Id",    # AWS
            "X-Azure-Ref",                          # Azure
            "Nel", "Report-To",                     # Network Error Logging
        }
        return {k: v for k, v in norm.items() if k.title() in interesting_keys}

    def _calculate_risk_score(self, findings: List[Dict]) -> int:
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
        total = sum(weights.get(f.get("severity", "info"), 0) for f in findings)
        return min(100, total)

    # ------------------------------------------------------------------
    # Aggregation across targets
    # ------------------------------------------------------------------
    
    def _aggregate_findings(self, target_results: Dict) -> Dict:
        all_findings: List[Dict] = []
        severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        header_miss_freq: Dict[str, int] = {}
        leak_headers_seen: Dict[str, List[str]] = {}
        reachable_count = 0
        scores = []

        for url, result in target_results.items():
            if not result.get("reachable", True):
                continue
            reachable_count += 1
            scores.append(result.get("risk_score", 0))

            for finding in result.get("findings", []):
                all_findings.append({**finding, "source_url": url})
                sev = finding.get("severity", "info")
                severity_totals[sev] = severity_totals.get(sev, 0) + 1

                if finding["type"] == "missing_security_header":
                    h = finding["header"]
                    header_miss_freq[h] = header_miss_freq.get(h, 0) + 1

                if finding["type"] == "information_disclosure":
                    h = finding["header"]
                    val = finding.get("exposed_value", "")
                    leak_headers_seen.setdefault(h, [])
                    if val not in leak_headers_seen[h]:
                        leak_headers_seen[h].append(val)

        # Most-missed security headers (present across all targets)
        universal_misses = [
            h for h, count in header_miss_freq.items() if count == reachable_count
        ]

        avg_score = round(sum(scores) / len(scores), 1) if scores else 0
        max_score = max(scores) if scores else 0

        # Top unique attack classes across all findings
        attack_class_freq: Dict[str, int] = {}
        for f in all_findings:
            for ac in f.get("attack_class", []):
                attack_class_freq[ac] = attack_class_freq.get(ac, 0) + 1

        top_attack_classes = sorted(
            attack_class_freq.items(), key=lambda x: x[1], reverse=True
        )[:8]

        return {
            "total_findings": len(all_findings),
            "severity_counts": severity_totals,
            "average_risk_score": avg_score,
            "max_risk_score": max_score,
            "reachable_targets": reachable_count,
            "universal_missing_headers": universal_misses,
            "leaking_headers": leak_headers_seen,
            "top_attack_classes": [ac for ac, _ in top_attack_classes],
            "critical_findings": [
                f for f in all_findings if f.get("severity") == "critical"
            ],
            "high_findings": [
                f for f in all_findings if f.get("severity") == "high"
            ],
        }

    # ------------------------------------------------------------------
    # Pass 2 — AI enrichment via Groq
    # ------------------------------------------------------------------
    
    def _ai_analysis(
        self,
        domain: str,
        target_results: Dict,
        aggregate: Dict,
    ) -> Optional[Dict]:
        try:
            prompt = self._build_prompt(domain, target_results, aggregate)
            response_text = self._call_groq(prompt)
            if not response_text:
                return None
            return self._parse_ai_response(response_text)
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return None

    def _build_prompt(
        self, domain: str, target_results: Dict, aggregate: Dict
    ) -> str:
        # Condense findings to stay within token budget
        condensed_targets = []
        for url, result in list(target_results.items())[:6]:
            if not result.get("reachable", True):
                continue
            condensed_targets.append({
                "url": url,
                "risk_score": result.get("risk_score", 0),
                "status_code": result.get("status_code"),
                "critical_high_findings": [
                    {"type": f["type"], "header": f["header"], "severity": f["severity"],
                     "attack_class": f.get("attack_class", [])}
                    for f in result.get("findings", [])
                    if f.get("severity") in ("critical", "high")
                ][:6],
                "leak_headers": [
                    {"header": f["header"], "value": f.get("exposed_value", "")[:60]}
                    for f in result.get("findings", [])
                    if f["type"] == "information_disclosure"
                ][:4],
            })

        summary = {
            "domain": domain,
            "total_findings": aggregate["total_findings"],
            "severity_counts": aggregate["severity_counts"],
            "universal_missing_headers": aggregate["universal_missing_headers"],
            "top_attack_classes": aggregate["top_attack_classes"],
            "avg_risk_score": aggregate["average_risk_score"],
        }

        return f"""You are a senior offensive security engineer performing HTTP security header analysis.
Analyze the following header findings from an automated scan and return ONLY valid JSON.

Domain: {domain}
Scan Summary: {json.dumps(summary, indent=2)}
Per-Target Findings (sample): {json.dumps(condensed_targets, indent=2)}

Return a JSON object with EXACTLY these keys:
- "attack_narrative": string — 3-4 sentence description of how an attacker would chain these header weaknesses into a real attack. Be specific and technical.
- "exploit_chain": array of objects, each with "step" (int), "action" (string), "header_abused" (string), "impact" (string)
- "priority_fixes": array of objects ordered by urgency, each with "header" (string), "urgency" (critical/high/medium/low), "one_line_fix" (string)
- "hunter_notes": array of strings — 3-5 actionable recon notes for a bug bounty hunter based on what was found
- "overall_grade": one of [A, B, C, D, F] based on the header security posture
- "overall_grade_reason": string — one sentence explaining the grade

Return ONLY valid JSON. No markdown, no preamble, no trailing text."""

    def _call_groq(self, prompt: str) -> Optional[str]:
        headers = {
            "Authorization": f"Bearer {self.groq_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": "llama3-70b-8192",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.4,
            "max_tokens": 1500,
        }

        for attempt in range(3):
            try:
                self.logger.info(f"Groq API call attempt {attempt + 1}")
                resp = requests.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=45,
                )
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"]
                if resp.status_code == 429:
                    wait = 10 * (attempt + 1)
                    self.logger.warning(f"Rate limited — waiting {wait}s")
                    time.sleep(wait)
                    continue
                self.logger.error(f"Groq returned {resp.status_code}: {resp.text[:200]}")
                break
            except requests.exceptions.Timeout:
                self.logger.warning(f"Groq timeout on attempt {attempt + 1}")
                if attempt < 2:
                    time.sleep(2 ** attempt)
            except Exception as e:
                self.logger.error(f"Groq request error: {e}")
                break

        return None

    def _parse_ai_response(self, text: str) -> Optional[Dict]:
        # Strip markdown fences if model included them
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("```")[1]
            if cleaned.startswith("json"):
                cleaned = cleaned[4:]
        cleaned = cleaned.strip()

        try:
            parsed = json.loads(cleaned)
            parsed["ai_model"] = "Groq Llama3-70B"
            parsed["generated_at"] = datetime.now().isoformat()
            return parsed
        except json.JSONDecodeError:
            # Last resort — extract JSON block
            start = cleaned.find("{")
            end = cleaned.rfind("}") + 1
            if start != -1 and end > start:
                try:
                    parsed = json.loads(cleaned[start:end])
                    parsed["ai_model"] = "Groq Llama3-70B"
                    parsed["generated_at"] = datetime.now().isoformat()
                    return parsed
                except json.JSONDecodeError:
                    pass
            self.logger.error("Could not parse AI JSON response")
            return None