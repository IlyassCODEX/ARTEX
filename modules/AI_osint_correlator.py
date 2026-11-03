# AI_osint_correlator.py
# optional API keys: SHODAN_API_KEY, VIRUSTOTAL_API_KEY, HUNTER_API_KEY,
#                    SECURITYTRAILS_API_KEY, GITHUB_TOKEN
# all sources degrade gracefully when key is absent — passive-only fallback always runs

import requests
import dns.resolver
import dns.exception
import socket
import json
import time
import re
import hashlib
import random
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urlparse


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PASSIVE_SOURCES = [
    "crt.sh",
    "hackertarget",
    "alienvault_otx",
    "urlscan",
    "wayback_machine",
    "common_crawl",
]

CLOUD_ASN_MAP = {
    "AS16509": "Amazon AWS",
    "AS14618": "Amazon AWS",
    "AS15169": "Google Cloud",
    "AS8075":  "Microsoft Azure",
    "AS13335": "Cloudflare",
    "AS54113": "Fastly",
    "AS20940": "Akamai",
    "AS16276": "OVH",
    "AS14061": "DigitalOcean",
    "AS63949": "Linode/Akamai",
    "AS396982": "Google Cloud",
    "AS36351": "SoftLayer/IBM",
}

INTERESTING_FILE_EXTENSIONS = [
    ".env", ".bak", ".sql", ".zip", ".tar.gz", ".config",
    ".json", ".xml", ".yml", ".yaml", ".log", ".pem", ".key",
    ".backup", ".old", ".swp", ".git", "wp-config.php",
    "phpinfo.php", "info.php", "test.php", "debug.php",
]

GITHUB_DORK_TEMPLATES = [
    '{domain} password',
    '{domain} secret',
    '{domain} api_key',
    '{domain} token',
    '{domain} credentials',
    '{domain} .env',
    '{domain} database',
    '{domain} internal',
]

SHODAN_FACETS = "org,country,port,os,product"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class AIOSINTCorrelator:
    """
    Multi-source OSINT correlation engine for ARTEX.

    Collects from up to 12 passive and semi-active sources,
    de-duplicates and cross-correlates findings, then feeds a
    condensed profile to Groq for attack surface prioritisation.

    Sources (all gracefully degrade without keys):
      Free / no-key   — crt.sh, HackerTarget, AlienVault OTX, URLScan.io,
                        Wayback Machine, CommonCrawl, ip-api.com, bgp.tools
      Shodan          — SHODAN_API_KEY
      VirusTotal      — VIRUSTOTAL_API_KEY
      Hunter.io       — HUNTER_API_KEY (email harvest)
      SecurityTrails  — SECURITYTRAILS_API_KEY
      GitHub          — GITHUB_TOKEN (secret / credential leak dork)

    Slot in run_scan() after subdomains + dns + real_ip blocks:
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
        )
    """

    def __init__(
        self,
        groq_api_key: Optional[str] = None,
        shodan_key: Optional[str] = None,
        vt_key: Optional[str] = None,
        hunter_key: Optional[str] = None,
        sectrails_key: Optional[str] = None,
        github_token: Optional[str] = None,
        timeout: int = 12,
        max_workers: int = 10,
    ):
        self.groq_api_key   = groq_api_key
        self.shodan_key     = shodan_key
        self.vt_key         = vt_key
        self.hunter_key     = hunter_key
        self.sectrails_key  = sectrails_key
        self.github_token   = github_token
        self.timeout        = timeout
        self.max_workers    = max_workers

        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
            ))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)

        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": random.choice(USER_AGENTS)
        })

        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = 4
        self._resolver.lifetime = 4

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def correlate(
        self,
        domain: str,
        scan_results: Optional[Dict] = None,
        deep: bool = False,
    ) -> Dict:
        """
        Args:
            domain:       Primary domain (e.g. "example.com").
            scan_results: Existing ARTEX scan_results dict — used to avoid
                          re-querying data already gathered (subdomains, DNS, IPs).
            deep:         If True, enables Wayback URL enumeration and
                          CommonCrawl path harvest (slower).

        Returns dict with keys:
            infrastructure    — IPs, ASN, cloud/CDN classification
            subdomains        — extended enumeration from OSINT sources
            emails            — harvested email addresses + pattern
            exposed_paths     — interesting URLs from Wayback / URLScan
            tech_signals      — banners, headers, cert subjects from Shodan/VT
            credential_leaks  — GitHub / Pastebin dork hits
            dns_intelligence  — SPF/DMARC analysis, historical DNS
            reputation        — VirusTotal domain report
            certificates      — cert transparency enrichment
            source_coverage   — which sources returned data
            ai_analysis       — Groq correlation narrative (or None)
            scan_metadata
        """
        self.logger.info(f"OSINT correlation starting — domain: {domain}")
        start = time.time()

        # Extract already-known context from existing scan results
        known_ips     = self._extract_known_ips(scan_results)
        known_subs    = self._extract_known_subs(scan_results)
        known_dns     = self._extract_known_dns(scan_results)

        # Parallel source collection
        collected: Dict[str, Dict] = {}
        tasks = {
            "crt_sh":           lambda: self._crt_sh(domain),
            "hackertarget":     lambda: self._hackertarget(domain),
            "alienvault_otx":   lambda: self._alienvault_otx(domain),
            "urlscan":          lambda: self._urlscan(domain),
            "ip_enrichment":    lambda: self._enrich_ips(domain, known_ips),
            "dns_intelligence": lambda: self._dns_intelligence(domain, known_dns),
            "email_harvest":    lambda: self._email_harvest(domain),
        }

        if self.shodan_key:
            tasks["shodan"] = lambda: self._shodan(domain, known_ips)

        if self.vt_key:
            tasks["virustotal"] = lambda: self._virustotal(domain)

        if self.sectrails_key:
            tasks["securitytrails"] = lambda: self._securitytrails(domain)

        if self.github_token or True:   # dork works without token, just rate-limited
            tasks["github_dorks"] = lambda: self._github_dorks(domain)

        if deep:
            tasks["wayback"]      = lambda: self._wayback_urls(domain)
            tasks["commoncrawl"]  = lambda: self._commoncrawl_paths(domain)

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(fn): name for name, fn in tasks.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    collected[name] = future.result() or {}
                    self.logger.info(f"Source '{name}' complete")
                except Exception as e:
                    self.logger.warning(f"Source '{name}' failed: {e}")
                    collected[name] = {"error": str(e)}

        # Cross-correlate and de-duplicate
        output = self._correlate_findings(domain, collected, known_ips, known_subs)

        # AI enrichment
        ai_result = None
        if self.groq_api_key:
            ai_result = self._ai_analysis(domain, output)

        duration = round(time.time() - start, 2)
        self.logger.info(f"OSINT correlation complete in {duration}s")

        output["ai_analysis"]   = ai_result
        output["source_coverage"] = {
            name: ("ok" if "error" not in d else f"error: {d['error']}")
            for name, d in collected.items()
        }
        output["scan_metadata"] = {
            "domain":                  domain,
            "scan_duration_seconds":   duration,
            "timestamp":               datetime.now().isoformat(),
            "deep_scan":               deep,
            "sources_queried":         len(tasks),
            "ai_model":                "Groq Llama3-70B" if ai_result else "Rule-based only",
        }

        return output

    # ------------------------------------------------------------------
    # Context extraction from existing scan_results
    # ------------------------------------------------------------------
    
    def _extract_known_ips(self, scan_results: Optional[Dict]) -> Set[str]:
        ips: Set[str] = set()
        if not scan_results:
            return ips
        for sub in scan_results.get("subdomains", []):
            if sub.get("ip"):
                ips.add(sub["ip"])
        real_ip = scan_results.get("real_ip", {})
        for ip in real_ip.get("origin_ips", []):
            ips.add(ip)
        dns = scan_results.get("dns_records", {})
        for ip in dns.get("A", []):
            ips.add(ip)
        return ips
        
    def _extract_known_subs(self, scan_results: Optional[Dict]) -> Set[str]:
        subs: Set[str] = set()
        if not scan_results:
            return subs
        for sub in scan_results.get("subdomains", []):
            name = sub.get("subdomain", "")
            if name:
                subs.add(name.lower())
        return subs
        
    def _extract_known_dns(self, scan_results: Optional[Dict]) -> Dict:
        if not scan_results:
            return {}
        return scan_results.get("dns_records", {})

    # ------------------------------------------------------------------
    # Source: crt.sh — certificate transparency
    # ------------------------------------------------------------------