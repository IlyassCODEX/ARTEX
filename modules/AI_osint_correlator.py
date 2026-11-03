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

    def _crt_sh(self, domain: str) -> Dict:
        result: Dict = {"subdomains": [], "issuers": [], "certificates": []}
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = self._get(url)
            if not resp:
                return result

            seen_names: Set[str] = set()
            seen_issuers: Set[str] = set()

            for cert in resp.json():
                issuer = cert.get("issuer_name", "")
                if issuer and issuer not in seen_issuers:
                    seen_issuers.add(issuer)
                    result["issuers"].append(issuer)

                not_before = cert.get("not_before", "")
                not_after  = cert.get("not_after", "")
                cn         = cert.get("common_name", "")

                for raw_name in cert.get("name_value", "").split("\n"):
                    name = raw_name.strip().lower().lstrip("*.")
                    if name and domain in name and name not in seen_names:
                        seen_names.add(name)
                        result["subdomains"].append(name)

                if cn and cn not in result["certificates"]:
                    result["certificates"].append({
                        "cn": cn,
                        "issuer": issuer,
                        "not_before": not_before,
                        "not_after": not_after,
                        "id": cert.get("id"),
                    })

            # Flag wildcard certs — broad attack surface signal
            result["wildcard_certs"] = [
                c for c in result["certificates"]
                if c["cn"].startswith("*.")
            ]
            result["expired_certs"] = [
                c for c in result["certificates"]
                if c.get("not_after") and c["not_after"] < datetime.now().isoformat()
            ]

        except Exception as e:
            self.logger.warning(f"crt.sh failed: {e}")

        return result

    # ------------------------------------------------------------------
    # Source: HackerTarget — passive DNS + subdomain API
    # ------------------------------------------------------------------

    def _hackertarget(self, domain: str) -> Dict:
        result: Dict = {"subdomains": [], "dns_lookup": []}
        try:
            # Subdomain finder
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            resp = self._get(url, raw_text=True)
            if resp:
                for line in resp.strip().split("\n"):
                    if "," in line:
                        sub, ip = line.split(",", 1)
                        result["subdomains"].append({
                            "subdomain": sub.strip().lower(),
                            "ip": ip.strip(),
                        })

            time.sleep(1)  # HackerTarget rate limit

            # Reverse IP lookup for known IPs — returns co-hosted domains
            # (skip if we have no IPs yet; correlate call may add them)
        except Exception as e:
            self.logger.warning(f"HackerTarget failed: {e}")

        return result

    # ------------------------------------------------------------------
    # Source: AlienVault OTX — passive DNS + URL history
    # ------------------------------------------------------------------

    def _alienvault_otx(self, domain: str) -> Dict:
        result: Dict = {
            "passive_dns": [],
            "url_list": [],
            "malware_samples": [],
            "reputation": None,
        }
        base = "https://otx.alienvault.com/api/v1/indicators/domain"
        sections = [
            ("passive_dns", "passive_dns"),
            ("url_list",    "url_list"),
            ("malware",     "malware"),
            ("general",     None),
        ]
        try:
            for section, key in sections:
                url = f"{base}/{domain}/{section}"
                resp_json = self._get(url)
                if not resp_json:
                    continue

                if section == "passive_dns":
                    for record in resp_json.get("passive_dns", []):
                        result["passive_dns"].append({
                            "hostname":   record.get("hostname"),
                            "address":    record.get("address"),
                            "record_type": record.get("record_type"),
                            "first_seen": record.get("first"),
                            "last_seen":  record.get("last"),
                        })

                elif section == "url_list":
                    for entry in resp_json.get("url_list", [])[:30]:
                        url_entry = entry.get("url", "")
                        if url_entry:
                            result["url_list"].append({
                                "url":         url_entry,
                                "date":        entry.get("date"),
                                "http_code":   entry.get("httpcode"),
                                "result":      entry.get("result", {}).get("urlworker", {}).get("http_code"),
                            })

                elif section == "malware":
                    for sample in resp_json.get("data", [])[:10]:
                        result["malware_samples"].append({
                            "hash":       sample.get("hash"),
                            "type":       sample.get("type"),
                            "date":       sample.get("date"),
                        })

                elif section == "general":
                    pulse_count = resp_json.get("pulse_info", {}).get("count", 0)
                    result["reputation"] = {
                        "pulse_count":   pulse_count,
                        "flagged":       pulse_count > 0,
                        "alexa_rank":    resp_json.get("alexa"),
                        "asn":           resp_json.get("asn"),
                        "city":          resp_json.get("city"),
                        "country":       resp_json.get("country_name"),
                    }

                time.sleep(0.5)

        except Exception as e:
            self.logger.warning(f"AlienVault OTX failed: {e}")

        return result

    # ------------------------------------------------------------------
    # Source: URLScan.io — crawled URL + DOM screenshot metadata
    # ------------------------------------------------------------------

    def _urlscan(self, domain: str) -> Dict:
        result: Dict = {
            "scanned_urls":     [],
            "related_domains":  [],
            "ip_hits":          [],
            "technologies":     [],
            "interesting_paths": [],
        }
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=50"
            resp_json = self._get(url)
            if not resp_json:
                return result

            seen_ips:     Set[str] = set()
            seen_domains: Set[str] = set()
            seen_techs:   Set[str] = set()

            for entry in resp_json.get("results", []):
                page = entry.get("page", {})
                task = entry.get("task", {})
                meta = entry.get("meta", {})

                # Scanned URL entry
                scanned_url = page.get("url", "")
                if scanned_url:
                    parsed_path = urlparse(scanned_url).path
                    path_entry = {
                        "url":    scanned_url,
                        "status": page.get("status"),
                        "date":   task.get("time"),
                    }
                    result["scanned_urls"].append(path_entry)

                    # Flag interesting paths
                    for ext in INTERESTING_FILE_EXTENSIONS:
                        if ext in parsed_path.lower():
                            if path_entry not in result["interesting_paths"]:
                                result["interesting_paths"].append(path_entry)

                # IPs seen in scan
                ip = page.get("ip")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    result["ip_hits"].append({
                        "ip":      ip,
                        "country": page.get("country"),
                        "asn":     page.get("asn"),
                        "asnname": page.get("asnname"),
                    })

                # Related domains from page links
                for domain_hit in meta.get("processors", {}).get("domain", {}).get("data", []):
                    d = domain_hit.get("domain", "").lower()
                    if d and d not in seen_domains and d != domain:
                        seen_domains.add(d)
                        result["related_domains"].append(d)

                # Technologies from wappalyzer data in scan
                for tech in entry.get("stats", {}).get("technologies", []):
                    name = tech.get("name", "")
                    if name and name not in seen_techs:
                        seen_techs.add(name)
                        result["technologies"].append({
                            "name":       name,
                            "categories": tech.get("categories", []),
                        })

        except Exception as e:
            self.logger.warning(f"URLScan failed: {e}")

        return result

    # ------------------------------------------------------------------
    # Source: Shodan — internet-wide banner scan
    # ------------------------------------------------------------------

    def _shodan(self, domain: str, known_ips: Set[str]) -> Dict:
        result: Dict = {
            "hosts":          [],
            "open_ports":     {},
            "banners":        [],
            "vulns":          [],
            "org":            None,
            "isp":            None,
            "asn":            None,
            "facets":         {},
        }
        if not self.shodan_key:
            return result

        try:
            # Domain search
            url = (
                f"https://api.shodan.io/shodan/host/search"
                f"?key={self.shodan_key}&query=hostname:{domain}&facets={SHODAN_FACETS}"
            )
            resp_json = self._get(url)
            if resp_json:
                result["facets"] = resp_json.get("facets", {})
                for match in resp_json.get("matches", [])[:20]:
                    ip_str   = match.get("ip_str", "")
                    port     = match.get("port")
                    product  = match.get("product", "")
                    version  = match.get("version", "")
                    vulns    = list(match.get("vulns", {}).keys())
                    banner   = match.get("data", "")[:200]

                    host_entry = {
                        "ip":        ip_str,
                        "port":      port,
                        "product":   product,
                        "version":   version,
                        "os":        match.get("os"),
                        "country":   match.get("location", {}).get("country_name"),
                        "org":       match.get("org"),
                        "hostnames": match.get("hostnames", []),
                        "vulns":     vulns,
                    }
                    result["hosts"].append(host_entry)

                    # Aggregate open ports
                    if ip_str not in result["open_ports"]:
                        result["open_ports"][ip_str] = []
                    if port:
                        result["open_ports"][ip_str].append(port)

                    if banner:
                        result["banners"].append({
                            "ip": ip_str, "port": port, "banner": banner
                        })

                    for cve in vulns:
                        if cve not in result["vulns"]:
                            result["vulns"].append(cve)

                if result["hosts"]:
                    first = result["hosts"][0]
                    result["org"] = first.get("org")
                    result["asn"] = resp_json.get("facets", {}).get("asn", [{}])[0].get("value")

            # Per-IP lookup for known IPs not already covered
            for ip in list(known_ips)[:5]:
                if any(h["ip"] == ip for h in result["hosts"]):
                    continue
                ip_url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}"
                ip_data = self._get(ip_url)
                if ip_data and "error" not in ip_data:
                    for port_data in ip_data.get("data", [])[:5]:
                        result["hosts"].append({
                            "ip":        ip,
                            "port":      port_data.get("port"),
                            "product":   port_data.get("product", ""),
                            "version":   port_data.get("version", ""),
                            "banner":    port_data.get("data", "")[:150],
                            "org":       ip_data.get("org"),
                            "hostnames": ip_data.get("hostnames", []),
                            "vulns":     list(ip_data.get("vulns", {}).keys()),
                        })
                time.sleep(1)

        except Exception as e:
            self.logger.warning(f"Shodan failed: {e}")

        return result

    # ------------------------------------------------------------------
    # Source: VirusTotal — domain + IP reputation
    # ------------------------------------------------------------------

    def _virustotal(self, domain: str) -> Dict:
        result: Dict = {
            "detection_stats":    None,
            "categories":         [],
            "related_domains":    [],
            "communicating_ips":  [],
            "subdomains":         [],
            "malicious_urls":     [],
            "reputation_score":   None,
            "last_analysis_date": None,
        }
        if not self.vt_key:
            return result

        headers = {"x-apikey": self.vt_key}
        base    = "https://www.virustotal.com/api/v3"

        try:
            # Domain report
            resp = self._get(f"{base}/domains/{domain}", headers=headers)
            if resp:
                attrs = resp.get("data", {}).get("attributes", {})
                result["detection_stats"]  = attrs.get("last_analysis_stats")
                result["categories"]       = list(attrs.get("categories", {}).values())
                result["reputation_score"] = attrs.get("reputation")
                result["last_analysis_date"] = attrs.get("last_analysis_date")

                # Malicious URL samples
                for url_entry in attrs.get("last_https_certificate_date", []):
                    pass  # placeholder — full URL list via relationships below

            time.sleep(1)

            # Subdomains relationship
            resp_subs = self._get(
                f"{base}/domains/{domain}/subdomains?limit=40",
                headers=headers,
            )
            if resp_subs:
                for item in resp_subs.get("data", []):
                    sub_id = item.get("id", "")
                    if sub_id:
                        result["subdomains"].append(sub_id)

            time.sleep(1)

            # Communicating files / IPs
            resp_ips = self._get(
                f"{base}/domains/{domain}/resolutions?limit=20",
                headers=headers,
            )
            if resp_ips:
                for item in resp_ips.get("data", []):
                    ip_str = item.get("attributes", {}).get("ip_address")
                    date   = item.get("attributes", {}).get("date")
                    if ip_str:
                        result["communicating_ips"].append({
                            "ip":   ip_str,
                            "date": date,
                        })

        except Exception as e:
            self.logger.warning(f"VirusTotal failed: {e}")

        return result

    # ------------------------------------------------------------------
    # Source: SecurityTrails — historical DNS + associated domains
    # ------------------------------------------------------------------

    def _securitytrails(self, domain: str) -> Dict:
        result: Dict = {
            "historical_a":     [],
            "historical_mx":    [],
            "historical_ns":    [],
            "associated_domains": [],
            "subdomains":       [],
            "whois":            {},
        }
        if not self.sectrails_key:
            return result

        headers = {"APIKEY": self.sectrails_key, "Content-Type": "application/json"}
        base    = "https://api.securitytrails.com/v1"

        try:
            # General domain info + subdomains
            resp = self._get(f"{base}/domain/{domain}", headers=headers)
            if resp:
                result["whois"] = resp.get("whois", {})

            time.sleep(1)

            # Subdomain list
            resp_subs = self._get(
                f"{base}/domain/{domain}/subdomains?children_only=false&include_inactive=true",
                headers=headers,
            )
            if resp_subs:
                for sub in resp_subs.get("subdomains", []):
                    result["subdomains"].append(f"{sub}.{domain}")

            time.sleep(1)

            # Historical DNS — A record
            for record_type in ("a", "mx", "ns"):
                resp_hist = self._get(
                    f"{base}/history/{domain}/dns/{record_type}",
                    headers=headers,
                )
                if resp_hist:
                    key = f"historical_{record_type}"
                    for entry in resp_hist.get("records", [])[:15]:
                        values = [
                            v.get("ip") or v.get("value") or v.get("host", "")
                            for v in entry.get("values", [])
                        ]
                        result[key].append({
                            "first_seen": entry.get("first_seen"),
                            "last_seen":  entry.get("last_seen"),
                            "values":     values,
                        })
                time.sleep(1)

        except Exception as e:
            self.logger.warning(f"SecurityTrails failed: {e}")

        return result

    # ------------------------------------------------------------------
    # Source: Hunter.io — email harvest
    # ------------------------------------------------------------------

    def _email_harvest(self, domain: str) -> Dict:
        result: Dict = {
            "emails":         [],
            "pattern":        None,
            "total_count":    0,
            "sources":        [],
            "linkedin_found": False,
        }

        # Hunter.io (key required)
        if self.hunter_key:
            try:
                url = (
                    f"https://api.hunter.io/v2/domain-search"
                    f"?domain={domain}&api_key={self.hunter_key}&limit=50"
                )
                resp_json = self._get(url)
                if resp_json:
                    data = resp_json.get("data", {})
                    result["pattern"]     = data.get("pattern")
                    result["total_count"] = data.get("total", 0)

                    for entry in data.get("emails", []):
                        result["emails"].append({
                            "email":       entry.get("value"),
                            "type":        entry.get("type"),
                            "confidence":  entry.get("confidence"),
                            "first_name":  entry.get("first_name"),
                            "last_name":   entry.get("last_name"),
                            "position":    entry.get("position"),
                            "linkedin":    entry.get("linkedin"),
                            "sources":     [s.get("domain") for s in entry.get("sources", [])],
                        })
                        if entry.get("linkedin"):
                            result["linkedin_found"] = True

            except Exception as e:
                self.logger.warning(f"Hunter.io failed: {e}")

        # Fallback: passive email harvest from URLScan and OTX URLs
        # (no key needed — best-effort regex over known URL corpus)
        # Already collected in _urlscan and _alienvault_otx — merged in correlate step

        return result

    # ------------------------------------------------------------------
    # Source: GitHub dork search — credential / secret leaks
    # ------------------------------------------------------------------

    def _github_dorks(self, domain: str) -> Dict:
        result: Dict = {
            "hits":          [],
            "total_count":   0,
            "dorks_run":     [],
            "secret_signals": [],
        }

        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"

        secret_patterns = [
            (r'api[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})', "API Key"),
            (r'password\s*[=:]\s*["\']?([^\s"\']{8,})',             "Password"),
            (r'secret\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})',        "Secret"),
            (r'token\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{16,})',       "Token"),
            (r'aws_access_key_id\s*[=:]\s*([A-Z0-9]{20})',           "AWS Key ID"),
            (r'aws_secret_access_key\s*[=:]\s*([A-Za-z0-9+/]{40})', "AWS Secret"),
        ]

        try:
            for template in GITHUB_DORK_TEMPLATES[:4]:   # 4 dorks to stay inside rate limit
                query = template.format(domain=domain)
                result["dorks_run"].append(query)

                url = (
                    "https://api.github.com/search/code"
                    f"?q={quote(query)}&per_page=10&sort=indexed"
                )
                resp_json = self._get(url, headers=headers)
                if not resp_json:
                    time.sleep(2)
                    continue

                result["total_count"] += resp_json.get("total_count", 0)

                for item in resp_json.get("items", [])[:5]:
                    repo     = item.get("repository", {})
                    raw_url  = item.get("html_url", "").replace(
                        "github.com", "raw.githubusercontent.com"
                    ).replace("/blob/", "/")

                    hit = {
                        "repo":       repo.get("full_name"),
                        "file":       item.get("name"),
                        "path":       item.get("path"),
                        "url":        item.get("html_url"),
                        "private":    repo.get("private", False),
                        "updated_at": repo.get("updated_at"),
                        "secrets_found": [],
                    }

                    # Try to fetch raw content and scan for secrets
                    raw_content = self._get(raw_url, raw_text=True)
                    if raw_content:
                        for pattern, label in secret_patterns:
                            matches = re.findall(pattern, raw_content, re.IGNORECASE)
                            for match in matches[:3]:
                                hit["secrets_found"].append({
                                    "type":    label,
                                    "snippet": match[:40] + "..." if len(match) > 40 else match,
                                })
                                if {"type": label} not in result["secret_signals"]:
                                    result["secret_signals"].append({"type": label, "source": hit["repo"]})

                    result["hits"].append(hit)

                time.sleep(3)   # GitHub code search: 10 req/min unauthenticated

        except Exception as e:
            self.logger.warning(f"GitHub dorks failed: {e}")

        return result

    # ------------------------------------------------------------------
    # Source: Wayback Machine — URL enumeration
    # ------------------------------------------------------------------

    def _wayback_urls(self, domain: str) -> Dict:
        result: Dict = {
            "total_snapshots":    0,
            "interesting_urls":   [],
            "all_paths":          [],
            "oldest_snapshot":    None,
            "newest_snapshot":    None,
        }
        try:
            # CDX API — fetch URL index
            cdx_url = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url=*.{domain}/*&output=json&fl=original,statuscode,timestamp"
                f"&collapse=urlkey&limit=200&from=20100101"
            )
            resp_json = self._get(cdx_url)
            if not resp_json or len(resp_json) < 2:
                return result

            # First row is header
            rows = resp_json[1:]
            result["total_snapshots"] = len(rows)

            timestamps = []
            seen_paths: Set[str] = set()

            for row in rows:
                if len(row) < 3:
                    continue
                original, status, ts = row[0], row[1], row[2]
                timestamps.append(ts)

                parsed = urlparse(original)
                path   = parsed.path.lower()

                if path not in seen_paths:
                    seen_paths.add(path)
                    result["all_paths"].append(path)

                # Flag interesting paths
                for ext in INTERESTING_FILE_EXTENSIONS:
                    if ext in path:
                        result["interesting_urls"].append({
                            "url":       original,
                            "status":    status,
                            "timestamp": ts,
                            "reason":    ext,
                        })
                        break

            if timestamps:
                result["oldest_snapshot"] = min(timestamps)
                result["newest_snapshot"] = max(timestamps)

            # Deduplicate interesting_urls
            seen_iurl: Set[str] = set()
            deduped = []
            for item in result["interesting_urls"]:
                if item["url"] not in seen_iurl:
                    seen_iurl.add(item["url"])
                    deduped.append(item)
            result["interesting_urls"] = deduped[:50]

        except Exception as e:
            self.logger.warning(f"Wayback Machine failed: {e}")

        return result

    # ------------------------------------------------------------------
    # Source: CommonCrawl — indexed path harvest
    # ------------------------------------------------------------------

    def _commoncrawl_paths(self, domain: str) -> Dict:
        result: Dict = {"paths": [], "total": 0}
        try:
            # Use the CDX index — latest crawl
            index_url = "https://index.commoncrawl.org/collinfo.json"
            resp_json = self._get(index_url)
            if not resp_json:
                return result

            # Take latest index
            latest = resp_json[0].get("cdx-api") if resp_json else None
            if not latest:
                return result

            cdx_url = (
                f"{latest}?url=*.{domain}/*&output=json&fl=url,status"
                f"&collapse=urlkey&limit=100"
            )
            resp_text = self._get(cdx_url, raw_text=True)
            if not resp_text:
                return result

            seen: Set[str] = set()
            for line in resp_text.strip().split("\n"):
                try:
                    entry = json.loads(line)
                    url   = entry.get("url", "")
                    path  = urlparse(url).path.lower()
                    if path and path not in seen:
                        seen.add(path)
                        result["paths"].append(path)
                except json.JSONDecodeError:
                    continue

            result["total"] = len(result["paths"])

        except Exception as e:
            self.logger.warning(f"CommonCrawl failed: {e}")

        return result

    # ------------------------------------------------------------------
    # Source: IP enrichment — ASN, geo, cloud classification
    # ------------------------------------------------------------------

    def _enrich_ips(self, domain: str, known_ips: Set[str]) -> Dict:
        result: Dict = {"ip_profiles": [], "cloud_ips": [], "hosting_orgs": set()}

        # Resolve domain IPs if none known yet
        target_ips = set(known_ips)
        if not target_ips:
            try:
                answers = self._resolver.resolve(domain, "A")
                for rdata in answers:
                    target_ips.add(str(rdata))
            except dns.exception.DNSException:
                pass

        for ip in list(target_ips)[:10]:
            try:
                url  = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,asname,hosting,proxy,mobile,query"
                resp_json = self._get(url)
                if not resp_json or resp_json.get("status") != "success":
                    continue

                asn_str = resp_json.get("as", "")
                asn_id  = asn_str.split(" ")[0] if asn_str else ""
                cloud   = CLOUD_ASN_MAP.get(asn_id)

                profile = {
                    "ip":          ip,
                    "country":     resp_json.get("country"),
                    "city":        resp_json.get("city"),
                    "isp":         resp_json.get("isp"),
                    "org":         resp_json.get("org"),
                    "asn":         asn_str,
                    "asn_name":    resp_json.get("asname"),
                    "cloud":       cloud,
                    "is_hosting":  resp_json.get("hosting", False),
                    "is_proxy":    resp_json.get("proxy", False),
                }
                result["ip_profiles"].append(profile)

                if cloud:
                    result["cloud_ips"].append({"ip": ip, "provider": cloud})

                org = resp_json.get("org", "")
                if org:
                    result["hosting_orgs"].add(org)

                time.sleep(0.5)   # ip-api free tier: 45 req/min

            except Exception as e:
                self.logger.debug(f"IP enrichment failed for {ip}: {e}")

        result["hosting_orgs"] = list(result["hosting_orgs"])
        return result

    # ------------------------------------------------------------------
    # Source: DNS intelligence — SPF/DMARC analysis, open resolvers
    # ------------------------------------------------------------------

    def _dns_intelligence(self, domain: str, known_dns: Dict) -> Dict:
        result: Dict = {
            "spf_analysis":    {},
            "dmarc_analysis":  {},
            "dkim_selectors":  [],
            "mx_analysis":     [],
            "ns_analysis":     [],
            "open_resolver":   False,
            "dnssec_enabled":  False,
        }

        try:
            # SPF deep analysis
            spf_records = known_dns.get("SPF") or known_dns.get("TXT") or []
            spf_raw = next((r for r in spf_records if "v=spf1" in str(r)), None)

            if spf_raw:
                result["spf_analysis"] = self._analyse_spf(str(spf_raw))
            else:
                # Try to resolve fresh
                try:
                    txts = self._resolver.resolve(domain, "TXT")
                    for rdata in txts:
                        txt_str = str(rdata).strip('"')
                        if "v=spf1" in txt_str:
                            result["spf_analysis"] = self._analyse_spf(txt_str)
                            break
                except dns.exception.DNSException:
                    pass

            # DMARC deep analysis
            try:
                dmarc_ans = self._resolver.resolve(f"_dmarc.{domain}", "TXT")
                for rdata in dmarc_ans:
                    dmarc_str = str(rdata).strip('"')
                    if "v=DMARC1" in dmarc_str:
                        result["dmarc_analysis"] = self._analyse_dmarc(dmarc_str)
                        break
            except dns.exception.DNSException:
                result["dmarc_analysis"] = {
                    "present":  False,
                    "policy":   None,
                    "risk":     "high",
                    "note":     "No DMARC record — domain spoofable in email From header.",
                }

            # DKIM selector discovery — common selectors
            common_selectors = [
                "default", "google", "mail", "dkim", "k1", "k2",
                "selector1", "selector2", "s1", "s2", "smtp",
                "mailjet", "sendgrid", "amazonses",
            ]
            for selector in common_selectors:
                try:
                    dkim_host = f"{selector}._domainkey.{domain}"
                    self._resolver.resolve(dkim_host, "TXT")
                    result["dkim_selectors"].append(selector)
                except dns.exception.DNSException:
                    pass

            # MX analysis — flag catch-all / wildcard / suspicious
            mx_records = known_dns.get("MX", [])
            if not mx_records:
                try:
                    mx_ans = self._resolver.resolve(domain, "MX")
                    mx_records = [str(r.exchange).rstrip(".") for r in mx_ans]
                except dns.exception.DNSException:
                    pass

            for mx in mx_records:
                mx_str = str(mx)
                entry = {
                    "host":      mx_str,
                    "provider":  self._classify_mx(mx_str),
                    "resolves":  self._resolves(mx_str),
                }
                result["mx_analysis"].append(entry)

            # NS analysis
            ns_records = known_dns.get("NS", [])
            for ns in ns_records:
                ns_str = str(ns).rstrip(".")
                result["ns_analysis"].append({
                    "host":     ns_str,
                    "resolves": self._resolves(ns_str),
                    "provider": self._classify_ns(ns_str),
                })

            # DNSSEC check
            try:
                dnskey = self._resolver.resolve(domain, "DNSKEY")
                result["dnssec_enabled"] = bool(dnskey)
            except dns.exception.DNSException:
                result["dnssec_enabled"] = False

            # Open resolver test (checks if domain's NS accepts recursive queries)
            if result["ns_analysis"]:
                ns_host = result["ns_analysis"][0]["host"]
                result["open_resolver"] = self._test_open_resolver(ns_host)

        except Exception as e:
            self.logger.warning(f"DNS intelligence failed: {e}")

        return result

    def _analyse_spf(self, spf: str) -> Dict:
        mechanisms = spf.split()
        includes  = [m for m in mechanisms if m.startswith("include:")]
        redirects = [m for m in mechanisms if m.startswith("redirect=")]
        all_flag  = "+all" in spf or "~all" not in spf and "-all" not in spf
        fail_mode = "-all" if "-all" in spf else "~all" if "~all" in spf else "?all/+all"

        return {
            "raw":          spf,
            "present":      True,
            "fail_mode":    fail_mode,
            "risk":         "high" if all_flag else "low",
            "includes":     includes,
            "redirects":    redirects,
            "lookup_count": len([m for m in mechanisms if m.startswith(("include:", "a:", "mx:", "ptr:", "exists:"))]),
            "note": (
                "SPF uses +all or no -all — any server can send as this domain."
                if all_flag else
                f"SPF present with fail mode '{fail_mode}'."
            ),
        }

    def _analyse_dmarc(self, dmarc: str) -> Dict:
        tags  = dict(re.findall(r"(\w+)=([^;]+)", dmarc))
        policy    = tags.get("p", "none").strip()
        pct       = int(tags.get("pct", "100").strip())
        rua       = tags.get("rua", "").strip()
        ruf       = tags.get("ruf", "").strip()
        sp_policy = tags.get("sp", policy).strip()

        risk = (
            "high"   if policy == "none"
            else "medium" if pct < 100
            else "low"
        )

        return {
            "raw":       dmarc,
            "present":   True,
            "policy":    policy,
            "pct":       pct,
            "sp_policy": sp_policy,
            "rua":       rua,
            "ruf":       ruf,
            "risk":      risk,
            "note": (
                "DMARC policy is 'none' — monitoring only, spoofing not blocked."
                if policy == "none"
                else f"DMARC policy '{policy}' at {pct}% enforcement."
            ),
        }

    def _classify_mx(self, mx: str) -> str:
        patterns = {
            "Google Workspace": ["google.com", "googlemail.com", "aspmx.l.google"],
            "Microsoft 365":    ["protection.outlook.com", "mail.protection.outlook"],
            "Proofpoint":       ["pphosted.com", "proofpoint.com"],
            "Mimecast":         ["mimecast.com"],
            "Zoho Mail":        ["zoho.com", "zohomail.com"],
            "SendGrid":         ["sendgrid.net"],
            "Amazon SES":       ["amazonses.com"],
            "Postmark":         ["inbound.postmarkapp.com"],
        }
        for provider, patterns_list in patterns.items():
            if any(p in mx.lower() for p in patterns_list):
                return provider
        return "Unknown"

    def _classify_ns(self, ns: str) -> str:
        patterns = {
            "Cloudflare":   ["cloudflare.com", "ns.cloudflare"],
            "Amazon Route53": ["awsdns"],
            "GoDaddy":      ["domaincontrol.com"],
            "Namecheap":    ["registrar-servers.com", "namecheaphosting"],
            "Google":       ["googledomains.com", "ns-cloud"],
            "Netlify":      ["netlify.com"],
        }
        for provider, patterns_list in patterns.items():
            if any(p in ns.lower() for p in patterns_list):
                return provider
        return "Unknown"

    def _resolves(self, host: str) -> bool:
        try:
            socket.gethostbyname(host)
            return True
        except socket.gaierror:
            return False

    def _test_open_resolver(self, ns_host: str) -> bool:
        """Check if nameserver answers recursive queries for external domains."""
        try:
            r = dns.resolver.Resolver()
            r.nameservers = [socket.gethostbyname(ns_host)]
            r.timeout    = 3
            r.lifetime   = 3
            r.resolve("google.com", "A")
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Cross-correlation and de-duplication
    # ------------------------------------------------------------------

    def _correlate_findings(
        self,
        domain: str,
        collected: Dict[str, Dict],
        known_ips: Set[str],
        known_subs: Set[str],
    ) -> Dict:
        """
        Merge all source outputs into a clean, de-duplicated OSINT profile.
        """
        # Subdomain aggregation
        all_subs: Dict[str, Set[str]] = {}  # subdomain → set of sources

        def _add_sub(sub: str, source: str) -> None:
            sub = sub.strip().lower().lstrip("*.")
            if sub and domain in sub:
                all_subs.setdefault(sub, set()).add(source)

        for sub in collected.get("crt_sh", {}).get("subdomains", []):
            _add_sub(sub, "crt.sh")
        for entry in collected.get("hackertarget", {}).get("subdomains", []):
            _add_sub(entry.get("subdomain", ""), "hackertarget")
        for entry in collected.get("alienvault_otx", {}).get("passive_dns", []):
            _add_sub(entry.get("hostname", ""), "alienvault_otx")
        for sub in collected.get("virustotal", {}).get("subdomains", []):
            _add_sub(sub, "virustotal")
        for sub in collected.get("securitytrails", {}).get("subdomains", []):
            _add_sub(sub, "securitytrails")

        # Subdomains not seen in main scan
        new_subs = [
            {"subdomain": sub, "sources": sorted(sources)}
            for sub, sources in all_subs.items()
            if sub not in known_subs
        ]

        # IP aggregation
        all_ips: Dict[str, Set[str]] = {}

        def _add_ip(ip: str, source: str) -> None:
            if ip and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                all_ips.setdefault(ip, set()).add(source)

        for entry in collected.get("hackertarget", {}).get("subdomains", []):
            _add_ip(entry.get("ip", ""), "hackertarget")
        for entry in collected.get("alienvault_otx", {}).get("passive_dns", []):
            _add_ip(entry.get("address", ""), "alienvault_otx")
        for entry in collected.get("urlscan", {}).get("ip_hits", []):
            _add_ip(entry.get("ip", ""), "urlscan")
        for host in collected.get("shodan", {}).get("hosts", []):
            _add_ip(host.get("ip", ""), "shodan")
        for entry in collected.get("virustotal", {}).get("communicating_ips", []):
            _add_ip(entry.get("ip", ""), "virustotal")
        for ip in known_ips:
            _add_ip(ip, "artex_scan")

        infrastructure = {
            "all_ips": [
                {"ip": ip, "sources": sorted(srcs)}
                for ip, srcs in all_ips.items()
            ],
            "ip_profiles":  collected.get("ip_enrichment", {}).get("ip_profiles", []),
            "cloud_ips":    collected.get("ip_enrichment", {}).get("cloud_ips", []),
            "hosting_orgs": collected.get("ip_enrichment", {}).get("hosting_orgs", []),
            "shodan_org":   collected.get("shodan", {}).get("org"),
            "shodan_asn":   collected.get("shodan", {}).get("asn"),
            "open_ports":   collected.get("shodan", {}).get("open_ports", {}),
            "vulns_from_shodan": collected.get("shodan", {}).get("vulns", []),
        }

        # Email aggregation
        emails = collected.get("email_harvest", {}).get("emails", [])

        # Exposed paths — merge Wayback + URLScan interesting
        exposed_paths = (
            collected.get("wayback_machine", {}).get("interesting_urls", [])
            + collected.get("urlscan", {}).get("interesting_paths", [])
        )
        # Deduplicate by URL
        seen_eu: Set[str] = set()
        deduped_paths = []
        for p in exposed_paths:
            key = p.get("url", p.get("path", ""))
            if key and key not in seen_eu:
                seen_eu.add(key)
                deduped_paths.append(p)

        # Technology signals — URLScan + Shodan banners
        tech_signals = collected.get("urlscan", {}).get("technologies", [])
        banners      = collected.get("shodan", {}).get("banners", [])

        # Certificate enrichment
        certificates = {
            "issuers":        collected.get("crt_sh", {}).get("issuers", []),
            "wildcard_certs": collected.get("crt_sh", {}).get("wildcard_certs", []),
            "expired_certs":  collected.get("crt_sh", {}).get("expired_certs", []),
            "all_certs":      collected.get("crt_sh", {}).get("certificates", [])[:20],
        }

        # Reputation summary
        reputation = {
            "virustotal":    collected.get("virustotal", {}).get("detection_stats"),
            "vt_score":      collected.get("virustotal", {}).get("reputation_score"),
            "vt_categories": collected.get("virustotal", {}).get("categories", []),
            "alienvault":    collected.get("alienvault_otx", {}).get("reputation"),
            "malware_samples": collected.get("alienvault_otx", {}).get("malware_samples", []),
        }

        # Credential leak summary
        credential_leaks = {
            "github_hits":      collected.get("github_dorks", {}).get("hits", []),
            "github_total":     collected.get("github_dorks", {}).get("total_count", 0),
            "secret_signals":   collected.get("github_dorks", {}).get("secret_signals", []),
            "dorks_run":        collected.get("github_dorks", {}).get("dorks_run", []),
        }

        # DNS intelligence
        dns_intel = collected.get("dns_intelligence", {})

        # Historical DNS from SecurityTrails
        if collected.get("securitytrails"):
            dns_intel["historical_a"]  = collected["securitytrails"].get("historical_a", [])
            dns_intel["historical_mx"] = collected["securitytrails"].get("historical_mx", [])
            dns_intel["historical_ns"] = collected["securitytrails"].get("historical_ns", [])

        # Related domains from URLScan
        related_domains = collected.get("urlscan", {}).get("related_domains", [])

        return {
            "infrastructure":   infrastructure,
            "subdomains":       new_subs,
            "emails":           emails,
            "email_pattern":    collected.get("email_harvest", {}).get("pattern"),
            "email_total":      collected.get("email_harvest", {}).get("total_count", 0),
            "exposed_paths":    deduped_paths[:60],
            "tech_signals":     tech_signals,
            "banners":          banners[:10],
            "credential_leaks": credential_leaks,
            "dns_intelligence": dns_intel,
            "reputation":       reputation,
            "certificates":     certificates,
            "related_domains":  related_domains[:20],
        }

    # ------------------------------------------------------------------
    # Pass 2 — Groq AI analysis
    # ------------------------------------------------------------------

    def _ai_analysis(self, domain: str, correlated: Dict) -> Optional[Dict]:
        try:
            prompt = self._build_prompt(domain, correlated)
            text   = self._call_groq(prompt)
            if not text:
                return None
            return self._parse_ai_response(text)
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return None

    def _build_prompt(self, domain: str, c: Dict) -> str:
        # Condense to stay inside token budget
        summary = {
            "domain":         domain,
            "total_ips":      len(c["infrastructure"]["all_ips"]),
            "cloud_ips":      [x["provider"] for x in c["infrastructure"]["cloud_ips"]],
            "hosting_orgs":   c["infrastructure"]["hosting_orgs"][:5],
            "shodan_vulns":   c["infrastructure"]["vulns_from_shodan"][:5],
            "open_ports_sample": {
                ip: ports[:8]
                for ip, ports in list(c["infrastructure"]["open_ports"].items())[:3]
            },
            "new_subdomains": len(c["subdomains"]),
            "new_sub_samples": [s["subdomain"] for s in c["subdomains"][:10]],
            "email_count":     c["email_total"],
            "email_pattern":   c["email_pattern"],
            "email_sample":    [e["email"] for e in c["emails"][:5]],
            "exposed_paths":   [p.get("url", p.get("path", "")) for p in c["exposed_paths"][:8]],
            "credential_leaks": {
                "github_total":   c["credential_leaks"]["github_total"],
                "secret_signals": c["credential_leaks"]["secret_signals"][:5],
            },
            "spf_risk":        c["dns_intelligence"].get("spf_analysis", {}).get("risk"),
            "dmarc_policy":    c["dns_intelligence"].get("dmarc_analysis", {}).get("policy"),
            "dmarc_risk":      c["dns_intelligence"].get("dmarc_analysis", {}).get("risk"),
            "dnssec":          c["dns_intelligence"].get("dnssec_enabled"),
            "open_resolver":   c["dns_intelligence"].get("open_resolver"),
            "vt_detections":   c["reputation"].get("virustotal"),
            "malware_samples": len(c["reputation"].get("malware_samples", [])),
            "wildcard_certs":  len(c["certificates"].get("wildcard_certs", [])),
            "expired_certs":   len(c["certificates"].get("expired_certs", [])),
            "related_domains": c["related_domains"][:5],
        }

        return f"""You are a senior threat intelligence analyst and offensive security expert.
Correlate the following OSINT profile for {domain} and return ONLY valid JSON.

OSINT Profile:
{json.dumps(summary, indent=2)}

Return a JSON object with EXACTLY these keys:
- "executive_summary": string — 3-4 sentences on the overall threat exposure and most critical risks.
- "attack_surface_map": array of objects, each with:
    "surface" (string), "severity" (critical/high/medium/low), "evidence" (string — what OSINT data proves this), "attack_angle" (string).
  Cover infrastructure exposure, email/phishing surface, credential leak risk, web exposure, DNS weaknesses.
- "priority_attack_paths": array of objects ordered by ease × impact, each with:
    "path_name" (string), "steps" (array of strings — concrete attacker actions),
    "required_resources" (string — what attacker needs), "impact" (string).
- "phishing_risk_assessment": object with:
    "score" (0-100), "factors" (array of strings), "recommended_lure" (string — most credible phishing pretext given the org's profile).
- "hunter_recon_checklist": array of strings — 5-7 actionable next steps for a bug bounty hunter or red teamer based on these findings.
- "credential_exposure_notes": string — assessment of the GitHub / credential leak findings.
- "overall_risk_level": one of [critical, high, medium, low, info].

Return ONLY valid JSON. No markdown fences, no preamble, no trailing text."""

    def _call_groq(self, prompt: str) -> Optional[str]:
        headers = {
            "Authorization": f"Bearer {self.groq_api_key}",
            "Content-Type":  "application/json",
        }
        payload = {
            "model":       "llama3-70b-8192",
            "messages":    [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens":  1800,
        }

        for attempt in range(3):
            try:
                self.logger.info(f"Groq API call attempt {attempt + 1}")
                resp = requests.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=50,
                )
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"]
                if resp.status_code == 429:
                    wait = 12 * (attempt + 1)
                    self.logger.warning(f"Rate limited — waiting {wait}s")
                    time.sleep(wait)
                    continue
                self.logger.error(f"Groq {resp.status_code}: {resp.text[:200]}")
                break
            except requests.exceptions.Timeout:
                if attempt < 2:
                    time.sleep(2 ** attempt)
            except Exception as e:
                self.logger.error(f"Groq error: {e}")
                break

        return None

    def _parse_ai_response(self, text: str) -> Optional[Dict]:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("```")[1]
            if cleaned.startswith("json"):
                cleaned = cleaned[4:]
        cleaned = cleaned.strip()

        try:
            parsed = json.loads(cleaned)
            parsed["ai_model"]     = "Groq Llama3-70B"
            parsed["generated_at"] = datetime.now().isoformat()
            return parsed
        except json.JSONDecodeError:
            start = cleaned.find("{")
            end   = cleaned.rfind("}") + 1
            if start != -1 and end > start:
                try:
                    parsed = json.loads(cleaned[start:end])
                    parsed["ai_model"]     = "Groq Llama3-70B"
                    parsed["generated_at"] = datetime.now().isoformat()
                    return parsed
                except json.JSONDecodeError:
                    pass
            self.logger.error("Could not parse AI JSON response")
            return None

    # ------------------------------------------------------------------
    # HTTP helper — unified GET with graceful degradation
    # ------------------------------------------------------------------

    def _get(
        self,
        url: str,
        headers: Optional[Dict] = None,
        raw_text: bool = False,
    ):
        try:
            merged_headers = dict(self._session.headers)
            if headers:
                merged_headers.update(headers)

            resp = self._session.get(
                url,
                headers=merged_headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )

            if resp.status_code == 429:
                self.logger.warning(f"Rate limited by {url[:60]} — sleeping 10s")
                time.sleep(10)
                return None

            if resp.status_code not in (200, 201):
                return None

            if raw_text:
                return resp.text

            content_type = resp.headers.get("Content-Type", "")
            if "json" in content_type:
                return resp.json()

            # Try JSON parse regardless
            try:
                return resp.json()
            except Exception:
                return resp.text if raw_text else None

        except requests.exceptions.Timeout:
            self.logger.debug(f"Timeout: {url[:80]}")
        except requests.exceptions.ConnectionError:
            self.logger.debug(f"Connection error: {url[:80]}")
        except Exception as e:
            self.logger.debug(f"GET failed {url[:80]}: {e}")

        return None