# AI_subdomain_takeover_analyzer.py
import requests
import dns.resolver
import dns.exception
import socket
import json
import time
import random
import logging
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Fingerprint database — service -> (cname_patterns, body_fingerprints, notes)
# Sourced from: https://github.com/EdOverflow/can-i-take-over-xyz
# ---------------------------------------------------------------------------

TAKEOVER_FINGERPRINTS: Dict[str, Dict] = {
    "github_pages": {
        "cname_patterns": [r"\.github\.io$", r"\.github\.com$"],
        "body_fingerprints": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index",
        ],
        "status_codes": [404],
        "confidence": "high",
        "difficulty": "easy",
        "notes": "Claim by creating a GitHub Pages repo matching the subdomain.",
        "takeover_method": "Create repo <username>.github.io or set CNAME in Pages settings.",
    },
    "aws_s3": {
        "cname_patterns": [
            r"\.s3\.amazonaws\.com$",
            r"\.s3-[a-z0-9\-]+\.amazonaws\.com$",
            r"\.s3\.[a-z0-9\-]+\.amazonaws\.com$",
        ],
        "body_fingerprints": [
            "<Code>NoSuchBucket</Code>",
            "The specified bucket does not exist",
        ],
        "status_codes": [404],
        "confidence": "high",
        "difficulty": "easy",
        "notes": "Register the bucket name in any AWS account.",
        "takeover_method": "aws s3 mb s3://<bucket-name> in any AWS account, then upload content.",
    },
    "aws_elastic_beanstalk": {
        "cname_patterns": [r"\.elasticbeanstalk\.com$"],
        "body_fingerprints": [
            "404 Not Found",
            "No Application",
        ],
        "status_codes": [404],
        "confidence": "medium",
        "difficulty": "medium",
        "notes": "Requires matching region and app name.",
        "takeover_method": "Create EB environment with matching CNAME in target AWS region.",
    },
    "heroku": {
        "cname_patterns": [r"\.herokuapp\.com$", r"\.herokudns\.com$"],
        "body_fingerprints": [
            "No such app",
            "herokucdn.com/error-pages/no-such-app.html",
        ],
        "status_codes": [404],
        "confidence": "high",
        "difficulty": "easy",
        "notes": "Free tier still allows custom domains.",
        "takeover_method": "heroku create <app-name> && heroku domains:add <subdomain>",
    },
    "shopify": {
        "cname_patterns": [r"\.myshopify\.com$", r"shops\.myshopify\.com$"],
        "body_fingerprints": [
            "Sorry, this shop is currently unavailable",
            "Only one step away from your own online store",
        ],
        "status_codes": [404],
        "confidence": "high",
        "difficulty": "easy",
        "notes": "Register shop name at myshopify.com.",
        "takeover_method": "Register <name>.myshopify.com and point custom domain.",
    },
    "fastly": {
        "cname_patterns": [r"\.fastly\.net$", r"\.fastlylb\.net$"],
        "body_fingerprints": [
            "Fastly error: unknown domain",
            "Please check that this domain has been added to a service",
        ],
        "status_codes": [404],
        "confidence": "medium",
        "difficulty": "medium",
        "notes": "Requires Fastly account — domain validation needed.",
        "takeover_method": "Create Fastly service, add matching domain in Domains panel.",
    },
    "azure": {
        "cname_patterns": [
            r"\.azurewebsites\.net$",
            r"\.cloudapp\.net$",
            r"\.cloudapp\.azure\.com$",
            r"\.trafficmanager\.net$",
            r"\.blob\.core\.windows\.net$",
        ],
        "body_fingerprints": [
            "404 Web Site not found",
            "This web app has been stopped",
            "The resource you are looking for has been removed",
            "BlobNotFound",
        ],
        "status_codes": [404],
        "confidence": "high",
        "difficulty": "medium",
        "notes": "Azure resource names are global — register if available.",
        "takeover_method": "Create matching Azure resource (App Service / Blob / Traffic Manager) with identical hostname.",
    },
    "netlify": {
        "cname_patterns": [r"\.netlify\.app$", r"\.netlify\.com$"],
        "body_fingerprints": [
            "Not Found - Request ID",
            "netlify.app",
        ],
        "status_codes": [404],
        "confidence": "medium",
        "difficulty": "easy",
        "notes": "Claim site name on Netlify and add custom domain.",
        "takeover_method": "netlify sites:create --name <name>, then custom domain → <subdomain>.",
    },
    "vercel": {
        "cname_patterns": [r"\.vercel\.app$", r"\.now\.sh$"],
        "body_fingerprints": [
            "The deployment could not be found",
            "DEPLOYMENT_NOT_FOUND",
        ],
        "status_codes": [404],
        "confidence": "medium",
        "difficulty": "easy",
        "notes": "Deploy any project and map the domain.",
        "takeover_method": "vercel deploy && vercel domains add <subdomain>",
    },
    "sendgrid": {
        "cname_patterns": [r"\.sendgrid\.net$", r"em\.sendgrid\.net$"],
        "body_fingerprints": ["The CNAME record is not pointing to SendGrid"],
        "status_codes": [404],
        "confidence": "medium",
        "difficulty": "medium",
        "notes": "Email sender domain takeover — spam/phishing risk.",
        "takeover_method": "Register SendGrid account, verify the domain CNAME.",
    },
    "zendesk": {
        "cname_patterns": [r"\.zendesk\.com$"],
        "body_fingerprints": [
            "Help Center Closed",
            "This help center no longer exists",
        ],
        "status_codes": [404],
        "confidence": "medium",
        "difficulty": "medium",
        "notes": "Claim subdomain via Zendesk account.",
        "takeover_method": "Create Zendesk account, configure host mapping to <subdomain>.",
    },
    "hubspot": {
        "cname_patterns": [r"\.hs-sites\.com$", r"\.hubspot\.com$", r"\.hubspotpagebuilder\.com$"],
        "body_fingerprints": [
            "Domain not configured",
            "does not exist in our system",
        ],
        "status_codes": [404],
        "confidence": "medium",
        "difficulty": "medium",
        "notes": "HubSpot CMS subdomain takeover.",
        "takeover_method": "Create HubSpot free account, add custom domain.",
    },
    "ghost": {
        "cname_patterns": [r"\.ghost\.io$"],
        "body_fingerprints": ["The thing you were looking for is no longer here"],
        "status_codes": [404],
        "confidence": "medium",
        "difficulty": "easy",
        "notes": "Ghost CMS blog platform.",
        "takeover_method": "Register Ghost account with matching subdomain.",
    },
    "tumblr": {
        "cname_patterns": [r"\.tumblr\.com$"],
        "body_fingerprints": [
            "Whatever you were looking for doesn't currently exist at this address",
        ],
        "status_codes": [404],
        "confidence": "high",
        "difficulty": "easy",
        "notes": "Tumblr custom domain — claim blog name.",
        "takeover_method": "Create Tumblr blog, set custom domain to <subdomain>.",
    },
    "wordpress_com": {
        "cname_patterns": [r"\.wordpress\.com$"],
        "body_fingerprints": ["Do you want to register"],
        "status_codes": [404],
        "confidence": "low",
        "difficulty": "medium",
        "notes": "WordPress.com hosted site.",
        "takeover_method": "Create WordPress.com site, map custom domain.",
    },
    "surveysparrow": {
        "cname_patterns": [r"\.surveysparrow\.com$"],
        "body_fingerprints": ["Account not found"],
        "status_codes": [404],
        "confidence": "medium",
        "difficulty": "easy",
        "notes": "Survey platform subdomain.",
        "takeover_method": "Register SurveySparrow account and map domain.",
    },
    "strikingly": {
        "cname_patterns": [r"\.strikinglydns\.com$"],
        "body_fingerprints": ["page not found"],
        "status_codes": [404],
        "confidence": "medium",
        "difficulty": "easy",
        "notes": "Strikingly website builder.",
        "takeover_method": "Create Strikingly account, add custom domain.",
    },
    "readme_io": {
        "cname_patterns": [r"\.readme\.io$", r"\.readmessl\.com$"],
        "body_fingerprints": ["Project doesnt exist", "page not found"],
        "status_codes": [404],
        "confidence": "medium",
        "difficulty": "medium",
        "notes": "API documentation platform.",
        "takeover_method": "Register Readme.io project, map custom domain.",
    },
    "intercom": {
        "cname_patterns": [r"\.custom\.intercom\.help$"],
        "body_fingerprints": ["This page is reserved for", "no longer exists"],
        "status_codes": [404],
        "confidence": "medium",
        "difficulty": "medium",
        "notes": "Intercom help center subdomain.",
        "takeover_method": "Create Intercom account, configure custom domain.",
    },
    "surge_sh": {
        "cname_patterns": [r"\.surge\.sh$"],
        "body_fingerprints": ["project not found", "surge.sh"],
        "status_codes": [404],
        "confidence": "high",
        "difficulty": "easy",
        "notes": "Static site hosting — trivial to claim.",
        "takeover_method": "surge --domain <subdomain> from any local directory.",
    },
    "bitbucket": {
        "cname_patterns": [r"\.bitbucket\.io$"],
        "body_fingerprints": ["Repository not found"],
        "status_codes": [404],
        "confidence": "high",
        "difficulty": "easy",
        "notes": "Bitbucket Pages — similar to GitHub Pages.",
        "takeover_method": "Create Bitbucket repo matching the subdomain, enable Pages.",
    },
}

# NS/MX dangling check — these don't have CNAME patterns
# We check if NS/MX records point to registrar parking pages
DANGLING_NS_INDICATORS = [
    "is not a registered nameserver",
    "NXDOMAIN",
    "dns1.registrar-servers.com",
    "ns1.sedoparking.com",
    "parkingpage.namecheap.com",
]

DANGLING_MX_INDICATORS = [
    "aspmx.l.google.com",      # orphaned G Suite domain
    "mx.zoho.com",             # orphaned Zoho
    "mxext1.mailcluster.nl",
]


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class AISubdomainTakeoverAnalyzer:
    """
    Extends ARTEX subdomain takeover detection beyond the 4-service baseline.

    Pass 1 — rule-based: CNAME chain walk, NXDOMAIN dangling NS/MX check,
             HTTP body fingerprinting against 20+ services.
    Pass 2 — Groq AI: takeover priority ranking, per-finding exploit narrative,
             difficulty vs. impact matrix, hunter action list.

    slot in run_scan() after subdomains block:
        analyzer = AISubdomainTakeoverAnalyzer(groq_api_key=GROQ_API_KEY)
        scan_results[scan_id]['takeover_analysis'] = analyzer.analyze(domain, subdomains)
    """

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    ]

    def __init__(
        self,
        groq_api_key: Optional[str] = None,
        timeout: int = 8,
        max_workers: int = 20,
    ):
        self.groq_api_key = groq_api_key
        self.timeout = timeout
        self.max_workers = max_workers
        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
            ))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)

        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = 3
        self._resolver.lifetime = 3

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze(
        self,
        domain: str,
        subdomains: Optional[List[Dict]] = None,
        max_targets: int = 50,
    ) -> Dict:
        """
        Args:
            domain:      Primary domain string.
            subdomains:  List from SubdomainEnumerator — each dict has
                         'subdomain', optionally 'http_status', 'https_status', 'ip'.
            max_targets: Cap on subdomains to probe (main domain always included).

        Returns dict with keys:
            vulnerable       — confirmed/probable takeover candidates
            dangling_dns     — NXDOMAIN / unresolvable CNAME targets
            safe             — checked and clean
            scan_metadata
            ai_analysis      — Groq enrichment or None
        """
        self.logger.info(f"Takeover analysis starting — domain: {domain}")
        start = time.time()

        targets = self._build_target_list(domain, subdomains, max_targets)
        self.logger.info(f"Probing {len(targets)} targets")

        vulnerable: List[Dict] = []
        dangling: List[Dict] = []
        safe: List[Dict] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._check_target, t): t for t in targets}
            for future in as_completed(futures):
                result = future.result()
                if result is None:
                    continue
                bucket = (
                    vulnerable if result["status"] in ("vulnerable", "probable")
                    else dangling if result["status"] == "dangling"
                    else safe
                )
                bucket.append(result)

        vulnerable.sort(
            key=lambda x: (
                {"high": 3, "medium": 2, "low": 1}.get(x.get("confidence_level", "low"), 0)
            ),
            reverse=True,
        )

        ai_result = None
        if self.groq_api_key and (vulnerable or dangling):
            ai_result = self._ai_analysis(domain, vulnerable, dangling)

        duration = round(time.time() - start, 2)
        self.logger.info(
            f"Takeover analysis done in {duration}s — "
            f"{len(vulnerable)} vulnerable, {len(dangling)} dangling"
        )

        return {
            "vulnerable": vulnerable,
            "dangling_dns": dangling,
            "safe": safe,
            "summary": {
                "total_checked": len(targets),
                "vulnerable_count": len(vulnerable),
                "dangling_count": len(dangling),
                "safe_count": len(safe),
            },
            "scan_metadata": {
                "domain": domain,
                "scan_duration_seconds": duration,
                "timestamp": datetime.now().isoformat(),
                "ai_model": "Groq Llama3-70B" if ai_result else "Rule-based only",
            },
            "ai_analysis": ai_result,
        }

    # ------------------------------------------------------------------
    # Target list builder
    # ------------------------------------------------------------------

    def _build_target_list(
        self,
        domain: str,
        subdomains: Optional[List[Dict]],
        max_targets: int,
    ) -> List[str]:
        targets = [domain]
        if not subdomains:
            return targets
        seen = {domain}
        for sub in subdomains[:max_targets]:
            name = sub.get("subdomain", "").strip().lower()
            if name and name not in seen:
                targets.append(name)
                seen.add(name)
        return targets

    # ------------------------------------------------------------------
    # Per-target check — CNAME walk → fingerprint → dangling NS/MX
    # ------------------------------------------------------------------

    def _check_target(self, subdomain: str) -> Optional[Dict]:
        try:
            result: Dict = {
                "subdomain": subdomain,
                "status": "safe",
                "confidence_level": None,
                "service": None,
                "cname_chain": [],
                "dangling_reason": None,
                "takeover_method": None,
                "http_evidence": None,
                "checked_at": datetime.now().isoformat(),
            }

            # Step 1 — CNAME chain walk
            cname_chain, nxdomain_target = self._walk_cname_chain(subdomain)
            result["cname_chain"] = cname_chain

            # Step 2 — NXDOMAIN in chain = dangling pointer
            if nxdomain_target:
                result["status"] = "dangling"
                result["dangling_reason"] = (
                    f"CNAME target '{nxdomain_target}' resolves to NXDOMAIN — "
                    "dangling DNS pointer"
                )
                # Still try to fingerprint the final hop
                svc = self._match_service(nxdomain_target)
                if svc:
                    result["service"] = svc
                    fp = TAKEOVER_FINGERPRINTS[svc]
                    result["confidence_level"] = fp["confidence"]
                    result["takeover_method"] = fp["takeover_method"]
                    result["status"] = "vulnerable"
                return result

            # Step 3 — match any hop in the chain against fingerprints
            matched_service = None
            matched_cname = None
            for hop in cname_chain:
                svc = self._match_service(hop)
                if svc:
                    matched_service = svc
                    matched_cname = hop
                    break

            if not matched_service:
                # Step 4 — check dangling NS/MX even without CNAME
                dangling_info = self._check_dangling_ns_mx(subdomain)
                if dangling_info:
                    result["status"] = "dangling"
                    result["dangling_reason"] = dangling_info
                return result

            # Step 5 — HTTP body fingerprint to confirm
            fp_data = TAKEOVER_FINGERPRINTS[matched_service]
            http_evidence = self._http_fingerprint(subdomain, fp_data)

            result["service"] = matched_service
            result["matched_cname"] = matched_cname
            result["takeover_method"] = fp_data["takeover_method"]
            result["difficulty"] = fp_data["difficulty"]
            result["service_notes"] = fp_data["notes"]

            if http_evidence["confirmed"]:
                result["status"] = "vulnerable"
                result["confidence_level"] = fp_data["confidence"]
                result["http_evidence"] = http_evidence
            else:
                # CNAME matched but body didn't confirm — still probable
                result["status"] = "probable"
                result["confidence_level"] = "low"
                result["http_evidence"] = http_evidence

            return result

        except Exception as e:
            self.logger.debug(f"Check failed for {subdomain}: {e}")
            return None

    # ------------------------------------------------------------------
    # DNS helpers
    # ------------------------------------------------------------------

    def _walk_cname_chain(
        self, subdomain: str, depth: int = 10
    ) -> Tuple[List[str], Optional[str]]:
        """
        Recursively walk CNAME chain.
        Returns (chain_list, nxdomain_hop_or_None).
        """
        chain: List[str] = []
        current = subdomain
        seen: set = set()

        for _ in range(depth):
            if current in seen:
                break
            seen.add(current)
            try:
                answers = self._resolver.resolve(current, "CNAME")
                target = str(answers[0].target).rstrip(".")
                chain.append(target)
                current = target
            except dns.resolver.NXDOMAIN:
                # The current node itself doesn't exist
                if chain:
                    return chain, current
                return chain, None
            except dns.resolver.NoAnswer:
                # No more CNAME — this is an A/AAAA record, chain ends normally
                break
            except dns.exception.DNSException:
                break

        return chain, None

    def _match_service(self, cname: str) -> Optional[str]:
        for service, fp in TAKEOVER_FINGERPRINTS.items():
            for pattern in fp["cname_patterns"]:
                if re.search(pattern, cname, re.IGNORECASE):
                    return service
        return None

    def _check_dangling_ns_mx(self, subdomain: str) -> Optional[str]:
        # Check NS
        try:
            ns_answers = self._resolver.resolve(subdomain, "NS")
            for rdata in ns_answers:
                ns = str(rdata.target).rstrip(".")
                try:
                    self._resolver.resolve(ns, "A")
                except dns.resolver.NXDOMAIN:
                    return f"NS record '{ns}' resolves to NXDOMAIN — nameserver dangling"
                except dns.exception.DNSException:
                    pass
        except dns.exception.DNSException:
            pass

        # Check MX
        try:
            mx_answers = self._resolver.resolve(subdomain, "MX")
            for rdata in mx_answers:
                mx = str(rdata.exchange).rstrip(".")
                try:
                    self._resolver.resolve(mx, "A")
                except dns.resolver.NXDOMAIN:
                    return f"MX record '{mx}' resolves to NXDOMAIN — mail exchanger dangling"
                except dns.exception.DNSException:
                    pass
        except dns.exception.DNSException:
            pass

        return None

    # ------------------------------------------------------------------
    # HTTP body fingerprint
    # ------------------------------------------------------------------

    def _http_fingerprint(self, subdomain: str, fp_data: Dict) -> Dict:
        evidence = {
            "confirmed": False,
            "status_code": None,
            "matched_body_pattern": None,
            "url_checked": None,
        }

        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                resp = requests.get(
                    url,
                    headers={"User-Agent": random.choice(self.USER_AGENTS)},
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )
                evidence["status_code"] = resp.status_code
                evidence["url_checked"] = url

                # Check status code match
                if resp.status_code in fp_data.get("status_codes", [404]):
                    # Check body fingerprint
                    for body_pattern in fp_data.get("body_fingerprints", []):
                        if body_pattern.lower() in resp.text.lower():
                            evidence["confirmed"] = True
                            evidence["matched_body_pattern"] = body_pattern
                            return evidence

                return evidence  # got a response but no body match

            except requests.exceptions.SSLError:
                continue
            except requests.exceptions.ConnectionError:
                break
            except requests.exceptions.Timeout:
                break
            except Exception:
                break

        return evidence

    # ------------------------------------------------------------------
    # Pass 2 — Groq AI enrichment
    # ------------------------------------------------------------------

    def _ai_analysis(
        self,
        domain: str,
        vulnerable: List[Dict],
        dangling: List[Dict],
    ) -> Optional[Dict]:
        try:
            prompt = self._build_prompt(domain, vulnerable, dangling)
            response_text = self._call_groq(prompt)
            if not response_text:
                return None
            return self._parse_ai_response(response_text)
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return None

    def _build_prompt(
        self,
        domain: str,
        vulnerable: List[Dict],
        dangling: List[Dict],
    ) -> str:
        # Condense to stay in token budget
        vuln_condensed = [
            {
                "subdomain": v["subdomain"],
                "service": v.get("service"),
                "confidence": v.get("confidence_level"),
                "difficulty": v.get("difficulty"),
                "cname_chain": v.get("cname_chain", [])[:3],
                "confirmed_by_body": v.get("http_evidence", {}).get("confirmed", False),
                "takeover_method": v.get("takeover_method"),
            }
            for v in vulnerable[:10]
        ]

        dangling_condensed = [
            {
                "subdomain": d["subdomain"],
                "dangling_reason": d.get("dangling_reason"),
                "cname_chain": d.get("cname_chain", [])[:3],
            }
            for d in dangling[:10]
        ]

        return f"""You are a senior offensive security researcher specialising in subdomain takeover attacks.
Analyze the following takeover findings for {domain} and return ONLY valid JSON.

Confirmed/Probable Vulnerable Subdomains:
{json.dumps(vuln_condensed, indent=2)}

Dangling DNS Records (no service matched yet):
{json.dumps(dangling_condensed, indent=2)}

Return a JSON object with EXACTLY these keys:
- "executive_summary": string — 2-3 sentences on the overall takeover risk posture.
- "priority_targets": array of objects ordered by exploit ease × impact, each with:
    "subdomain" (string), "why_priority" (string), "estimated_effort" (easy/medium/hard),
    "potential_impact" (string — e.g. phishing, session theft, malware delivery).
- "attack_scenarios": array of objects, each with:
    "scenario_name" (string), "steps" (array of strings), "impact" (string).
    Cover at least: phishing via email subdomain, session cookie theft via HTTPS takeover,
    malware delivery via asset subdomain — only include scenarios relevant to found targets.
- "dangling_investigation_tips": array of strings — how to manually confirm and exploit
    the dangling records that didn't match a known service fingerprint.
- "hunter_notes": array of strings — 3-5 practical notes for a bug bounty report.
- "overall_severity": one of [critical, high, medium, low, info].

Return ONLY valid JSON. No markdown fences, no preamble."""

    def _call_groq(self, prompt: str) -> Optional[str]:
        headers = {
            "Authorization": f"Bearer {self.groq_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": "llama3-70b-8192",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.35,
            "max_tokens": 1600,
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
            parsed["ai_model"] = "Groq Llama3-70B"
            parsed["generated_at"] = datetime.now().isoformat()
            return parsed
        except json.JSONDecodeError:
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