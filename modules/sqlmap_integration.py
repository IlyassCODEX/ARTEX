# sqlmap_integration.py
import subprocess
import shutil
import hashlib
import time
import json
import logging
import re
import requests
from datetime import datetime
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.batch_manager import TargetContext, BatchOperation

GROQ_API_KEY_ENV = __import__("os").getenv("GROQ_API_KEY", "")

# ── Hardcoded restriction list — never added to any command ──────────
_FORBIDDEN_ARGS = {
    "--dump", "--dump-all", "--os-cmd", "--os-shell",
    "--os-pwn", "--file-write", "--file-read",
    "--sql-shell", "--priv-esc", "--reg-write",
    "--passwords",   # would dump credential hashes
}

# ── Default safe profile ─────────────────────────────────────────────
_SAFE_PROFILE = [
    "--batch",          # non-interactive
    "--level=1",        # minimum test depth
    "--risk=1",         # minimum risk
    "--technique=BT",   # Boolean-based + Time-based only (no error/union/stacked)
    "--timeout=10",
    "--retries=1",
    "--threads=1",
    "--time-sec=5",
    "--max-time=60",    # hard cap: 60 seconds of active testing
    "--no-cast",
    "--output-dir=/tmp/sqlmap_artex",
]

MAX_RUNTIME_SECONDS = 90   # absolute wall-clock cap


class SQLMapIntegration:
    """
    Restricted SQLMap integration for authorised lab SQL injection assessments.

    Enforces:
        - No destructive operations (dump, os-cmd, os-shell, etc.)
        - Strict time limits
        - Actual argv capture
        - Full stdout/stderr preservation
        - AIAnalyst interpretation of results

    Usage (from AI_batch_orchestrator):
        sqli = SQLMapIntegration(groq_api_key=GROQ_API_KEY)
        result = sqli.run_assessment(url, target_ctx, batch_op)
    """

    def __init__(self, groq_api_key: str = GROQ_API_KEY_ENV):
        self.groq_api_key = groq_api_key
        self.logger       = logging.getLogger(__name__)

        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] SQLMapIntegration — %(message)s"
            ))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)

    # ------------------------------------------------------------------
    # Availability check
    # ------------------------------------------------------------------

    @staticmethod
    def is_available() -> bool:
        return shutil.which("sqlmap") is not None

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run_assessment(
        self,
        url:        str,
        target_ctx: "TargetContext",
        batch_op:   "BatchOperation",
        extra_args: Optional[List[str]] = None,
    ) -> Dict:
        """
        Run a restricted SQLMap assessment against one URL.

        Args:
            url:        Target URL with parameter(s) to test.
            target_ctx: ARTEX TargetContext for evidence attachment.
            batch_op:   BatchOperation for execution log.
            extra_args: Optional additional (safe) args. Forbidden args are stripped.

        Returns:
            {
                available:   bool,
                executed:    bool,
                command:     str,       # actual full command line
                exit_code:   int,
                stdout:      str,
                stderr:      str,
                duration_s:  float,
                injectable:  bool,
                parameters:  [str],     # found injectable params
                techniques:  [str],     # found techniques
                ai_summary:  str,
                evidence_id: str,
            }
        """
        if not self.is_available():
            self.logger.warning("sqlmap not found in PATH — skipping SQLi assessment")
            return {
                "available":  False,
                "executed":   False,
                "command":    "",
                "exit_code":  -1,
                "stdout":     "",
                "stderr":     "sqlmap not installed",
                "duration_s": 0.0,
                "injectable": False,
                "parameters": [],
                "techniques": [],
                "ai_summary": "sqlmap not available — install with: pip install sqlmap",
                "evidence_id": "",
            }

        # ── Build safe command ────────────────────────────────────────
        cmd = self._build_command(url, extra_args or [])

        # Record full command for transparency
        cmd_str = " ".join(cmd)
        self.logger.info(f"SQLMap command: {cmd_str}")

        # ── Attach to execution log ───────────────────────────────────
        evidence_id = hashlib.md5(
            f"{url}{time.time()}".encode()
        ).hexdigest()[:12]

        batch_op.log_execution({
            "evidence_id": evidence_id,
            "target_id":   target_ctx.target_id,
            "target_url":  url,
            "agent":       "sqli_agent",
            "tool":        "sqlmap",
            "operation":   "sql_injection_assessment",
            "command":     cmd_str,
            "args":        cmd[1:],
            "timestamp":   datetime.now().isoformat(),
            "status":      "running",
        })

        # ── Execute ───────────────────────────────────────────────────
        t0 = time.time()
        stdout_txt, stderr_txt, exit_code = self._execute(cmd)
        duration = round(time.time() - t0, 2)

        # ── Parse results ─────────────────────────────────────────────
        injectable, parameters, techniques = self._parse_output(stdout_txt)

        # ── AI interpretation ─────────────────────────────────────────
        ai_summary = self._ai_interpret(url, stdout_txt, injectable, parameters, techniques)

        result = {
            "available":   True,
            "executed":    True,
            "command":     cmd_str,
            "exit_code":   exit_code,
            "stdout":      stdout_txt[:5000],
            "stderr":      stderr_txt[:1000],
            "duration_s":  duration,
            "injectable":  injectable,
            "parameters":  parameters,
            "techniques":  techniques,
            "ai_summary":  ai_summary,
            "evidence_id": evidence_id,
        }

        # Update execution log entry
        batch_op.log_execution({
            "evidence_id": evidence_id,
            "target_url":  url,
            "agent":       "sqli_agent",
            "tool":        "sqlmap",
            "operation":   "sql_injection_assessment",
            "command":     cmd_str,
            "duration_s":  duration,
            "exit_code":   exit_code,
            "stdout":      stdout_txt[:2000],
            "stderr":      stderr_txt[:500],
            "status":      "completed",
            "injectable":  injectable,
            "parameters":  parameters,
        })

        target_ctx.evidence_ids.append(evidence_id)
        self.logger.info(
            f"SQLMap done — injectable={injectable}, "
            f"params={parameters}, duration={duration}s"
        )

        return result

    # ------------------------------------------------------------------
    # Command builder
    # ------------------------------------------------------------------

    def _build_command(self, url: str, extra_args: List[str]) -> List[str]:
        """Build sqlmap command — strips forbidden args, enforces safe profile."""
        # Strip any forbidden args the caller might have passed
        safe_extras = [
            a for a in extra_args
            if a.split("=")[0] not in _FORBIDDEN_ARGS
            and a not in _FORBIDDEN_ARGS
        ]

        cmd = ["sqlmap", "-u", url] + _SAFE_PROFILE + safe_extras

        # Paranoid check — walk final command and strip any forbidden arg
        cmd = [
            arg for arg in cmd
            if arg.split("=")[0] not in _FORBIDDEN_ARGS
            and arg not in _FORBIDDEN_ARGS
        ]

        return cmd

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def _execute(self, cmd: List[str]) -> tuple:
        """Run sqlmap subprocess with hard wall-clock cap."""
        try:
            proc = subprocess.run(
                cmd,
                capture_output = True,
                text           = True,
                timeout        = MAX_RUNTIME_SECONDS,
            )
            return proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired:
            self.logger.warning(f"SQLMap hit {MAX_RUNTIME_SECONDS}s wall-clock cap")
            return "", f"Killed after {MAX_RUNTIME_SECONDS}s timeout", 124
        except FileNotFoundError:
            return "", "sqlmap binary not found", 127
        except Exception as e:
            return "", str(e), -1

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_output(stdout: str) -> tuple:
        """
        Extract injection summary from sqlmap output.
        Returns (injectable: bool, parameters: list, techniques: list).
        """
        injectable = False
        parameters: List[str] = []
        techniques: List[str] = []

        if not stdout:
            return injectable, parameters, techniques

        # Injection confirmed signal
        if re.search(r"Parameter:\s+.+\s+\(", stdout, re.IGNORECASE):
            injectable = True

        # Extract parameter names
        for m in re.finditer(r"Parameter:\s+([^\s(]+)", stdout, re.IGNORECASE):
            param = m.group(1).strip()
            if param and param not in parameters:
                parameters.append(param)

        # Extract technique names
        technique_names = [
            "Boolean-based blind", "Time-based blind",
            "Error-based", "UNION query", "Stacked queries",
        ]
        for t in technique_names:
            if t.lower() in stdout.lower():
                techniques.append(t)

        # Additional confirmed line
        if "sqlmap identified the following injection point" in stdout.lower():
            injectable = True

        return injectable, parameters, techniques

    # ------------------------------------------------------------------
    # AI interpretation
    # ------------------------------------------------------------------

    def _ai_interpret(
        self,
        url:        str,
        stdout:     str,
        injectable: bool,
        parameters: List[str],
        techniques: List[str],
    ) -> str:
        """Send sqlmap output to Groq for analyst-grade summary."""
        if not self.groq_api_key:
            if injectable:
                return (
                    f"SQL injection confirmed on {url}. "
                    f"Vulnerable parameters: {', '.join(parameters) or 'unknown'}. "
                    f"Techniques: {', '.join(techniques) or 'unknown'}."
                )
            return f"No SQL injection confirmed at {url}."

        prompt = f"""You are a senior penetration tester reviewing sqlmap output.
Target: {url}
Injectable: {injectable}
Vulnerable Parameters: {parameters}
Techniques Found: {techniques}

SQLMap Output (truncated):
{stdout[:1500]}

Write a 2-3 sentence technical summary of this finding for a pentest report.
Focus on: what was found, severity, and immediate risk. No preamble."""

        try:
            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.groq_api_key}",
                    "Content-Type":  "application/json",
                },
                json={
                    "model":       "llama3-70b-8192",
                    "messages":    [{"role": "user", "content": prompt}],
                    "temperature": 0.2,
                    "max_tokens":  200,
                },
                timeout=20,
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"].strip()
        except Exception as e:
            self.logger.warning(f"AI interpretation failed: {e}")

        return f"SQLMap assessment completed. Injectable={injectable}. Parameters={parameters}."