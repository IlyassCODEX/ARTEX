# batch_manager.py
import uuid
import threading
import time
import re
import hashlib
import ipaddress
import logging
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from typing import Dict, List, Optional, Set, Callable, Tuple
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TARGET_STATUS = {
    "pending":    "pending",
    "running":    "running",
    "completed":  "completed",
    "failed":     "failed",
    "skipped":    "skipped",
    "timeout":    "timeout",
    "cancelled":  "cancelled",
}

BATCH_STATUS = {
    "created":    "created",
    "running":    "running",
    "completed":  "completed",
    "failed":     "failed",
    "stopped":    "stopped",
    "cancelled":  "cancelled",
}

# Private/reserved ranges that must not be targeted without explicit lab flag
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

MAX_URLS_PER_BATCH    = 500
DEFAULT_CONCURRENCY   = 3
MAX_CONCURRENCY       = 10
DEFAULT_TARGET_TIMEOUT = 600    # 10 min per target
DEFAULT_BATCH_TIMEOUT  = 7200   # 2 hours total
MAX_RETRIES           = 1


# ---------------------------------------------------------------------------
# Target model
# ---------------------------------------------------------------------------

class TargetContext:
    """Independent state container for one target URL."""

    __slots__ = (
        "target_id", "url", "domain", "scheme", "port",
        "status", "progress", "current_task",
        "start_time", "end_time", "duration",
        "retry_count", "error",
        "scan_results", "scan_status_data",
        "evidence_ids", "findings_count", "highest_severity",
        "technologies", "web_server", "framework",
        "ai_decision_log",
    )

    def __init__(self, url: str):
        parsed        = urlparse(url if "://" in url else f"https://{url}")
        self.target_id    = hashlib.md5(url.encode()).hexdigest()[:12]
        self.url          = url
        self.domain       = parsed.netloc or parsed.path.split("/")[0]
        self.scheme       = parsed.scheme or "https"
        self.port         = parsed.port
        self.status       = TARGET_STATUS["pending"]
        self.progress     = 0
        self.current_task = "Pending"
        self.start_time:  Optional[datetime] = None
        self.end_time:    Optional[datetime] = None
        self.duration:    Optional[str]      = None
        self.retry_count  = 0
        self.error:       Optional[str]      = None
        self.scan_results: Dict              = {}
        self.scan_status_data: Dict          = {}
        self.evidence_ids: List[str]         = []
        self.findings_count  = 0
        self.highest_severity: Optional[str] = None
        self.technologies:    List[str]      = []
        self.web_server:      Optional[str]  = None
        self.framework:       Optional[str]  = None
        self.ai_decision_log: List[Dict]     = []

    def mark_running(self) -> None:
        self.status     = TARGET_STATUS["running"]
        self.start_time = datetime.now()

    def mark_done(self, status: str, error: Optional[str] = None) -> None:
        self.status   = status
        self.end_time = datetime.now()
        self.error    = error
        if self.start_time:
            secs = (self.end_time - self.start_time).total_seconds()
            m, s = divmod(int(secs), 60)
            self.duration = f"{m}m {s}s"

    def to_dict(self) -> Dict:
        return {
            "target_id":        self.target_id,
            "url":              self.url,
            "domain":           self.domain,
            "status":           self.status,
            "progress":         self.progress,
            "current_task":     self.current_task,
            "start_time":       self.start_time.isoformat() if self.start_time else None,
            "end_time":         self.end_time.isoformat()   if self.end_time   else None,
            "duration":         self.duration,
            "retry_count":      self.retry_count,
            "error":            self.error,
            "findings_count":   self.findings_count,
            "highest_severity": self.highest_severity,
            "technologies":     self.technologies,
            "web_server":       self.web_server,
            "framework":        self.framework,
            "ai_decision_log":  self.ai_decision_log[-5:],   # last 5 entries only
        }


# ---------------------------------------------------------------------------
# Batch model
# ---------------------------------------------------------------------------

class BatchOperation:
    """State container for one complete batch run."""

    def __init__(
        self,
        batch_id:    str,
        filename:    str,
        targets:     List[TargetContext],
        options:     Dict,
    ):
        self.batch_id     = batch_id
        self.filename     = filename
        self.targets      = targets                       # ordered list
        self.target_map   = {t.target_id: t for t in targets}
        self.options      = options
        self.status       = BATCH_STATUS["created"]
        self.created_at   = datetime.now()
        self.start_time:  Optional[datetime] = None
        self.end_time:    Optional[datetime] = None
        self.duration:    Optional[str]      = None
        self._stop_event  = threading.Event()
        self.execution_log: List[Dict] = []
        self.consolidated_findings: List[Dict] = []

    @property
    def total(self)      -> int: return len(self.targets)
    @property
    def completed(self)  -> int: return sum(1 for t in self.targets if t.status == TARGET_STATUS["completed"])
    @property
    def running(self)    -> int: return sum(1 for t in self.targets if t.status == TARGET_STATUS["running"])
    @property
    def failed(self)     -> int: return sum(1 for t in self.targets if t.status in (TARGET_STATUS["failed"], TARGET_STATUS["timeout"]))
    @property
    def pending(self)    -> int: return sum(1 for t in self.targets if t.status == TARGET_STATUS["pending"])
    @property
    def progress(self)   -> int:
        if not self.targets: return 0
        done = sum(1 for t in self.targets if t.status not in (TARGET_STATUS["pending"], TARGET_STATUS["running"]))
        return int((done / len(self.targets)) * 100)
    @property
    def stop_requested(self) -> bool: return self._stop_event.is_set()

    def stop(self) -> None:
        self._stop_event.set()
        self.status = BATCH_STATUS["stopped"]

    def log_execution(self, entry: Dict) -> None:
        entry.setdefault("timestamp", datetime.now().isoformat())
        entry["batch_id"] = self.batch_id
        self.execution_log.append(entry)

    def to_dict(self) -> Dict:
        return {
            "batch_id":    self.batch_id,
            "filename":    self.filename,
            "status":      self.status,
            "created_at":  self.created_at.isoformat(),
            "start_time":  self.start_time.isoformat() if self.start_time else None,
            "end_time":    self.end_time.isoformat()   if self.end_time   else None,
            "duration":    self.duration,
            "total":       self.total,
            "completed":   self.completed,
            "running":     self.running,
            "failed":      self.failed,
            "pending":     self.pending,
            "progress":    self.progress,
            "targets":     [t.to_dict() for t in self.targets],
            "execution_log_count": len(self.execution_log),
        }


# ---------------------------------------------------------------------------
# BatchManager
# ---------------------------------------------------------------------------

class BatchManager:
    """
    Manages the full lifecycle of a batch assessment operation.

    Responsibilities (only):
        - Parse and validate TXT file
        - Normalise URLs, detect duplicates
        - Validate scope (allowlist / private-range protection)
        - Create BatchOperation and TargetContext objects
        - Schedule and execute targets concurrently via ThreadPoolExecutor
        - Enforce per-target and global timeouts
        - Isolate failures — one target crash does not stop the batch
        - Provide emergency stop
        - Persist batch/target state for the dashboard

    AI decision logic lives entirely in AI_batch_orchestrator.py.
    """

    def __init__(
        self,
        concurrency:      int  = DEFAULT_CONCURRENCY,
        target_timeout:   int  = DEFAULT_TARGET_TIMEOUT,
        batch_timeout:    int  = DEFAULT_BATCH_TIMEOUT,
        allow_private:    bool = False,
        allowed_domains:  Optional[List[str]] = None,
    ):
        self.concurrency     = min(max(1, concurrency), MAX_CONCURRENCY)
        self.target_timeout  = target_timeout
        self.batch_timeout   = batch_timeout
        self.allow_private   = allow_private
        self.allowed_domains = [d.lower() for d in (allowed_domains or [])]

        self._batches: Dict[str, BatchOperation] = {}
        self._lock    = threading.Lock()
        self.logger   = logging.getLogger(__name__)

        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] BatchManager — %(message)s"
            ))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)

    # ------------------------------------------------------------------
    # TXT file parsing
    # ------------------------------------------------------------------

    def parse_txt_file(self, content: str) -> Dict:
        """
        Parse raw TXT file content into a validated URL set.

        Returns:
            {
                valid_urls:   [str],
                invalid_urls: [str],
                duplicates:   [str],
                total_lines:  int,
                parse_errors: [str],
            }
        """
        lines       = content.splitlines()
        seen:       Set[str]  = set()
        valid:      List[str] = []
        invalid:    List[str] = []
        duplicates: List[str] = []
        errors:     List[str] = []

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Normalise — ensure scheme present
            url, err = self._normalise_url(line)
            if err:
                invalid.append(line)
                errors.append(f"Line '{line[:60]}': {err}")
                continue

            # Duplicate check (by normalised URL)
            canon = url.lower().rstrip("/")
            if canon in seen:
                duplicates.append(url)
                continue
            seen.add(canon)

            if len(valid) >= MAX_URLS_PER_BATCH:
                errors.append(f"Batch limit {MAX_URLS_PER_BATCH} reached — remaining URLs skipped.")
                break

            valid.append(url)

        return {
            "valid_urls":   valid,
            "invalid_urls": invalid,
            "duplicates":   duplicates,
            "total_lines":  len(lines),
            "parse_errors": errors,
        }

    @staticmethod
    def _normalise_url(raw: str) -> Tuple[str, Optional[str]]:
        """Return (normalised_url, error_string_or_None)."""
        url = raw.strip()
        if not url:
            return "", "Empty line"

        # Add scheme if missing
        if not re.match(r"^https?://", url, re.IGNORECASE):
            url = "https://" + url

        try:
            parsed = urlparse(url)
        except Exception as e:
            return "", f"URL parse error: {e}"

        netloc = parsed.netloc.lower()
        if not netloc:
            return "", "No host found"

        # Strip port for validation
        host = netloc.split(":")[0]

        # Basic hostname pattern
        hostname_re = re.compile(
            r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
        )
        ip_re = re.compile(
            r"^(\d{1,3}\.){3}\d{1,3}$"
        )

        if not hostname_re.match(host) and not ip_re.match(host) and host != "localhost":
            return "", f"Invalid hostname: {host}"

        return url, None

    # ------------------------------------------------------------------
    # Scope validation
    # ------------------------------------------------------------------

    def validate_scope(self, url: str) -> Tuple[bool, str]:
        """
        Returns (is_allowed, reason).
        Blocks private IP ranges unless allow_private=True.
        Enforces domain allowlist when configured.
        """
        try:
            parsed = urlparse(url)
            host   = parsed.netloc.split(":")[0].lower()

            # IP address check
            try:
                ip = ipaddress.ip_address(host)
                if not self.allow_private:
                    for private_range in _PRIVATE_RANGES:
                        if ip in private_range:
                            return False, f"Private IP {host} blocked (enable allow_private for lab use)"
            except ValueError:
                pass   # it's a hostname, not an IP

            # Allowlist check
            if self.allowed_domains:
                if not any(host == d or host.endswith("." + d) for d in self.allowed_domains):
                    return False, f"Domain {host} not in allowed_domains list"

            return True, "ok"

        except Exception as e:
            return False, str(e)

    # ------------------------------------------------------------------
    # Batch creation
    # ------------------------------------------------------------------

    def create_batch(
        self,
        txt_content:    str,
        filename:       str = "targets.txt",
        options:        Optional[Dict] = None,
    ) -> Tuple[Optional[BatchOperation], Dict]:
        """
        Parse TXT file, validate scope, create BatchOperation.

        Returns:
            (batch_operation_or_None, parse_report_dict)
        """
        parse_report = self.parse_txt_file(txt_content)
        options      = options or {}

        in_scope: List[str] = []
        out_scope: List[str] = []

        for url in parse_report["valid_urls"]:
            allowed, reason = self.validate_scope(url)
            if allowed:
                in_scope.append(url)
            else:
                out_scope.append(url)
                parse_report["parse_errors"].append(f"Out of scope: {url} — {reason}")

        parse_report["in_scope_count"]  = len(in_scope)
        parse_report["out_scope_count"] = len(out_scope)
        parse_report["out_scope_urls"]  = out_scope

        if not in_scope:
            return None, parse_report

        targets   = [TargetContext(url) for url in in_scope]
        batch_id  = str(uuid.uuid4())
        batch_op  = BatchOperation(batch_id, filename, targets, options)

        with self._lock:
            self._batches[batch_id] = batch_op

        self.logger.info(f"Batch {batch_id} created — {len(targets)} targets")
        return batch_op, parse_report

    # ------------------------------------------------------------------
    # Execution engine
    # ------------------------------------------------------------------

    def run_batch(
        self,
        batch_id:  str,
        worker_fn: Callable[[TargetContext, BatchOperation], None],
    ) -> None:
        """
        Execute the batch using ThreadPoolExecutor.

        Args:
            batch_id:  Batch to run.
            worker_fn: Callable(target_ctx, batch_op) — provided by AI_batch_orchestrator.
                       The manager calls this for each target; the orchestrator handles logic.
        """
        batch = self._batches.get(batch_id)
        if not batch:
            raise ValueError(f"Batch {batch_id} not found")

        batch.status     = BATCH_STATUS["running"]
        batch.start_time = datetime.now()
        self.logger.info(f"Batch {batch_id} starting — concurrency={self.concurrency}")

        futures: Dict[Future, TargetContext] = {}
        batch_deadline = time.time() + self.batch_timeout

        try:
            with ThreadPoolExecutor(
                max_workers=self.concurrency,
                thread_name_prefix=f"batch_{batch_id[:8]}",
            ) as pool:

                for target in batch.targets:
                    if batch.stop_requested:
                        target.mark_done(TARGET_STATUS["cancelled"])
                        continue
                    if time.time() > batch_deadline:
                        target.mark_done(TARGET_STATUS["cancelled"])
                        self.logger.warning(f"Batch timeout — skipping {target.url}")
                        continue

                    future = pool.submit(
                        self._run_target_safe,
                        target, batch, worker_fn,
                    )
                    futures[future] = target

                for future in as_completed(futures, timeout=self.batch_timeout):
                    target = futures[future]
                    try:
                        future.result()
                    except Exception as exc:
                        # Failure isolation — log and continue
                        target.mark_done(TARGET_STATUS["failed"], str(exc))
                        self.logger.error(f"Target {target.url} raised: {exc}")
                        batch.log_execution({
                            "event":    "target_exception",
                            "target":   target.url,
                            "error":    str(exc),
                        })

        except Exception as exc:
            self.logger.error(f"Batch executor error: {exc}")
            batch.status = BATCH_STATUS["failed"]
        finally:
            batch.end_time = datetime.now()
            secs = (batch.end_time - batch.start_time).total_seconds()
            m, s = divmod(int(secs), 60)
            h, m = divmod(m, 60)
            batch.duration = f"{h}h {m}m {s}s"

            if batch.status not in (BATCH_STATUS["stopped"], BATCH_STATUS["failed"]):
                batch.status = BATCH_STATUS["completed"]

            self.logger.info(
                f"Batch {batch_id} done — "
                f"{batch.completed}/{batch.total} completed, "
                f"{batch.failed} failed in {batch.duration}"
            )

    def _run_target_safe(
        self,
        target:    TargetContext,
        batch:     BatchOperation,
        worker_fn: Callable,
    ) -> None:
        """Run one target with per-target timeout and retry logic."""
        if batch.stop_requested:
            target.mark_done(TARGET_STATUS["cancelled"])
            return

        target.mark_running()
        attempt = 0

        while attempt <= MAX_RETRIES:
            try:
                # Timeout via threading.Timer — raises in worker after deadline
                timer = threading.Timer(
                    self.target_timeout,
                    lambda t=target: self._timeout_target(t),
                )
                timer.start()
                try:
                    worker_fn(target, batch)
                finally:
                    timer.cancel()

                if target.status != TARGET_STATUS["timeout"]:
                    target.mark_done(TARGET_STATUS["completed"])
                return

            except Exception as exc:
                attempt += 1
                target.retry_count = attempt
                self.logger.warning(
                    f"Target {target.url} attempt {attempt} failed: {exc}"
                )
                if attempt > MAX_RETRIES:
                    target.mark_done(TARGET_STATUS["failed"], str(exc))
                    return
                time.sleep(2 ** attempt)   # brief back-off before retry

    @staticmethod
    def _timeout_target(target: TargetContext) -> None:
        target.status       = TARGET_STATUS["timeout"]
        target.current_task = "Timed out"
        target.error        = f"Target timeout after assessment window"

    # ------------------------------------------------------------------
    # Control interface
    # ------------------------------------------------------------------

    def stop_batch(self, batch_id: str) -> bool:
        batch = self._batches.get(batch_id)
        if not batch:
            return False
        batch.stop()
        self.logger.info(f"Stop requested for batch {batch_id}")
        return True

    # ------------------------------------------------------------------
    # State access
    # ------------------------------------------------------------------

    def get_batch(self, batch_id: str) -> Optional[BatchOperation]:
        return self._batches.get(batch_id)

    def get_batch_status(self, batch_id: str) -> Optional[Dict]:
        batch = self._batches.get(batch_id)
        return batch.to_dict() if batch else None

    def get_target(self, batch_id: str, target_id: str) -> Optional[TargetContext]:
        batch = self._batches.get(batch_id)
        return batch.target_map.get(target_id) if batch else None

    def list_batches(self) -> List[Dict]:
        with self._lock:
            return [
                {
                    "batch_id":  b.batch_id,
                    "filename":  b.filename,
                    "status":    b.status,
                    "total":     b.total,
                    "completed": b.completed,
                    "failed":    b.failed,
                    "progress":  b.progress,
                    "created_at": b.created_at.isoformat(),
                }
                for b in self._batches.values()
            ]

    def get_execution_log(self, batch_id: str, limit: int = 100) -> List[Dict]:
        batch = self._batches.get(batch_id)
        return batch.execution_log[-limit:] if batch else []


# ---------------------------------------------------------------------------
# Global singleton — imported by app.py and AI_batch_orchestrator.py
# ---------------------------------------------------------------------------
batch_manager = BatchManager()