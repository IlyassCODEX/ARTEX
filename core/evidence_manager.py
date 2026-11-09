# evidence_manager.py
import hashlib
import json
import re
import threading
import time
import os
import csv
import io
import uuid
import logging
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Set, Any, Iterator, Tuple


# ---------------------------------------------------------------------------
# Redaction engine
# ---------------------------------------------------------------------------

# Patterns that must never appear in stored evidence
_REDACTION_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # HTTP Authorization header values
    (re.compile(r'(Authorization\s*:\s*)(Bearer\s+)[A-Za-z0-9\-_\.=+/]{10,}',
                re.IGNORECASE), r'\1\2[REDACTED]'),
    (re.compile(r'(Authorization\s*:\s*Basic\s+)[A-Za-z0-9+/=]{4,}',
                re.IGNORECASE), r'\1[REDACTED]'),
    # Cookie / Set-Cookie header values (keep name, redact value)
    (re.compile(r'((?:Cookie|Set-Cookie)\s*:\s*[^=\n]{1,60}=)[^\s;,\n]{6,}',
                re.IGNORECASE), r'\1[REDACTED]'),
    # JWT tokens (three base64url segments)
    (re.compile(r'eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}'),
     '[JWT_REDACTED]'),
    # AWS access key IDs
    (re.compile(r'\b(AKIA|ASIA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b'),
     '[AWS_KEY_ID_REDACTED]'),
    # AWS secret access keys (40 chars base64)
    (re.compile(r'(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*[A-Za-z0-9/+]{40}'),
     r'\1=[AWS_SECRET_REDACTED]'),
    # Generic API key / token assignment patterns
    (re.compile(r'(?i)(api[_-]?key|apikey|api[_-]?token|access[_-]?token|'
                r'secret[_-]?key|private[_-]?key|client[_-]?secret)'
                r'\s*[=:]\s*["\']?[A-Za-z0-9\-_\.]{16,}["\']?'),
     r'\1=[CREDENTIAL_REDACTED]'),
    # Password field assignments
    (re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?.{6,}["\']?'),
     r'\1=[PASSWORD_REDACTED]'),
    # Private PEM key blocks
    (re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----.*?'
                r'-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
                re.DOTALL), '[PEM_PRIVATE_KEY_REDACTED]'),
    # Email addresses in certain high-sensitivity contexts
    # (kept — email addresses in evidence are legitimate findings)
]

# Field names whose values are always fully redacted regardless of content
_ALWAYS_REDACT_FIELDS: Set[str] = {
    "authorization", "x-auth-token", "x-api-key", "x-secret",
    "set-cookie", "cookie", "token", "password", "passwd", "secret",
    "api_key", "apikey", "private_key", "client_secret",
}

_REDACT_PLACEHOLDER = "[REDACTED]"


class Redactor:
    """
    Applies pattern-based redaction to strings and dict structures.
    Stateless — all methods are pure functions.
    """

    @staticmethod
    def redact_string(text: str) -> str:
        """Apply all redaction patterns to a plain string."""
        if not text:
            return text
        for pattern, replacement in _REDACTION_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    @staticmethod
    def redact_dict(data: Dict, depth: int = 0) -> Dict:
        """
        Recursively redact a dict.
        Keys in _ALWAYS_REDACT_FIELDS have their values replaced wholesale.
        """
        if depth > 8:
            return data
        result: Dict = {}
        for k, v in data.items():
            key_lower = str(k).lower()
            if key_lower in _ALWAYS_REDACT_FIELDS:
                result[k] = _REDACT_PLACEHOLDER
            elif isinstance(v, dict):
                result[k] = Redactor.redact_dict(v, depth + 1)
            elif isinstance(v, list):
                result[k] = Redactor.redact_list(v, depth + 1)
            elif isinstance(v, str):
                result[k] = Redactor.redact_string(v)
            else:
                result[k] = v
        return result

    @staticmethod
    def redact_list(data: List, depth: int = 0) -> List:
        """Recursively redact a list."""
        if depth > 8:
            return data
        result = []
        for item in data:
            if isinstance(item, dict):
                result.append(Redactor.redact_dict(item, depth + 1))
            elif isinstance(item, str):
                result.append(Redactor.redact_string(item))
            else:
                result.append(item)
        return result

    @staticmethod
    def redact_any(value: Any) -> Any:
        """Dispatch redaction by type."""
        if isinstance(value, str):
            return Redactor.redact_string(value)
        if isinstance(value, dict):
            return Redactor.redact_dict(value)
        if isinstance(value, list):
            return Redactor.redact_list(value)
        return value


# ---------------------------------------------------------------------------
# Evidence record — immutable after creation
# ---------------------------------------------------------------------------

class EvidenceRecord:
    """
    One atomic evidence record.

    Fields match the batch_manager spec exactly:
        Evidence ID       → evidence_id
        Target ID         → target_id
        Batch ID          → batch_id
        Source Tool       → source_tool
        Source Agent      → source_agent
        Timestamp         → timestamp
        Raw Output        → raw_output  (redacted before storage)
        SHA-256 Hash      → sha256      (computed over redacted content)

    Additional fields for ARTEX operational context:
        sequence, record_type, operation, arguments,
        stdout, stderr, exit_code, duration_s,
        severity, verdict, linked_evidence_ids,
        previous_hash (hash chain)
    """

    __slots__ = (
        # Spec-mandated fields
        "evidence_id",
        "target_id",
        "batch_id",
        "source_tool",
        "source_agent",
        "timestamp",
        "raw_output",
        "sha256",
        # Extended ARTEX fields
        "sequence",
        "record_type",
        "operation",
        "arguments",
        "stdout",
        "stderr",
        "exit_code",
        "duration_s",
        "severity",
        "verdict",
        "linked_evidence_ids",
        "previous_hash",
        "metadata",
    )

    def __init__(
        self,
        sequence:        int,
        target_id:       str,
        batch_id:        str,
        source_tool:     str,
        source_agent:    str,
        record_type:     str,
        operation:       str,
        arguments:       Dict,
        raw_output:      str,
        stdout:          str         = "",
        stderr:          str         = "",
        exit_code:       int         = 0,
        duration_s:      float       = 0.0,
        severity:        str         = "info",
        verdict:         str         = "clean",
        linked_evidence_ids: Optional[List[str]] = None,
        previous_hash:   str         = "GENESIS",
        metadata:        Optional[Dict] = None,
    ):
        redactor = Redactor()

        self.sequence              = sequence
        self.target_id             = target_id
        self.batch_id              = batch_id
        self.source_tool           = source_tool
        self.source_agent          = source_agent
        self.record_type           = record_type
        self.operation             = operation
        self.timestamp             = datetime.utcnow().isoformat() + "Z"
        self.arguments             = redactor.redact_dict(dict(arguments))
        self.raw_output            = redactor.redact_string(raw_output[:8000])
        self.stdout                = redactor.redact_string(stdout[:4000])
        self.stderr                = redactor.redact_string(stderr[:2000])
        self.exit_code             = exit_code
        self.duration_s            = round(float(duration_s), 3)
        self.severity              = severity
        self.verdict               = verdict
        self.linked_evidence_ids   = linked_evidence_ids or []
        self.previous_hash         = previous_hash
        self.metadata              = redactor.redact_dict(metadata or {})

        # Deterministic evidence ID
        raw_id = (
            f"{batch_id}|{target_id}|{source_tool}|{operation}"
            f"|{self.timestamp}|{sequence}"
        )
        self.evidence_id = hashlib.sha256(raw_id.encode()).hexdigest()[:20]

        # SHA-256 over all content + chain link
        chain_input = json.dumps({
            "evidence_id":   self.evidence_id,
            "sequence":      self.sequence,
            "target_id":     self.target_id,
            "batch_id":      self.batch_id,
            "source_tool":   self.source_tool,
            "source_agent":  self.source_agent,
            "operation":     self.operation,
            "arguments":     self.arguments,
            "raw_output":    self.raw_output,
            "exit_code":     self.exit_code,
            "severity":      self.severity,
            "verdict":       self.verdict,
            "previous_hash": self.previous_hash,
        }, sort_keys=True, default=str)
        self.sha256 = hashlib.sha256(chain_input.encode()).hexdigest()

    def to_dict(self, include_raw: bool = True) -> Dict:
        d = {k: getattr(self, k) for k in self.__slots__}
        if not include_raw:
            d["raw_output"] = d["raw_output"][:200] + "…" if len(d["raw_output"]) > 200 else d["raw_output"]
            d["stdout"]     = d["stdout"][:100] + "…"     if len(d["stdout"]) > 100     else d["stdout"]
            d["stderr"]     = d["stderr"][:100] + "…"     if len(d["stderr"]) > 100     else d["stderr"]
        return d

    def __repr__(self) -> str:
        return (
            f"EvidenceRecord(id={self.evidence_id[:10]}… "
            f"seq={self.sequence} tool={self.source_tool} "
            f"op={self.operation[:30]} sev={self.severity})"
        )


# ---------------------------------------------------------------------------
# Evidence store — thread-safe, append-only
# ---------------------------------------------------------------------------

class EvidenceStore:
    """
    In-memory append-only store with thread-safe access.
    Optional disk persistence via save()/load().

    Indexing:
        _by_batch[batch_id]        → [evidence_id, ...]
        _by_target[target_id]      → [evidence_id, ...]
        _by_tool[source_tool]      → [evidence_id, ...]
        _by_agent[source_agent]    → [evidence_id, ...]
        _by_severity[severity]     → [evidence_id, ...]
        _by_verdict[verdict]       → [evidence_id, ...]
        _chain[batch_id]           → ordered list of sha256 (for chain verify)
    """

    def __init__(self):
        self._records:     Dict[str, EvidenceRecord]  = {}   # evidence_id → record
        self._by_batch:    Dict[str, List[str]]        = defaultdict(list)
        self._by_target:   Dict[str, List[str]]        = defaultdict(list)
        self._by_tool:     Dict[str, List[str]]        = defaultdict(list)
        self._by_agent:    Dict[str, List[str]]        = defaultdict(list)
        self._by_severity: Dict[str, List[str]]        = defaultdict(list)
        self._by_verdict:  Dict[str, List[str]]        = defaultdict(list)
        self._chain:       Dict[str, List[str]]        = defaultdict(list)   # batch → sha256 list
        self._counters:    Dict[str, int]              = defaultdict(int)    # batch → seq
        self._lock         = threading.RLock()

    def add(self, record: EvidenceRecord) -> str:
        """Append one record. Returns evidence_id. Thread-safe."""
        with self._lock:
            if record.evidence_id in self._records:
                return record.evidence_id   # idempotent

            self._records[record.evidence_id] = record
            self._by_batch[record.batch_id].append(record.evidence_id)
            self._by_target[record.target_id].append(record.evidence_id)
            self._by_tool[record.source_tool].append(record.evidence_id)
            self._by_agent[record.source_agent].append(record.evidence_id)
            self._by_severity[record.severity].append(record.evidence_id)
            self._by_verdict[record.verdict].append(record.evidence_id)
            self._chain[record.batch_id].append(record.sha256)

        return record.evidence_id

    def get(self, evidence_id: str) -> Optional[EvidenceRecord]:
        with self._lock:
            return self._records.get(evidence_id)

    def next_sequence(self, batch_id: str) -> int:
        with self._lock:
            self._counters[batch_id] += 1
            return self._counters[batch_id]

    def last_hash(self, batch_id: str) -> str:
        with self._lock:
            chain = self._chain.get(batch_id, [])
            return chain[-1] if chain else "GENESIS"

    # ── Query interface ───────────────────────────────────────────────

    def query(
        self,
        batch_id:    Optional[str]  = None,
        target_id:   Optional[str]  = None,
        source_tool: Optional[str]  = None,
        source_agent: Optional[str] = None,
        severity:    Optional[str]  = None,
        verdict:     Optional[str]  = None,
        record_type: Optional[str]  = None,
        limit:       int            = 1000,
        offset:      int            = 0,
    ) -> List[EvidenceRecord]:
        """
        Multi-index query. All supplied filters are ANDed.
        Returns list of EvidenceRecord ordered by sequence asc.
        """
        with self._lock:
            # Start with the smallest candidate set
            candidate_sets: List[Set[str]] = []

            if batch_id:
                candidate_sets.append(set(self._by_batch.get(batch_id, [])))
            if target_id:
                candidate_sets.append(set(self._by_target.get(target_id, [])))
            if source_tool:
                candidate_sets.append(set(self._by_tool.get(source_tool, [])))
            if source_agent:
                candidate_sets.append(set(self._by_agent.get(source_agent, [])))
            if severity:
                candidate_sets.append(set(self._by_severity.get(severity, [])))
            if verdict:
                candidate_sets.append(set(self._by_verdict.get(verdict, [])))

            if candidate_sets:
                ids = candidate_sets[0]
                for s in candidate_sets[1:]:
                    ids = ids.intersection(s)
            else:
                ids = set(self._records.keys())

            records = [self._records[eid] for eid in ids if eid in self._records]

        # Post-filter by record_type (not indexed)
        if record_type:
            records = [r for r in records if r.record_type == record_type]

        records.sort(key=lambda r: r.sequence)
        return records[offset: offset + limit]

    def count(self, batch_id: Optional[str] = None, target_id: Optional[str] = None) -> int:
        with self._lock:
            if batch_id and target_id:
                b = set(self._by_batch.get(batch_id, []))
                t = set(self._by_target.get(target_id, []))
                return len(b & t)
            if batch_id:
                return len(self._by_batch.get(batch_id, []))
            if target_id:
                return len(self._by_target.get(target_id, []))
            return len(self._records)

    def batches(self) -> List[str]:
        with self._lock:
            return list(self._by_batch.keys())

    def targets_in_batch(self, batch_id: str) -> List[str]:
        with self._lock:
            ids = self._by_batch.get(batch_id, [])
            seen: Set[str] = set()
            result = []
            for eid in ids:
                rec = self._records.get(eid)
                if rec and rec.target_id not in seen:
                    seen.add(rec.target_id)
                    result.append(rec.target_id)
            return result

    # ── Chain integrity ───────────────────────────────────────────────

    def verify_chain(self, batch_id: str) -> Dict:
        """
        Re-walk the hash chain for a batch.
        Returns {valid: bool, broken_at: int|None, total: int}.
        """
        with self._lock:
            records = sorted(
                [r for r in self._records.values() if r.batch_id == batch_id],
                key=lambda r: r.sequence,
            )

        prev_hash = "GENESIS"
        for rec in records:
            # Recompute expected sha256
            chain_input = json.dumps({
                "evidence_id":   rec.evidence_id,
                "sequence":      rec.sequence,
                "target_id":     rec.target_id,
                "batch_id":      rec.batch_id,
                "source_tool":   rec.source_tool,
                "source_agent":  rec.source_agent,
                "operation":     rec.operation,
                "arguments":     rec.arguments,
                "raw_output":    rec.raw_output,
                "exit_code":     rec.exit_code,
                "severity":      rec.severity,
                "verdict":       rec.verdict,
                "previous_hash": prev_hash,
            }, sort_keys=True, default=str)
            expected = hashlib.sha256(chain_input.encode()).hexdigest()

            if expected != rec.sha256:
                return {
                    "valid":      False,
                    "broken_at":  rec.sequence,
                    "evidence_id": rec.evidence_id,
                    "total":      len(records),
                }
            prev_hash = rec.sha256

        return {"valid": True, "broken_at": None, "total": len(records)}

    # ── Export ────────────────────────────────────────────────────────

    def export_json(
        self,
        batch_id:   Optional[str] = None,
        target_id:  Optional[str] = None,
        include_raw: bool         = True,
    ) -> str:
        records = self.query(batch_id=batch_id, target_id=target_id, limit=100000)
        chain_valid = self.verify_chain(batch_id) if batch_id else {"valid": None}
        return json.dumps({
            "export_timestamp":  datetime.utcnow().isoformat() + "Z",
            "batch_id":          batch_id,
            "target_id":         target_id,
            "total_records":     len(records),
            "chain_integrity":   chain_valid,
            "records":           [r.to_dict(include_raw=include_raw) for r in records],
        }, indent=2, default=str)

    def export_csv(
        self,
        batch_id:  Optional[str] = None,
        target_id: Optional[str] = None,
    ) -> str:
        records = self.query(batch_id=batch_id, target_id=target_id, limit=100000)
        buf     = io.StringIO()
        writer  = csv.writer(buf)
        writer.writerow([
            "evidence_id", "sequence", "batch_id", "target_id",
            "source_tool", "source_agent", "record_type",
            "operation", "timestamp", "exit_code",
            "duration_s", "severity", "verdict", "sha256",
        ])
        for r in records:
            writer.writerow([
                r.evidence_id, r.sequence, r.batch_id, r.target_id,
                r.source_tool, r.source_agent, r.record_type,
                r.operation, r.timestamp, r.exit_code,
                r.duration_s, r.severity, r.verdict, r.sha256,
            ])
        return buf.getvalue()

    # ── Persistence ───────────────────────────────────────────────────

    def save(self, filepath: str) -> None:
        """Persist entire store to JSON file. Thread-safe."""
        with self._lock:
            records_data = {
                eid: rec.to_dict(include_raw=True)
                for eid, rec in self._records.items()
            }
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(records_data, fh, indent=2, default=str)

    def load(self, filepath: str) -> int:
        """Load records from JSON file. Returns number of records loaded."""
        if not os.path.exists(filepath):
            return 0
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        loaded = 0
        for eid, rec_dict in data.items():
            # Reconstruct a minimal record from stored dict
            # We re-create via EvidenceRecord but skip re-hashing to preserve stored sha256
            try:
                r = _reconstruct_record(rec_dict)
                self._records[r.evidence_id]           = r
                self._by_batch[r.batch_id].append(r.evidence_id)
                self._by_target[r.target_id].append(r.evidence_id)
                self._by_tool[r.source_tool].append(r.evidence_id)
                self._by_agent[r.source_agent].append(r.evidence_id)
                self._by_severity[r.severity].append(r.evidence_id)
                self._by_verdict[r.verdict].append(r.evidence_id)
                self._chain[r.batch_id].append(r.sha256)
                self._counters[r.batch_id] = max(
                    self._counters[r.batch_id], r.sequence
                )
                loaded += 1
            except Exception:
                continue
        return loaded

    # ── Stats ─────────────────────────────────────────────────────────

    def stats(self, batch_id: Optional[str] = None) -> Dict:
        with self._lock:
            if batch_id:
                recs = [self._records[eid]
                        for eid in self._by_batch.get(batch_id, [])
                        if eid in self._records]
            else:
                recs = list(self._records.values())

        if not recs:
            return {"total": 0}

        sev_counts:   Dict[str, int] = defaultdict(int)
        tool_counts:  Dict[str, int] = defaultdict(int)
        agent_counts: Dict[str, int] = defaultdict(int)
        type_counts:  Dict[str, int] = defaultdict(int)
        verdict_counts: Dict[str, int] = defaultdict(int)
        total_duration = 0.0

        for r in recs:
            sev_counts[r.severity]     += 1
            tool_counts[r.source_tool] += 1
            agent_counts[r.source_agent] += 1
            type_counts[r.record_type] += 1
            verdict_counts[r.verdict]  += 1
            total_duration             += r.duration_s

        return {
            "total":            len(recs),
            "by_severity":      dict(sev_counts),
            "by_tool":          dict(tool_counts),
            "by_agent":         dict(agent_counts),
            "by_record_type":   dict(type_counts),
            "by_verdict":       dict(verdict_counts),
            "total_duration_s": round(total_duration, 2),
            "targets":          len(set(r.target_id for r in recs)),
        }


# ---------------------------------------------------------------------------
# Reconstruct helper (for load — avoids re-hashing)
# ---------------------------------------------------------------------------

def _reconstruct_record(d: Dict) -> EvidenceRecord:
    """
    Rebuild an EvidenceRecord from a dict (loaded from disk).
    Skips __init__ hash computation to preserve stored sha256.
    """
    r = object.__new__(EvidenceRecord)
    for slot in EvidenceRecord.__slots__:
        setattr(r, slot, d.get(slot, "" if slot not in ("sequence","exit_code") else 0))
    return r


# ---------------------------------------------------------------------------
# EvidenceManager — high-level API
# ---------------------------------------------------------------------------

class EvidenceManager:
    """
    High-level evidence management for ARTEX.

    Usage from AI_batch_orchestrator and all AI modules:

        em = evidence_manager   # global singleton
        eid = em.record(
            batch_id    = batch_op.batch_id,
            target_id   = target.target_id,
            source_tool = "SubdomainEnumerator",
            source_agent = "recon_agent",
            record_type = "tool_invocation",
            operation   = "enumerate",
            arguments   = {"domain": domain},
            raw_output  = json.dumps(subdomains),
            stdout      = f"Found {len(subdomains)} subdomains",
            duration_s  = elapsed,
            severity    = "info",
        )
        # Link multiple evidence IDs to one finding:
        em.link(finding_id="FIND-001", evidence_ids=[eid1, eid2, eid3])

    Redaction is automatic — credentials in raw_output/stdout/arguments
    are stripped before any storage or export.
    """

    # Record type constants
    TYPE_TOOL_INVOCATION  = "tool_invocation"
    TYPE_HTTP_REQUEST     = "http_request"
    TYPE_HTTP_RESPONSE    = "http_response"
    TYPE_DNS_RESULT       = "dns_result"
    TYPE_FINDING          = "finding"
    TYPE_AI_DECISION      = "ai_decision"
    TYPE_AI_NARRATIVE     = "ai_narrative"
    TYPE_ERROR            = "error"
    TYPE_SCAN_START       = "scan_start"
    TYPE_SCAN_COMPLETE    = "scan_complete"
    TYPE_SQLMAP           = "sqlmap_result"
    TYPE_FUZZ_REQUEST     = "fuzz_request"
    TYPE_VULN_CONFIRMED   = "vulnerability_confirmed"

    def __init__(self, persist_dir: Optional[str] = None):
        self._store       = EvidenceStore()
        self._persist_dir = persist_dir
        self._link_map:   Dict[str, List[str]] = defaultdict(list)   # finding_id → [evidence_ids]
        self._lock        = threading.RLock()
        self.logger       = logging.getLogger(__name__)

        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] EvidenceManager — %(message)s"
            ))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)

    # ------------------------------------------------------------------
    # Core record method
    # ------------------------------------------------------------------

    def record(
        self,
        batch_id:     str,
        target_id:    str,
        source_tool:  str,
        source_agent: str,
        record_type:  str,
        operation:    str,
        arguments:    Dict,
        raw_output:   str         = "",
        stdout:       str         = "",
        stderr:       str         = "",
        exit_code:    int         = 0,
        duration_s:   float       = 0.0,
        severity:     str         = "info",
        verdict:      str         = "clean",
        linked_evidence_ids: Optional[List[str]] = None,
        metadata:     Optional[Dict] = None,
    ) -> str:
        """
        Create and store one evidence record.
        Returns evidence_id.
        All sensitive data is redacted before storage.
        """
        seq  = self._store.next_sequence(batch_id)
        prev = self._store.last_hash(batch_id)

        rec = EvidenceRecord(
            sequence           = seq,
            target_id          = target_id,
            batch_id           = batch_id,
            source_tool        = source_tool,
            source_agent       = source_agent,
            record_type        = record_type,
            operation          = operation,
            arguments          = arguments,
            raw_output         = raw_output,
            stdout             = stdout,
            stderr             = stderr,
            exit_code          = exit_code,
            duration_s         = duration_s,
            severity           = severity,
            verdict            = verdict,
            linked_evidence_ids = linked_evidence_ids or [],
            previous_hash      = prev,
            metadata           = metadata or {},
        )

        eid = self._store.add(rec)
        self.logger.debug(f"Recorded [{record_type}] {source_tool}:{operation} → {eid[:10]}…")

        # Auto-persist if dir configured
        if self._persist_dir and seq % 50 == 0:
            self._auto_persist(batch_id)

        return eid

    # ------------------------------------------------------------------
    # Convenience wrappers — one per record type
    # ------------------------------------------------------------------

    def record_tool(
        self,
        batch_id:    str,
        target_id:   str,
        agent:       str,
        tool:        str,
        operation:   str,
        arguments:   Dict,
        stdout:      str   = "",
        stderr:      str   = "",
        exit_code:   int   = 0,
        duration_s:  float = 0.0,
        severity:    str   = "info",
        raw_output:  str   = "",
    ) -> str:
        """Record a CLI or Python module tool invocation."""
        return self.record(
            batch_id    = batch_id,
            target_id   = target_id,
            source_tool = tool,
            source_agent = agent,
            record_type = self.TYPE_TOOL_INVOCATION,
            operation   = operation,
            arguments   = arguments,
            raw_output  = raw_output or stdout,
            stdout      = stdout,
            stderr      = stderr,
            exit_code   = exit_code,
            duration_s  = duration_s,
            severity    = severity,
        )

    def record_http(
        self,
        batch_id:   str,
        target_id:  str,
        agent:      str,
        url:        str,
        method:     str,
        request_headers:  Dict,
        request_body:     Any,
        response_status:  int,
        response_headers: Dict,
        response_body:    str,
        response_time_s:  float = 0.0,
        severity:         str   = "info",
        verdict:          str   = "clean",
    ) -> str:
        """Record an HTTP request+response pair."""
        return self.record(
            batch_id    = batch_id,
            target_id   = target_id,
            source_tool = "HTTPClient",
            source_agent = agent,
            record_type = self.TYPE_HTTP_REQUEST,
            operation   = f"{method} {url}",
            arguments   = {
                "url":    url,
                "method": method,
                "request_headers": request_headers,
                "request_body":    str(request_body)[:500] if request_body else "",
            },
            raw_output  = response_body[:4000],
            stdout      = f"HTTP {response_status} in {response_time_s:.3f}s",
            stderr      = "",
            exit_code   = 0 if response_status < 500 else 1,
            duration_s  = response_time_s,
            severity    = severity,
            verdict     = verdict,
            metadata    = {
                "response_status":  response_status,
                "response_headers": response_headers,
            },
        )

    def record_dns(
        self,
        batch_id:  str,
        target_id: str,
        domain:    str,
        records:   Dict,
        duration_s: float = 0.0,
    ) -> str:
        """Record DNS scan results."""
        summary = {k: len(v) if isinstance(v, list) else v
                   for k, v in records.items()}
        return self.record(
            batch_id    = batch_id,
            target_id   = target_id,
            source_tool = "DNSScanner",
            source_agent = "recon_agent",
            record_type = self.TYPE_DNS_RESULT,
            operation   = "dns_scan",
            arguments   = {"domain": domain},
            raw_output  = json.dumps(records, default=str)[:3000],
            stdout      = json.dumps(summary, default=str),
            duration_s  = duration_s,
            severity    = "info",
        )

    def record_finding(
        self,
        batch_id:   str,
        target_id:  str,
        agent:      str,
        tool:       str,
        title:      str,
        severity:   str,
        description: str,
        evidence:   Dict,
        linked_ids: Optional[List[str]] = None,
        verdict:    str = "confirmed",
    ) -> str:
        """Record a confirmed vulnerability or security finding."""
        return self.record(
            batch_id    = batch_id,
            target_id   = target_id,
            source_tool = tool,
            source_agent = agent,
            record_type = self.TYPE_FINDING,
            operation   = "finding_recorded",
            arguments   = {
                "title":       title,
                "severity":    severity,
                "description": description[:300],
            },
            raw_output  = json.dumps(evidence, default=str)[:4000],
            severity    = severity,
            verdict     = verdict,
            linked_evidence_ids = linked_ids or [],
        )

    def record_ai_decision(
        self,
        batch_id:   str,
        target_id:  str,
        agent:      str,
        decision:   str,
        rationale:  str,
        inputs:     Dict,
        outputs:    Dict,
        duration_s: float = 0.0,
        model:      str   = "llama3-70b-8192",
    ) -> str:
        """Record an AI autonomous decision."""
        return self.record(
            batch_id    = batch_id,
            target_id   = target_id,
            source_tool = f"Groq/{model}",
            source_agent = agent,
            record_type = self.TYPE_AI_DECISION,
            operation   = decision,
            arguments   = inputs,
            raw_output  = json.dumps(outputs, default=str)[:2000],
            stdout      = rationale[:500],
            duration_s  = duration_s,
            severity    = "info",
            verdict     = "clean",
        )

    def record_sqlmap(
        self,
        batch_id:    str,
        target_id:   str,
        url:         str,
        command:     str,
        stdout:      str,
        stderr:      str,
        exit_code:   int,
        duration_s:  float,
        injectable:  bool,
        parameters:  List[str],
    ) -> str:
        """Record a SQLMap execution."""
        severity = "critical" if injectable else "info"
        verdict  = "confirmed" if injectable else "clean"
        return self.record(
            batch_id    = batch_id,
            target_id   = target_id,
            source_tool = "sqlmap",
            source_agent = "sqli_agent",
            record_type = self.TYPE_SQLMAP,
            operation   = "sql_injection_assessment",
            arguments   = {
                "url":        url,
                "command":    command,
                "injectable": injectable,
                "parameters": parameters,
            },
            raw_output  = stdout[:5000],
            stdout      = stdout[:2000],
            stderr      = stderr[:500],
            exit_code   = exit_code,
            duration_s  = duration_s,
            severity    = severity,
            verdict     = verdict,
        )

    def record_fuzz_request(
        self,
        batch_id:      str,
        target_id:     str,
        url:           str,
        method:        str,
        payload_class: str,
        payload_value: Any,
        response_status: int,
        response_body: str,
        response_time_s: float,
        anomaly_verdict: str,
        anomaly_signals: List[str],
        sha256_req:    str,
    ) -> str:
        """Record one API fuzz request."""
        sev_map = {
            "confirmed": "high",
            "likely":    "medium",
            "signal":    "low",
            "clean":     "info",
        }
        return self.record(
            batch_id    = batch_id,
            target_id   = target_id,
            source_tool = "AIAPIFuzzer",
            source_agent = "api_fuzzer_agent",
            record_type = self.TYPE_FUZZ_REQUEST,
            operation   = f"{method} fuzz:{payload_class}",
            arguments   = {
                "url":           url,
                "method":        method,
                "payload_class": payload_class,
                "payload_value": str(payload_value)[:200],
            },
            raw_output  = response_body[:2000],
            stdout      = (
                f"HTTP {response_status} in {response_time_s:.3f}s "
                f"verdict={anomaly_verdict}"
            ),
            duration_s  = response_time_s,
            severity    = sev_map.get(anomaly_verdict, "info"),
            verdict     = anomaly_verdict,
            metadata    = {
                "response_status": response_status,
                "anomaly_signals": anomaly_signals,
                "request_sha256":  sha256_req,
            },
        )

    def record_error(
        self,
        batch_id:   str,
        target_id:  str,
        agent:      str,
        tool:       str,
        operation:  str,
        error_msg:  str,
        arguments:  Optional[Dict] = None,
    ) -> str:
        """Record an execution error."""
        return self.record(
            batch_id    = batch_id,
            target_id   = target_id,
            source_tool = tool,
            source_agent = agent,
            record_type = self.TYPE_ERROR,
            operation   = operation,
            arguments   = arguments or {},
            raw_output  = "",
            stderr      = error_msg[:1000],
            exit_code   = -1,
            severity    = "info",
            verdict     = "error",
        )

    # ------------------------------------------------------------------
    # Evidence linking
    # ------------------------------------------------------------------

    def link(self, finding_id: str, evidence_ids: List[str]) -> None:
        """Associate multiple evidence records with one finding ID."""
        with self._lock:
            self._link_map[finding_id].extend(evidence_ids)

    def get_linked(self, finding_id: str) -> List[EvidenceRecord]:
        """Return all evidence records linked to a finding ID."""
        with self._lock:
            eids = self._link_map.get(finding_id, [])
        return [r for eid in eids if (r := self._store.get(eid)) is not None]

    def links_for_target(self, target_id: str) -> Dict[str, List[str]]:
        """Return {finding_id: [evidence_ids]} for all findings linked to a target."""
        recs   = self._store.query(target_id=target_id, limit=100000)
        rec_ids = {r.evidence_id for r in recs}
        with self._lock:
            return {
                fid: [eid for eid in eids if eid in rec_ids]
                for fid, eids in self._link_map.items()
                if any(eid in rec_ids for eid in eids)
            }

    # ------------------------------------------------------------------
    # Query passthrough
    # ------------------------------------------------------------------

    def query(self, **kwargs) -> List[EvidenceRecord]:
        return self._store.query(**kwargs)

    def get(self, evidence_id: str) -> Optional[EvidenceRecord]:
        return self._store.get(evidence_id)

    def stats(self, batch_id: Optional[str] = None) -> Dict:
        return self._store.stats(batch_id=batch_id)

    def verify_chain(self, batch_id: str) -> Dict:
        return self._store.verify_chain(batch_id)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_json(
        self,
        batch_id:    Optional[str] = None,
        target_id:   Optional[str] = None,
        include_raw: bool          = True,
    ) -> str:
        return self._store.export_json(
            batch_id=batch_id, target_id=target_id, include_raw=include_raw
        )

    def export_csv(
        self,
        batch_id:  Optional[str] = None,
        target_id: Optional[str] = None,
    ) -> str:
        return self._store.export_csv(batch_id=batch_id, target_id=target_id)

    def export_txt(
        self,
        batch_id:  Optional[str] = None,
        target_id: Optional[str] = None,
    ) -> str:
        records = self._store.query(batch_id=batch_id, target_id=target_id, limit=100000)
        chain   = self.verify_chain(batch_id) if batch_id else {"valid": None, "total": len(records)}
        lines   = [
            "=" * 72,
            "  ARTEX EVIDENCE LOG",
            f"  Batch:   {batch_id or 'all'}",
            f"  Target:  {target_id or 'all'}",
            f"  Total:   {len(records)} records",
            f"  Chain:   {'VERIFIED' if chain.get('valid') else 'BROKEN' if chain.get('valid') is False else 'N/A'}",
            f"  Exported: {datetime.utcnow().isoformat()}Z",
            "=" * 72,
            "",
        ]
        for r in records:
            lines += [
                f"  ┌─ [{r.sequence:04d}] {r.timestamp}",
                f"  │  ID:      {r.evidence_id}",
                f"  │  Batch:   {r.batch_id}",
                f"  │  Target:  {r.target_id}",
                f"  │  Tool:    {r.source_tool}",
                f"  │  Agent:   {r.source_agent}",
                f"  │  Type:    {r.record_type}",
                f"  │  Op:      {r.operation}",
                f"  │  Args:    {json.dumps(r.arguments, default=str)[:100]}",
                f"  │  Stdout:  {r.stdout[:120]}",
                f"  │  Stderr:  {r.stderr[:60]}" if r.stderr else "",
                f"  │  Exit:    {r.exit_code} | Duration: {r.duration_s}s",
                f"  │  Sev:     {r.severity} | Verdict: {r.verdict}",
                f"  │  Linked:  {r.linked_evidence_ids}" if r.linked_evidence_ids else "",
                f"  └─ SHA256:  {r.sha256[:40]}…",
                "",
            ]
        return "\n".join(line for line in lines if line is not None)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, filepath: Optional[str] = None) -> str:
        path = filepath or self._default_path("evidence_store.json")
        self._store.save(path)
        self.logger.info(f"Evidence store saved → {path}")
        return path

    def load(self, filepath: Optional[str] = None) -> int:
        path = filepath or self._default_path("evidence_store.json")
        n = self._store.load(path)
        self.logger.info(f"Loaded {n} evidence records from {path}")
        return n

    def _auto_persist(self, batch_id: str) -> None:
        if not self._persist_dir:
            return
        path = os.path.join(self._persist_dir, f"evidence_{batch_id[:8]}.json")
        try:
            data = self._store.query(batch_id=batch_id, limit=100000)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump([r.to_dict() for r in data], fh, default=str)
        except Exception as e:
            self.logger.warning(f"Auto-persist failed: {e}")

    def _default_path(self, filename: str) -> str:
        base = self._persist_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "evidence"
        )
        os.makedirs(base, exist_ok=True)
        return os.path.join(base, filename)

    def batches(self) -> List[str]:
        return self._store.batches()

    def targets_in_batch(self, batch_id: str) -> List[str]:
        return self._store.targets_in_batch(batch_id)


# ---------------------------------------------------------------------------
# Global singleton — imported by all modules
# ---------------------------------------------------------------------------
evidence_manager = EvidenceManager(
    persist_dir=os.getenv("ARTEX_EVIDENCE_DIR", None)
)