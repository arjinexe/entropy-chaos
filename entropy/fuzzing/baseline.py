""""Baseline diffing — compare attack responses to clean control requests."""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from entropy.core.models import (
    APIEndpoint, Finding, FindingType, HTTPRequest,
    HTTPResponse, Severity, TestStep,
)


# ---------------------------------------------------------------------------
# Baseline record
# ---------------------------------------------------------------------------

@dataclass
class BaselineRecord:
    endpoint_uid:   str
    status_code:    int
    latency_ms:     float
    body_hash:      str          # sha256 of JSON-normalised body
    body_keys:      List[str]    # top-level keys (if dict)
    content_length: int

    @classmethod
    def from_response(cls, endpoint_uid: str, resp: HTTPResponse) -> "BaselineRecord":
        body_str = json.dumps(resp.body, sort_keys=True, default=str) if resp.body else ""
        keys     = list(resp.body.keys()) if isinstance(resp.body, dict) else []
        return cls(
            endpoint_uid   = endpoint_uid,
            status_code    = resp.status_code,
            latency_ms     = resp.latency_ms,
            body_hash      = hashlib.sha256(body_str.encode()).hexdigest()[:12],
            body_keys      = keys,
            content_length = len(body_str),
        )


# ---------------------------------------------------------------------------
# Diff result
# ---------------------------------------------------------------------------

@dataclass
class DiffAnalysis:
    changed_status:  bool = False
    changed_body:    bool = False
    latency_spike:   bool = False
    new_keys:        List[str] = field(default_factory=list)
    missing_keys:    List[str] = field(default_factory=list)
    baseline_status: int = 0
    attack_status:   int = 0

    @property
    def is_anomalous(self) -> bool:
        return any([
            self.changed_status,
            self.changed_body,
            self.latency_spike,
            self.new_keys,
            self.missing_keys,
        ])

    def to_finding(
        self,
        endpoint: str,
        req: HTTPRequest,
        resp: HTTPResponse,
        baseline: BaselineRecord,
    ) -> Optional[Finding]:
        if not self.is_anomalous:
            return None

        parts: List[str] = []
        if self.changed_status:
            parts.append(f"Status changed {baseline.status_code} → {self.attack_status}")
        if self.latency_spike:
            parts.append(f"Latency spike ({resp.latency_ms:.0f}ms vs baseline {baseline.latency_ms:.0f}ms)")
        if self.new_keys:
            parts.append(f"New response keys: {self.new_keys}")
        if self.missing_keys:
            parts.append(f"Missing keys vs baseline: {self.missing_keys}")
        if self.changed_body and not parts:
            parts.append("Response body differs from baseline")

        description = "; ".join(parts)

        # Pick severity based on what changed
        if self.changed_status and self.attack_status >= 500:
            sev = Severity.HIGH
        elif self.changed_status and self.attack_status == 200 and baseline.status_code >= 400:
            sev = Severity.CRITICAL   # attack got through where normal request would have failed
        elif self.new_keys:
            sev = Severity.MEDIUM
        elif self.latency_spike:
            sev = Severity.MEDIUM
        else:
            sev = Severity.LOW

        return Finding(
            type        = FindingType.LOGIC_ERROR,
            severity    = sev,
            title       = f"Baseline deviation: {endpoint}",
            description = description,
            endpoint    = endpoint,
            steps       = [
                TestStep(
                    step_number  = 1,
                    description  = "Baseline (control) request",
                    passed       = True,
                ),
                TestStep(
                    step_number  = 2,
                    description  = "Attack request",
                    request      = req,
                    response     = resp,
                    passed       = False,
                ),
            ],
            evidence = {
                "baseline_status":  baseline.status_code,
                "attack_status":    self.attack_status,
                "baseline_latency": round(baseline.latency_ms, 2),
                "attack_latency":   round(resp.latency_ms, 2),
                "new_keys":         self.new_keys,
                "missing_keys":     self.missing_keys,
            },
        )


# ---------------------------------------------------------------------------
# Baseline tester
# ---------------------------------------------------------------------------

class BaselineTester:
    """
    Records baseline responses for each endpoint, then evaluates attack
    responses against those baselines to eliminate false positives.
    """

    LATENCY_MULTIPLIER = 3.0   # flag if attack response is 3× slower than baseline
    LATENCY_FLOOR_MS   = 500   # ignore spikes below this absolute value

    def __init__(self, executor):
        self.executor  = executor
        self._baselines: Dict[str, BaselineRecord] = {}

    # ------------------------------------------------------------------

    def record_baseline(
        self,
        endpoint: APIEndpoint,
        base_url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> BaselineRecord:
        """Send a benign control request and record the baseline."""
        uid = endpoint.uid
        if uid in self._baselines:
            return self._baselines[uid]

        url = f"{base_url}{endpoint.path}"
        req = HTTPRequest(
            method  = endpoint.method.value,
            url     = url,
            headers = headers or {"Content-Type": "application/json"},
            body    = self._benign_body(endpoint),
        )
        resp, _ = self.executor.execute(req, {})
        record  = BaselineRecord.from_response(uid, resp)
        self._baselines[uid] = record
        return record

    def compare(
        self,
        endpoint: APIEndpoint,
        attack_req: HTTPRequest,
        attack_resp: HTTPResponse,
    ) -> DiffAnalysis:
        """Compare an attack response against the stored baseline."""
        baseline = self._baselines.get(endpoint.uid)
        if not baseline:
            return DiffAnalysis()   # no baseline recorded — skip diff

        attack_body_str = (
            json.dumps(attack_resp.body, sort_keys=True, default=str)
            if attack_resp.body else ""
        )
        attack_hash = hashlib.sha256(attack_body_str.encode()).hexdigest()[:12]
        attack_keys = (
            list(attack_resp.body.keys())
            if isinstance(attack_resp.body, dict) else []
        )

        latency_threshold = max(
            baseline.latency_ms * self.LATENCY_MULTIPLIER,
            self.LATENCY_FLOOR_MS,
        )

        new_keys     = [k for k in attack_keys if k not in baseline.body_keys]
        missing_keys = [k for k in baseline.body_keys if k not in attack_keys]

        return DiffAnalysis(
            changed_status  = attack_resp.status_code != baseline.status_code,
            changed_body    = attack_hash != baseline.body_hash,
            latency_spike   = attack_resp.latency_ms > latency_threshold,
            new_keys        = new_keys,
            missing_keys    = missing_keys,
            baseline_status = baseline.status_code,
            attack_status   = attack_resp.status_code,
        )

    def filter_findings_by_diff(
        self,
        endpoint: APIEndpoint,
        attack_req: HTTPRequest,
        attack_resp: HTTPResponse,
        findings: List[Finding],
    ) -> List[Finding]:
        """
        Filter findings to only those that show meaningful deviation from baseline.
        Returns all findings if no baseline exists.
        """
        if endpoint.uid not in self._baselines:
            return findings

        diff = self.compare(endpoint, attack_req, attack_resp)
        if not diff.is_anomalous and findings:
            # Attack behaved identically to baseline — likely false positive
            return []

        diff_finding = diff.to_finding(endpoint.uid, attack_req, attack_resp,
                                       self._baselines[endpoint.uid])
        if diff_finding and diff_finding not in findings:
            findings = [diff_finding] + findings

        return findings

    # ------------------------------------------------------------------

    @staticmethod
    def _benign_body(endpoint: APIEndpoint) -> Optional[Dict]:
        """Generate a minimal benign body for baseline recording."""
        if not endpoint.request_body:
            return None
        # Build a body with empty/default values from the schema
        schema = endpoint.request_body.get("content", {})
        for content_type, content in schema.items():
            props = content.get("schema", {}).get("properties", {})
            if props:
                body = {}
                for name, prop_schema in list(props.items())[:5]:
                    t = prop_schema.get("type", "string")
                    if t == "string":
                        body[name] = "test"
                    elif t in ("integer", "number"):
                        body[name] = 1
                    elif t == "boolean":
                        body[name] = True
                    elif t == "array":
                        body[name] = []
                    else:
                        body[name] = {}
                return body
        return {"test": True}
