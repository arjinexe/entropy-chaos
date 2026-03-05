"""Parameter mining — discover hidden query/body parameters not in the spec."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode, urlparse

from entropy.core.models import APIEndpoint, Finding, FindingType, Severity


# ---------------------------------------------------------------------------
# Parameter wordlists
# ---------------------------------------------------------------------------

# High-value parameters that often trigger different behaviour
PRIORITY_PARAMS: List[str] = [
    # Auth / privilege
    "admin", "is_admin", "role", "superuser", "privilege", "access",
    "permissions", "scope", "acl", "sudo", "elevated",
    # Debug / dev flags
    "debug", "test", "dev", "internal", "preview", "beta", "staging",
    "verbose", "trace", "log", "dump", "raw", "mode",
    # Data exposure
    "format", "output", "fields", "include", "expand", "embed",
    "select", "projection", "columns", "attributes", "with",
    # Bypass
    "bypass", "skip", "override", "force", "unsafe",
    "no_validate", "skip_auth", "disable_check",
    # Object IDs
    "id", "user_id", "account_id", "org_id", "tenant_id",
    "customer_id", "order_id", "invoice_id", "item_id",
    # Pagination / limit
    "limit", "offset", "page", "per_page", "size", "count",
    "max", "start", "end", "from", "to",
    # Callbacks / webhooks
    "callback", "redirect", "redirect_uri", "return_url",
    "next", "continue", "url", "uri", "endpoint", "webhook",
    # File ops
    "file", "filename", "path", "dir", "directory", "upload",
    "download", "export", "import", "template",
    # Cache / version
    "v", "version", "api_version", "cache", "nocache", "bust",
    # Common hidden
    "key", "token", "secret", "password", "apikey", "api_key",
    "auth", "authorization", "bearer", "jwt",
    # Misc often-hidden
    "action", "op", "operation", "cmd", "command", "exec",
    "eval", "query", "filter", "search", "q", "term",
    "sort", "order", "asc", "desc", "group", "by",
]


@dataclass
class ParamHit:
    endpoint:  str
    param:     str
    location:  str   # "query" | "body"
    evidence:  str   # what changed in the response
    severity:  str


class ParameterMiner:
    """
    Sends requests with candidate parameter names and detects when any of them
    change the response — indicating a hidden/undocumented parameter.

    Technique: compare baseline response (no extra params) against each probed
    variant. A changed status code, body length, or new fields = param found.
    """

    def __init__(
        self,
        base_url:    str,
        timeout:     float = 6.0,
        verify_ssl:  bool  = True,
        concurrency: int   = 10,
        dry_run:     bool  = False,
    ):
        self.base_url    = base_url.rstrip("/")
        self.timeout     = timeout
        self.verify_ssl  = verify_ssl
        self.concurrency = concurrency
        self.dry_run     = dry_run
        self._ctx        = self._build_ssl()

    # ------------------------------------------------------------------

    def mine_endpoint(
        self,
        endpoint:       APIEndpoint,
        known_params:   Optional[Set[str]] = None,
    ) -> List[Finding]:
        known  = known_params or {p.name for p in endpoint.parameters}
        probes = [p for p in PRIORITY_PARAMS if p not in known]
        if not probes:
            return []

        if self.dry_run:
            return self._mock_mine(endpoint, probes)

        url = f"{self.base_url}{endpoint.path}"

        # 1. Record baseline
        baseline = self._request(url, endpoint.method.value, {})
        if not baseline:
            return []

        # 2. Probe in batches (group 5 params per request for speed)
        hits: List[ParamHit] = []
        batch_size = 5
        batches = [probes[i:i+batch_size] for i in range(0, min(len(probes), 100), batch_size)]

        def probe_batch(params: List[str]) -> List[ParamHit]:
            batch_hits: List[ParamHit] = []
            # Try query params
            q_params = {p: f"entropy_probe_{p}" for p in params}
            resp = self._request(url, endpoint.method.value, {}, query_params=q_params)
            if resp and self._is_different(baseline, resp):
                # Narrow down which param caused the change
                for p in params:
                    single = self._request(url, endpoint.method.value, {}, query_params={p: f"entropy_probe_{p}"})
                    if single and self._is_different(baseline, single):
                        batch_hits.append(ParamHit(
                            endpoint = f"{endpoint.method.value} {endpoint.path}",
                            param    = p,
                            location = "query",
                            evidence = self._describe_diff(baseline, single),
                            severity = self._assess_severity(p),
                        ))
            return batch_hits

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = [pool.submit(probe_batch, batch) for batch in batches]
            for fut in as_completed(futures):
                try:
                    hits.extend(fut.result())
                except Exception:
                    pass

        return [self._to_finding(h) for h in hits[:10]]  # cap at 10 findings

    # ------------------------------------------------------------------

    def _request(
        self,
        url:          str,
        method:       str,
        body:         Dict,
        query_params: Optional[Dict] = None,
    ) -> Optional[Tuple[int, str, Dict]]:
        req_url  = url
        if query_params:
            req_url += "?" + urlencode(query_params)
        body_bytes = json.dumps(body).encode() if body else None
        headers    = {"Content-Type": "application/json", "Accept": "*/*", "User-Agent": "entropy/0.4.0"}
        req = urllib.request.Request(req_url, data=body_bytes, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                raw   = resp.read().decode(errors="replace")
                try:
                    parsed = json.loads(raw)
                except Exception:
                    parsed = {}
                return resp.status, raw, parsed
        except urllib.error.HTTPError as exc:
            return exc.code, "", {}
        except Exception:
            return None

    @staticmethod
    def _is_different(
        baseline: Tuple[int, str, Dict],
        probe:    Tuple[int, str, Dict],
    ) -> bool:
        if baseline[0] != probe[0]:
            return True
        # Body length difference > 10%
        bl, pl = len(baseline[1]), len(probe[1])
        if bl > 0 and abs(bl - pl) / bl > 0.10:
            return True
        # New keys in response dict
        if isinstance(baseline[2], dict) and isinstance(probe[2], dict):
            new_keys = set(probe[2].keys()) - set(baseline[2].keys())
            if new_keys:
                return True
        return False

    @staticmethod
    def _describe_diff(
        baseline: Tuple[int, str, Dict],
        probe:    Tuple[int, str, Dict],
    ) -> str:
        if baseline[0] != probe[0]:
            return f"Status changed: {baseline[0]} → {probe[0]}"
        bl, pl = len(baseline[1]), len(probe[1])
        if bl != pl:
            return f"Body size changed: {bl} → {pl} bytes"
        if isinstance(baseline[2], dict) and isinstance(probe[2], dict):
            new_keys = set(probe[2].keys()) - set(baseline[2].keys())
            if new_keys:
                return f"New response fields: {sorted(new_keys)}"
        return "Response differs"

    @staticmethod
    def _assess_severity(param: str) -> str:
        critical = {"admin", "is_admin", "role", "superuser", "bypass", "skip_auth",
                    "disable_check", "override", "sudo", "secret", "token", "jwt"}
        high     = {"debug", "internal", "dev", "test", "eval", "exec", "cmd", "command"}
        if param.lower() in critical:
            return "critical"
        if param.lower() in high:
            return "high"
        return "medium"

    def _mock_mine(self, endpoint: APIEndpoint, probes: List[str]) -> List[Finding]:
        import random
        rng     = random.Random(hash(endpoint.path))
        results = []
        for p in probes[:5]:
            if rng.random() < 0.08:
                hit = ParamHit(
                    endpoint = f"{endpoint.method.value} {endpoint.path}",
                    param    = p,
                    location = "query",
                    evidence = f"Status changed: 200 → 403 (simulated)",
                    severity = self._assess_severity(p),
                )
                results.append(self._to_finding(hit))
        return results

    def _build_ssl(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    @staticmethod
    def _to_finding(hit: ParamHit) -> Finding:
        sev_map = {
            "critical": Severity.CRITICAL,
            "high":     Severity.HIGH,
            "medium":   Severity.MEDIUM,
        }
        return Finding(
            type        = FindingType.DATA_LEAK,
            severity    = sev_map.get(hit.severity, Severity.MEDIUM),
            title       = f"Hidden Parameter: `{hit.param}`",
            description = (
                f"Undocumented parameter `{hit.param}` ({hit.location}) causes different behaviour "
                f"on `{hit.endpoint}`. This parameter is not in the API spec. Evidence: {hit.evidence}."
            ),
            endpoint    = hit.endpoint,
            evidence    = {
                "param":    hit.param,
                "location": hit.location,
                "diff":     hit.evidence,
            },
            remediation = (
                "Document all accepted parameters in the API spec. "
                "Implement server-side allowlisting — reject unknown query/body parameters. "
                "Never expose debug or admin flags in production."
            ),
        )
