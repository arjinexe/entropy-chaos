"""Compare two API targets and report response divergences."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from entropy.core.models import APIEndpoint, APISchema


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

@dataclass
class ResponseSnapshot:
    target:      str
    status_code: int
    body:        Any
    latency_ms:  float
    headers:     Dict[str, str] = field(default_factory=dict)
    error:       Optional[str]  = None


@dataclass
class Divergence:
    endpoint:    str
    kind:        str           # status_diff | body_diff | schema_diff | latency_diff | error_diff
    description: str
    severity:    str           # critical | high | medium | low
    snap_a:      ResponseSnapshot = None
    snap_b:      ResponseSnapshot = None

    @property
    def summary(self) -> str:
        return f"[{self.severity.upper()}] {self.kind} @ {self.endpoint}: {self.description}"


@dataclass
class DiffReport:
    target_a:    str
    target_b:    str
    divergences: List[Divergence] = field(default_factory=list)
    endpoints_tested: int = 0
    duration_s:  float = 0.0

    @property
    def has_breaking_changes(self) -> bool:
        return any(d.severity in ("critical", "high") for d in self.divergences)

    def summary(self) -> str:
        return (
            f"Differential: {self.target_a} vs {self.target_b} — "
            f"{self.endpoints_tested} endpoints, "
            f"{len(self.divergences)} divergence(s)"
            + (" ⚠ BREAKING CHANGES" if self.has_breaking_changes else "")
        )


# ---------------------------------------------------------------------------
# Tester
# ---------------------------------------------------------------------------

class DifferentialTester:
    """
    Sends identical requests to two API targets and compares responses.

    Detects:
      - Status code differences (breaking change indicator)
      - Response body schema changes (new/removed fields)
      - Significant latency differences (performance regression)
      - Error-only-on-one-side (partial failure)
    """

    LATENCY_DIFF_THRESHOLD = 2.0    # flag if B is 2× slower than A
    LATENCY_ABS_MS         = 500    # only flag if diff > 500ms absolute

    def __init__(
        self,
        target_a:   str,
        target_b:   str,
        timeout:    float = 10.0,
        verify_ssl: bool  = True,
        proxy_url:  Optional[str] = None,
        auth_headers: Optional[Dict[str, str]] = None,
    ):
        self.target_a     = target_a.rstrip("/")
        self.target_b     = target_b.rstrip("/")
        self.timeout      = timeout
        self.auth_headers = auth_headers or {}
        self._ctx         = self._build_ssl_ctx(verify_ssl)
        self._opener      = self._build_opener(proxy_url)

    # ------------------------------------------------------------------

    def run(self, schema: APISchema) -> DiffReport:
        start  = time.monotonic()
        report = DiffReport(target_a=self.target_a, target_b=self.target_b)

        for endpoint in schema.endpoints:
            divergences = self._compare_endpoint(endpoint)
            report.divergences.extend(divergences)
            report.endpoints_tested += 1

        report.duration_s = time.monotonic() - start
        return report

    def compare_url(self, path: str, method: str = "GET", body: Optional[Dict] = None) -> List[Divergence]:
        """Compare a single URL path between the two targets."""
        ep = _MockEndpoint(path=path, method=method)
        return self._compare_endpoint(ep, body=body)

    # ------------------------------------------------------------------

    def _compare_endpoint(self, endpoint, body: Optional[Dict] = None) -> List[Divergence]:
        path   = endpoint.path
        method = endpoint.method.value if hasattr(endpoint.method, "value") else endpoint.method

        snap_a = self._request(self.target_a + path, method, body)
        snap_b = self._request(self.target_b + path, method, body)

        return self._analyse(f"{method} {path}", snap_a, snap_b)

    def _analyse(
        self,
        endpoint: str,
        snap_a:   ResponseSnapshot,
        snap_b:   ResponseSnapshot,
    ) -> List[Divergence]:
        divs: List[Divergence] = []

        # 1. Status code difference
        if snap_a.status_code != snap_b.status_code:
            sev = "critical" if self._is_breaking_status_change(snap_a.status_code, snap_b.status_code) else "high"
            divs.append(Divergence(
                endpoint    = endpoint,
                kind        = "status_diff",
                description = f"Status {snap_a.status_code} (A) vs {snap_b.status_code} (B)",
                severity    = sev,
                snap_a      = snap_a,
                snap_b      = snap_b,
            ))

        # 2. Error on one side only
        if bool(snap_a.error) != bool(snap_b.error):
            divs.append(Divergence(
                endpoint    = endpoint,
                kind        = "error_diff",
                description = f"Error on {'A' if snap_a.error else 'B'}: {snap_a.error or snap_b.error}",
                severity    = "high",
                snap_a      = snap_a,
                snap_b      = snap_b,
            ))

        # 3. Body schema divergence (added/removed keys)
        if isinstance(snap_a.body, dict) and isinstance(snap_b.body, dict):
            keys_a = set(snap_a.body.keys())
            keys_b = set(snap_b.body.keys())
            added   = keys_b - keys_a
            removed = keys_a - keys_b
            if added or removed:
                parts = []
                if removed:
                    parts.append(f"removed: {sorted(removed)}")
                if added:
                    parts.append(f"added: {sorted(added)}")
                divs.append(Divergence(
                    endpoint    = endpoint,
                    kind        = "schema_diff",
                    description = f"Response schema changed — {'; '.join(parts)}",
                    severity    = "high" if removed else "medium",
                    snap_a      = snap_a,
                    snap_b      = snap_b,
                ))

        # 4. Significant latency difference
        if snap_a.latency_ms > 0 and snap_b.latency_ms > 0:
            ratio    = snap_b.latency_ms / max(snap_a.latency_ms, 1)
            abs_diff = abs(snap_b.latency_ms - snap_a.latency_ms)
            if ratio > self.LATENCY_DIFF_THRESHOLD and abs_diff > self.LATENCY_ABS_MS:
                divs.append(Divergence(
                    endpoint    = endpoint,
                    kind        = "latency_diff",
                    description = (
                        f"B is {ratio:.1f}× slower than A "
                        f"({snap_a.latency_ms:.0f}ms vs {snap_b.latency_ms:.0f}ms)"
                    ),
                    severity    = "medium",
                    snap_a      = snap_a,
                    snap_b      = snap_b,
                ))

        return divs

    @staticmethod
    def _is_breaking_status_change(a: int, b: int) -> bool:
        """Returns True if the status code change represents a breaking API change."""
        # 2xx → 4xx/5xx = always breaking
        if 200 <= a < 300 and b >= 400:
            return True
        # 404 → 200 could indicate new endpoint (not breaking, but notable)
        # 200 → 404 = endpoint removed = breaking
        if a == 200 and b == 404:
            return True
        return False

    # ------------------------------------------------------------------

    def _request(self, url: str, method: str, body: Optional[Dict]) -> ResponseSnapshot:
        headers = {
            "Content-Type": "application/json",
            "Accept":       "application/json",
            **self.auth_headers,
        }
        body_bytes = json.dumps(body).encode() if body else None
        req = urllib.request.Request(
            url=url, data=body_bytes, headers=headers, method=method
        )
        start = time.monotonic()
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                latency = (time.monotonic() - start) * 1000
                raw     = resp.read()
                try:
                    parsed_body = json.loads(raw)
                except Exception:
                    parsed_body = raw.decode(errors="replace")
                return ResponseSnapshot(
                    target=url, status_code=resp.status,
                    body=parsed_body, latency_ms=latency,
                    headers=dict(resp.headers),
                )
        except urllib.error.HTTPError as exc:
            latency = (time.monotonic() - start) * 1000
            try:
                parsed_body = json.loads(exc.read())
            except Exception:
                parsed_body = None
            return ResponseSnapshot(
                target=url, status_code=exc.code,
                body=parsed_body, latency_ms=latency,
                error=str(exc),
            )
        except Exception as exc:
            latency = (time.monotonic() - start) * 1000
            return ResponseSnapshot(
                target=url, status_code=0,
                body=None, latency_ms=latency,
                error=str(exc),
            )

    @staticmethod
    def _build_ssl_ctx(verify_ssl: bool) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    def _build_opener(self, proxy_url: Optional[str]):
        handlers: list = [urllib.request.HTTPSHandler(context=self._ctx)]
        if proxy_url:
            handlers.append(urllib.request.ProxyHandler({
                "http": proxy_url, "https": proxy_url,
            }))
        return urllib.request.build_opener(*handlers)


class _MockEndpoint:
    """Minimal endpoint shim for compare_url."""
    def __init__(self, path: str, method: str):
        self.path   = path
        self.method = method
