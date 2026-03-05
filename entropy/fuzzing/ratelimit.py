"""Rate limit detection — finds missing limits and common bypass techniques."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Bypass header sets to try
# ---------------------------------------------------------------------------

BYPASS_HEADERS: List[Dict[str, str]] = [
    # IP spoofing
    {"X-Forwarded-For": "203.0.113.1"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Real-IP": "203.0.113.2"},
    {"CF-Connecting-IP": "203.0.113.3"},
    {"True-Client-IP": "203.0.113.4"},
    {"X-Originating-IP": "203.0.113.5"},
    # Custom rate-limit identity spoofing
    {"X-User-ID": "bypass-test"},
    {"X-Api-Version": "internal"},
    {"X-Internal-Request": "true"},
    # Endpoint casing / trailing slash variation
    {},  # baseline (no extra headers)
]

PATH_VARIATIONS: List[str] = [
    "",          # original
    "/",         # trailing slash
    "//",        # double slash
    "?_=1",      # cache-bust param
    "#fragment", # fragment (some proxies strip)
]


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass
class RateLimitProbe:
    """Single probe result."""
    request_number: int
    status_code:    int
    latency_ms:     float
    retry_after:    Optional[int]   = None   # Retry-After header value


@dataclass
class RateLimitResult:
    url:             str
    limit_at:        Optional[int]   = None   # request # that triggered 429
    limit_window:    Optional[str]   = None   # e.g. "60s" inferred from Retry-After
    bypass_vectors:  List[str]       = field(default_factory=list)
    probes:          List[RateLimitProbe] = field(default_factory=list)
    has_rate_limit:  bool            = False
    retry_after_respected: Optional[bool] = None

    @property
    def severity(self) -> str:
        if not self.has_rate_limit:
            return "high"          # no rate limit at all = HIGH
        if self.bypass_vectors:
            return "critical"      # bypassable = CRITICAL
        return "info"              # rate limit present and working = INFO

    @property
    def summary(self) -> str:
        if not self.has_rate_limit:
            return f"No rate limit detected after {len(self.probes)} requests"
        bypass = f" | Bypasses: {self.bypass_vectors}" if self.bypass_vectors else ""
        return f"Rate limit at request #{self.limit_at}{bypass}"


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class RateLimitDetector:
    """
    Probes an endpoint to characterise its rate limiting behaviour.

    Strategy:
      1. Send requests until 429 is returned (up to max_probes)
      2. If 429 found, test each bypass vector
      3. If 429 found, test Retry-After compliance
    """

    def __init__(
        self,
        url:         str,
        method:      str   = "GET",
        body:        Optional[Dict] = None,
        headers:     Optional[Dict[str, str]] = None,
        timeout:     float = 8.0,
        max_probes:  int   = 60,
        delay_ms:    float = 50,
        verify_ssl:  bool  = True,
        proxy_url:   Optional[str] = None,
    ):
        self.url        = url
        self.method     = method
        self.body       = body
        self.headers    = headers or {"Content-Type": "application/json", "Accept": "application/json"}
        self.timeout    = timeout
        self.max_probes = max_probes
        self.delay_ms   = delay_ms
        self._ctx       = self._build_ssl_ctx(verify_ssl)
        self._opener    = self._build_opener(proxy_url)

    # ------------------------------------------------------------------

    def probe(self) -> RateLimitResult:
        result = RateLimitResult(url=self.url)

        # Phase 1: find the limit
        limit_at = self._find_limit(result)
        result.has_rate_limit = limit_at is not None
        result.limit_at       = limit_at

        if not result.has_rate_limit:
            return result

        # Phase 2: infer window from Retry-After
        retry_afters = [p.retry_after for p in result.probes if p.retry_after]
        if retry_afters:
            result.limit_window = f"{retry_afters[-1]}s"

        # Phase 3: bypass vectors
        result.bypass_vectors = self._find_bypasses()

        # Phase 4: Retry-After compliance
        if retry_afters:
            result.retry_after_respected = self._test_retry_after_compliance(retry_afters[0])

        return result

    # ------------------------------------------------------------------

    def _find_limit(self, result: RateLimitResult) -> Optional[int]:
        for i in range(1, self.max_probes + 1):
            status, latency, retry_after = self._send(self.url, self.headers, self.body)
            result.probes.append(RateLimitProbe(
                request_number=i,
                status_code=status,
                latency_ms=latency,
                retry_after=retry_after,
            ))

            if status == 429:
                return i

            if status == 0:
                break  # network error

            time.sleep(self.delay_ms / 1000)

        return None

    def _find_bypasses(self) -> List[str]:
        bypasses: List[str] = []

        # Test header-based bypasses
        for extra_headers in BYPASS_HEADERS:
            if not extra_headers:
                continue
            merged = {**self.headers, **extra_headers}
            # Send a burst to re-trigger limit
            for _ in range(3):
                status, _, _ = self._send(self.url, merged, self.body)
                if status == 429:
                    break
            else:
                # Didn't get 429 — bypass works
                header_name = list(extra_headers.keys())[0]
                bypasses.append(f"Header bypass: {header_name}")

        # Test path variation bypasses
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(self.url)
        for variation in PATH_VARIATIONS[1:]:   # skip original
            variant_url = urlunparse(parsed._replace(path=parsed.path + variation))
            for _ in range(3):
                status, _, _ = self._send(variant_url, self.headers, self.body)
                if status == 429:
                    break
            else:
                bypasses.append(f"Path variation bypass: {variation!r}")

        return bypasses

    def _test_retry_after_compliance(self, retry_after_s: int) -> bool:
        """Wait Retry-After seconds, then check if limit is lifted."""
        wait = min(retry_after_s, 5)   # cap at 5s for testing
        time.sleep(wait)
        status, _, _ = self._send(self.url, self.headers, self.body)
        return status != 429

    # ------------------------------------------------------------------

    def _send(
        self,
        url:     str,
        headers: Dict[str, str],
        body:    Optional[Dict],
    ) -> Tuple[int, float, Optional[int]]:
        body_bytes = json.dumps(body).encode() if body else None
        req = urllib.request.Request(
            url=url, data=body_bytes,
            headers=headers, method=self.method,
        )
        start = time.monotonic()
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                latency = (time.monotonic() - start) * 1000
                return resp.status, latency, None
        except urllib.error.HTTPError as exc:
            latency     = (time.monotonic() - start) * 1000
            retry_after = None
            try:
                retry_after = int(exc.headers.get("Retry-After", 0)) or None
            except Exception:
                pass
            return exc.code, latency, retry_after
        except Exception:
            latency = (time.monotonic() - start) * 1000
            return 0, latency, None

    @staticmethod
    def _build_ssl_ctx(verify_ssl: bool) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    def _build_opener(self, proxy_url: Optional[str]):
        handlers = []
        if proxy_url:
            handlers.append(urllib.request.ProxyHandler({
                "http":  proxy_url,
                "https": proxy_url,
            }))
        ctx_handler = urllib.request.HTTPSHandler(context=self._ctx)
        handlers.append(ctx_handler)
        return urllib.request.build_opener(*handlers)


# ---------------------------------------------------------------------------
# Simulation helper (for dry-run / testing)
# ---------------------------------------------------------------------------

class MockRateLimitDetector(RateLimitDetector):
    """Simulates rate limit detection without real HTTP — for dry-run mode."""

    def probe(self) -> RateLimitResult:
        import random
        rng     = random.Random(hash(self.url))
        limit   = rng.randint(5, 30)
        result  = RateLimitResult(url=self.url, has_rate_limit=True, limit_at=limit)
        result.probes = [
            RateLimitProbe(i, 200 if i < limit else 429, rng.uniform(30, 200))
            for i in range(1, min(limit + 3, self.max_probes) + 1)
        ]
        result.limit_window    = "60s"
        result.bypass_vectors  = (
            ["Header bypass: X-Forwarded-For"] if rng.random() < 0.4 else []
        )
        result.retry_after_respected = rng.random() > 0.3
        return result
