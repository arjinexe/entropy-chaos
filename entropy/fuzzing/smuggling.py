"""HTTP Request Smuggling detection (CL.TE, TE.CL, TE.TE)."""
from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from entropy.core.models import Finding, FindingType, Severity


# ---------------------------------------------------------------------------
# Timing-based detection probes
# ---------------------------------------------------------------------------

# CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding
CL_TE_PROBE = (
    "POST {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 6\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "X"
)

# TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length
TE_CL_PROBE = (
    "POST {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 3\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "1\r\n"
    "X\r\n"
    "0\r\n"
    "\r\n"
)

# TE.TE obfuscation probes (header variations to confuse one parser)
TE_OBFUSCATION_VARIANTS = [
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
    "Transfer-Encoding:\x0bchunked",
    "X-Transfer-Encoding: chunked",
]


@dataclass
class SmuggleResult:
    attack_type:  str
    host:         str
    path:         str
    timing_delta: float   # ms difference vs baseline
    confirmed:    bool


class RequestSmugglingDetector:
    """
    Detects HTTP Request Smuggling via timing analysis.

    CL.TE: Send ambiguous request where CL says body is complete but
           TE leaves the back-end waiting — timing difference reveals mismatch.
    TE.CL: Inverse.

    NOTE: This is inherently a timing-based technique. False positives
    are possible on slow networks. Confirmed only when delta > 4s.
    """

    TIMING_THRESHOLD_MS = 4000   # 4 seconds delta = likely smuggling
    TIMEOUT             = 8.0

    def __init__(
        self,
        target_url: str,
        verify_ssl: bool = True,
        dry_run:    bool = False,
    ):
        parsed        = urlparse(target_url)
        self.host     = parsed.hostname or "localhost"
        self.port     = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.path     = parsed.path or "/"
        self.use_tls  = parsed.scheme == "https"
        self.verify_ssl = verify_ssl
        self.dry_run  = dry_run

    # ------------------------------------------------------------------

    def detect(self) -> List[Finding]:
        if self.dry_run:
            return []   # smuggling detection must not run in dry-run (real timing needed)

        findings: List[Finding] = []

        # Baseline: normal request latency
        baseline = self._baseline_latency()
        if baseline is None:
            return findings

        # CL.TE probe
        cl_te = self._probe_cl_te(baseline)
        if cl_te and cl_te.confirmed:
            findings.append(self._to_finding(cl_te))

        # TE.CL probe
        te_cl = self._probe_te_cl(baseline)
        if te_cl and te_cl.confirmed:
            findings.append(self._to_finding(te_cl))

        return findings

    # ------------------------------------------------------------------

    def _baseline_latency(self) -> Optional[float]:
        probe = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            "Connection: close\r\n\r\n"
        )
        start = time.monotonic()
        try:
            self._raw_send(probe, timeout=5.0)
            return (time.monotonic() - start) * 1000
        except Exception:
            return None

    def _probe_cl_te(self, baseline_ms: float) -> Optional[SmuggleResult]:
        probe = CL_TE_PROBE.format(host=self.host, path=self.path)
        start = time.monotonic()
        try:
            self._raw_send(probe, timeout=self.TIMEOUT)
            delta = (time.monotonic() - start) * 1000 - baseline_ms
            return SmuggleResult(
                attack_type  = "CL.TE",
                host         = self.host,
                path         = self.path,
                timing_delta = delta,
                confirmed    = delta > self.TIMING_THRESHOLD_MS,
            )
        except (socket.timeout, TimeoutError):
            delta = self.TIMEOUT * 1000
            return SmuggleResult("CL.TE", self.host, self.path, delta, delta > self.TIMING_THRESHOLD_MS)
        except Exception:
            return None

    def _probe_te_cl(self, baseline_ms: float) -> Optional[SmuggleResult]:
        probe = TE_CL_PROBE.format(host=self.host, path=self.path)
        start = time.monotonic()
        try:
            self._raw_send(probe, timeout=self.TIMEOUT)
            delta = (time.monotonic() - start) * 1000 - baseline_ms
            return SmuggleResult(
                attack_type  = "TE.CL",
                host         = self.host,
                path         = self.path,
                timing_delta = delta,
                confirmed    = delta > self.TIMING_THRESHOLD_MS,
            )
        except (socket.timeout, TimeoutError):
            delta = self.TIMEOUT * 1000
            return SmuggleResult("TE.CL", self.host, self.path, delta, delta > self.TIMING_THRESHOLD_MS)
        except Exception:
            return None

    def _raw_send(self, request: str, timeout: float = 8.0) -> bytes:
        sock = socket.create_connection((self.host, self.port), timeout=timeout)
        if self.use_tls:
            ctx = ssl.create_default_context()
            if not self.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        try:
            sock.sendall(request.encode())
            return sock.recv(4096)
        finally:
            sock.close()

    @staticmethod
    def _to_finding(result: SmuggleResult) -> Finding:
        return Finding(
            type        = FindingType.LOGIC_ERROR,
            severity    = Severity.CRITICAL,
            title       = f"HTTP Request Smuggling ({result.attack_type})",
            description = (
                f"{result.attack_type} request smuggling detected on {result.host}. "
                f"Timing delta: {result.timing_delta:.0f}ms above baseline. "
                "An attacker can poison the back-end request queue to hijack other users' requests."
            ),
            endpoint    = f"POST {result.path}",
            evidence    = {
                "attack_type":   result.attack_type,
                "timing_delta_ms": round(result.timing_delta, 1),
            },
            remediation = (
                "Ensure front-end and back-end servers agree on a single body framing mechanism. "
                "If using HTTP/1.1, reject requests with both Content-Length and Transfer-Encoding headers. "
                "Prefer HTTP/2 end-to-end to eliminate this class of vulnerability."
            ),
        )
