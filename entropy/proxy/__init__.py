"""HTTP interception proxy — auto-fuzz real traffic in flight."""
from __future__ import annotations

import json
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse


# ---------------------------------------------------------------------------
# Payload mutator
# ---------------------------------------------------------------------------

FUZZ_PAYLOADS: Dict[str, List[Any]] = {
    "string":  [
        "' OR '1'='1", "<script>alert(1)</script>",
        "../../../../etc/passwd", "${7*7}", "{{7*7}}",
        "; ls -la", "UNION SELECT NULL--",
        "", " " * 10000,
    ],
    "integer": [0, -1, -9999999, 2**31 - 1, 2**63],
    "boolean": [True, False, None, "true", "false"],
}


def mutate_body(body: Dict) -> List[Dict]:
    """Generate fuzz variants of a JSON body."""
    variants: List[Dict] = []
    for key, value in body.items():
        if isinstance(value, str):
            for payload in FUZZ_PAYLOADS["string"][:4]:
                variant = dict(body)
                variant[key] = payload
                variants.append(variant)
        elif isinstance(value, (int, float)):
            for payload in FUZZ_PAYLOADS["integer"][:3]:
                variant = dict(body)
                variant[key] = payload
                variants.append(variant)
        elif isinstance(value, bool):
            for payload in FUZZ_PAYLOADS["boolean"][:2]:
                variant = dict(body)
                variant[key] = payload
                variants.append(variant)
    # Mass assignment — always append, never cut by cap
    mass_assign = {**body, "is_admin": True, "role": "admin"}
    capped = variants[:8]
    if mass_assign not in capped:
        capped.append(mass_assign)
    return capped


# ---------------------------------------------------------------------------
# Intercept record
# ---------------------------------------------------------------------------

@dataclass
class InterceptedRequest:
    method:  str
    url:     str
    headers: Dict[str, str]
    body:    Optional[Dict]

@dataclass
class ProxyFinding:
    url:       str
    method:    str
    payload:   Dict
    original_status: int
    fuzz_status:     int
    description:     str
    severity:        str


# ---------------------------------------------------------------------------
# Proxy handler
# ---------------------------------------------------------------------------

class ProxyHandler(BaseHTTPRequestHandler):

    def log_message(self, *args):
        pass

    def do_GET(self):    self._proxy("GET",    None)
    def do_POST(self):   self._proxy("POST",   self._read_body())
    def do_PUT(self):    self._proxy("PUT",    self._read_body())
    def do_PATCH(self):  self._proxy("PATCH",  self._read_body())
    def do_DELETE(self): self._proxy("DELETE", None)

    def _read_body(self) -> Optional[Dict]:
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except Exception:
            return None

    def _proxy(self, method: str, body: Optional[Dict]) -> None:
        url      = self.path
        headers  = {k: v for k, v in self.headers.items()
                    if k.lower() not in ("host", "connection", "proxy-connection")}
        findings = []

        # 1. Forward real request
        orig_resp = self._forward(method, url, headers, body)
        if orig_resp is None:
            self.send_error(502, "Bad Gateway")
            return

        orig_status, orig_body = orig_resp

        # 2. Respond to client
        self.send_response(orig_status)
        self.send_header("Content-Type", "application/json")
        body_bytes = json.dumps(orig_body).encode() if orig_body else b""
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

        # 3. Fuzz in background thread
        if body and isinstance(body, dict):
            threading.Thread(
                target=self._fuzz,
                args=(method, url, headers, body, orig_status),
                daemon=True,
            ).start()

    def _forward(
        self, method: str, url: str, headers: Dict, body: Optional[Dict]
    ) -> Optional[Tuple[int, Any]]:
        body_bytes = json.dumps(body).encode() if body else None
        req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                try:
                    return resp.status, json.loads(resp.read())
                except Exception:
                    return resp.status, None
        except urllib.error.HTTPError as exc:
            return exc.code, None
        except Exception:
            return None

    def _fuzz(
        self,
        method: str,
        url: str,
        headers: Dict,
        body: Dict,
        orig_status: int,
    ) -> None:
        from entropy.web import emit

        for variant in mutate_body(body):
            fuzz_resp = self._forward(method, url, headers, variant)
            if fuzz_resp is None:
                continue
            fuzz_status, _ = fuzz_resp

            finding = self._analyse(url, method, variant, orig_status, fuzz_status)
            if finding:
                emit("finding", {
                    "type":     "proxy_fuzz",
                    "severity": finding.severity,
                    "title":    finding.description,
                    "endpoint": f"{method} {url}",
                    "description": finding.description,
                })
                print(f"  [PROXY] 🚨 {finding.severity.upper()} — {finding.description} @ {url}")

    @staticmethod
    def _analyse(
        url: str, method: str, payload: Dict,
        orig_status: int, fuzz_status: int,
    ) -> Optional[ProxyFinding]:
        desc: Optional[str] = None
        sev  = "medium"

        # Attack got through when original didn't
        if fuzz_status == 200 and orig_status in (400, 401, 403, 422):
            desc = f"Attack payload bypassed server validation (orig={orig_status} → fuzz=200)"
            sev  = "critical"
        # Crash
        elif fuzz_status >= 500 and orig_status < 500:
            desc = f"Server crashed on fuzz payload (orig={orig_status} → fuzz={fuzz_status})"
            sev  = "high"
        # Mass assignment accepted
        elif "is_admin" in payload and fuzz_status in (200, 201, 202):
            desc = "Mass assignment: server accepted privileged fields"
            sev  = "critical"

        if not desc:
            return None
        return ProxyFinding(
            url=url, method=method, payload=payload,
            original_status=orig_status, fuzz_status=fuzz_status,
            description=desc, severity=sev,
        )


# ---------------------------------------------------------------------------
# Proxy server
# ---------------------------------------------------------------------------

class EntropyProxy:
    """
    HTTP interception proxy that fuzzes every request in real time.

    Point your HTTP client at http://localhost:{port} and all traffic
    will be intercepted, forwarded, and fuzz-tested automatically.
    """

    def __init__(self, port: int = 8888, host: str = "127.0.0.1"):
        self.host    = host
        self.port    = port
        self._server: Optional[HTTPServer] = None

    def start(self) -> None:
        self._server = HTTPServer((self.host, self.port), ProxyHandler)
        print(f"\n  🔀 Entropy Proxy listening on http://{self.host}:{self.port}")
        print("  Set HTTP_PROXY=http://127.0.0.1:{self.port} to intercept traffic")
        print("  Ctrl-C to stop\n")
        try:
            self._server.serve_forever()
        except KeyboardInterrupt:
            print("\n  🛑 Proxy stopped")
        finally:
            self._server.shutdown()

    def start_background(self) -> str:
        self._server = HTTPServer((self.host, self.port), ProxyHandler)
        t = threading.Thread(target=self._server.serve_forever, daemon=True)
        t.start()
        return f"http://{self.host}:{self.port}"
