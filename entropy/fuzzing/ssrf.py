"""SSRF (Server-Side Request Forgery) detection."""
from __future__ import annotations

import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

from entropy.core.models import (
    APIEndpoint, Finding, FindingType, HTTPRequest, HTTPResponse, Severity,
)


# ---------------------------------------------------------------------------
# Internal / cloud-metadata targets to probe
# ---------------------------------------------------------------------------

SSRF_TARGETS: List[Dict[str, str]] = [
    # AWS metadata
    {"url": "http://169.254.169.254/latest/meta-data/", "marker": "ami-id", "label": "AWS EC2 metadata"},
    {"url": "http://169.254.169.254/latest/meta-data/iam/", "marker": "security-credentials", "label": "AWS IAM credentials"},
    {"url": "http://169.254.169.254/latest/user-data", "marker": "", "label": "AWS user-data"},
    # GCP metadata
    {"url": "http://metadata.google.internal/computeMetadata/v1/", "marker": "project", "label": "GCP metadata"},
    # Azure metadata
    {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "marker": "azEnvironment", "label": "Azure IMDS"},
    # Internal services
    {"url": "http://localhost/", "marker": "", "label": "localhost"},
    {"url": "http://127.0.0.1/", "marker": "", "label": "127.0.0.1"},
    {"url": "http://0.0.0.0/", "marker": "", "label": "0.0.0.0"},
    {"url": "http://[::1]/", "marker": "", "label": "IPv6 loopback"},
    # Internal network ranges (RFC1918 gateways)
    {"url": "http://10.0.0.1/", "marker": "", "label": "RFC1918 10.x"},
    {"url": "http://192.168.1.1/", "marker": "", "label": "RFC1918 192.168.x"},
    {"url": "http://172.16.0.1/", "marker": "", "label": "RFC1918 172.16.x"},
]

# URL-like parameter names that frequently lead to SSRF
SSRF_PARAM_NAMES: List[str] = [
    "url", "uri", "endpoint", "redirect", "redirect_url", "return",
    "return_url", "next", "dest", "destination", "target", "src",
    "source", "href", "link", "host", "site", "path", "img",
    "image", "file", "fetch", "load", "callback", "webhook",
    "proxy", "forward", "open", "continue", "ref", "referer",
    "referrer", "to", "goto", "domain",
]

# DNS rebinding / blind SSRF markers in responses
SSRF_RESPONSE_INDICATORS: List[str] = [
    "ami-id",
    "instance-id",
    "security-credentials",
    "computeMetadata",
    "azEnvironment",
    "169.254.169.254",
    "metadata.google.internal",
]


@dataclass
class SSRFResult:
    endpoint:    str
    param:       str
    target:      str
    target_label: str
    triggered:   bool
    evidence:    str
    severity:    str = "critical"


class SSRFDetector:
    """
    Tests API endpoints for Server-Side Request Forgery vulnerabilities.

    Strategy:
      1. Find parameters with URL-like names
      2. Inject internal/cloud-metadata URLs as values
      3. Analyse response body and timing for SSRF indicators
    """

    def __init__(
        self,
        base_url:   str,
        timeout:    float = 8.0,
        verify_ssl: bool  = True,
        proxy_url:  Optional[str] = None,
        dry_run:    bool  = False,
    ):
        self.base_url   = base_url.rstrip("/")
        self.timeout    = timeout
        self.verify_ssl = verify_ssl
        self.proxy_url  = proxy_url
        self.dry_run    = dry_run

    # ------------------------------------------------------------------

    def test_endpoint(self, endpoint: APIEndpoint) -> List[Finding]:
        findings: List[Finding] = []

        ssrf_params = self._find_ssrf_params(endpoint)
        if not ssrf_params:
            return findings

        for param_name in ssrf_params:
            for target_info in SSRF_TARGETS[:6]:  # cap for speed
                if self.dry_run:
                    result = self._mock_result(endpoint, param_name, target_info)
                else:
                    result = self._probe(endpoint, param_name, target_info)

                if result and result.triggered:
                    findings.append(self._to_finding(result))

        return findings

    # ------------------------------------------------------------------

    def _find_ssrf_params(self, endpoint: APIEndpoint) -> List[str]:
        found: List[str] = []
        for param in endpoint.parameters:
            if param.name.lower() in SSRF_PARAM_NAMES:
                found.append(param.name)
        if endpoint.request_body:
            body_str = str(endpoint.request_body).lower()
            for name in SSRF_PARAM_NAMES:
                if name in body_str and name not in found:
                    found.append(name)
        return found

    def _probe(
        self,
        endpoint:    APIEndpoint,
        param_name:  str,
        target_info: Dict[str, str],
    ) -> Optional[SSRFResult]:
        url    = f"{self.base_url}{endpoint.path}"
        method = endpoint.method.value

        # Build request with SSRF payload
        payload = {param_name: target_info["url"]}
        if method == "GET":
            req_url = url + "?" + urlencode(payload)
            body    = None
        else:
            req_url = url
            body    = payload

        import json, ssl
        body_bytes = json.dumps(body).encode() if body else None
        headers    = {"Content-Type": "application/json", "Accept": "*/*"}

        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

        req = urllib.request.Request(req_url, data=body_bytes, headers=headers, method=method)

        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                latency  = (time.monotonic() - t0) * 1000
                raw_body = resp.read().decode(errors="replace")

                # Check for SSRF indicators in body
                marker = target_info.get("marker", "")
                triggered = bool(marker and marker in raw_body)
                if not triggered:
                    for indicator in SSRF_RESPONSE_INDICATORS:
                        if indicator in raw_body:
                            triggered = True
                            break

                return SSRFResult(
                    endpoint    = f"{method} {endpoint.path}",
                    param       = param_name,
                    target      = target_info["url"],
                    target_label= target_info["label"],
                    triggered   = triggered,
                    evidence    = raw_body[:300] if triggered else "",
                )
        except Exception:
            # Timeout / connection error to internal address can itself be indicative
            latency = (time.monotonic() - t0) * 1000
            # If we got a connection to an internal host (latency < timeout and actual error)
            return None

    def _mock_result(
        self,
        endpoint:    APIEndpoint,
        param_name:  str,
        target_info: Dict[str, str],
    ) -> Optional[SSRFResult]:
        import random
        rng = random.Random(hash(endpoint.path + param_name + target_info["url"]))
        if rng.random() < 0.15:  # 15% simulated hit
            return SSRFResult(
                endpoint     = f"{endpoint.method.value} {endpoint.path}",
                param        = param_name,
                target       = target_info["url"],
                target_label = target_info["label"],
                triggered    = True,
                evidence     = f"ami-id: ami-12345678 (simulated)",
                severity     = "critical",
            )
        return None

    # ------------------------------------------------------------------

    @staticmethod
    def _to_finding(result: SSRFResult) -> Finding:
        return Finding(
            type        = FindingType.SSRF,
            severity    = Severity.CRITICAL,
            title       = f"SSRF — {result.target_label}",
            description = (
                f"Parameter `{result.param}` on `{result.endpoint}` fetches "
                f"attacker-controlled URLs. Injected `{result.target}` and received "
                f"a response containing internal metadata."
            ),
            endpoint    = result.endpoint,
            evidence    = {
                "param":        result.param,
                "ssrf_target":  result.target,
                "target_label": result.target_label,
                "response_snippet": result.evidence,
            },
            remediation = (
                "Implement a strict allowlist of permitted URL schemes and hosts. "
                "Block requests to RFC1918 ranges and cloud metadata endpoints at the network layer. "
                "Use a dedicated egress proxy with outbound filtering."
            ),
        )
