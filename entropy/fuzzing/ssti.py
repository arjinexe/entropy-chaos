"""SSTI (Server-Side Template Injection) detection."""
from __future__ import annotations

import json
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

from entropy.core.models import (
    APIEndpoint, Finding, FindingType, HTTPRequest, HTTPResponse, Severity,
)


# ---------------------------------------------------------------------------
# Probe payloads — each has a unique expected result
# ---------------------------------------------------------------------------

SSTI_PROBES: List[Dict[str, Any]] = [
    # Jinja2 / Twig / Nunjucks
    {"payload": "{{7*7}}",              "expect": "49",       "engine": "Jinja2/Twig"},
    {"payload": "{{7*'7'}}",            "expect": "7777777",  "engine": "Twig"},
    {"payload": "${7*7}",               "expect": "49",       "engine": "FreeMarker/EL"},
    {"payload": "#{7*7}",               "expect": "49",       "engine": "Thymeleaf/OGNL"},
    {"payload": "<%= 7*7 %>",           "expect": "49",       "engine": "ERB/EJS"},
    {"payload": "${7*7}",               "expect": "49",       "engine": "Spring EL"},
    {"payload": "{{config}}",           "expect": "SECRET",   "engine": "Flask/Jinja2 config leak"},
    {"payload": "{{self.__class__}}",   "expect": "__main__", "engine": "Jinja2 class leak"},
    # FreeMarker
    {"payload": "<#assign ex = 'freemarker.template.utility.Execute'?new()>${ex('id')}", "expect": "uid=", "engine": "FreeMarker RCE"},
    # Smarty
    {"payload": "{7*7}",               "expect": "49",        "engine": "Smarty"},
    # Velocity
    {"payload": "#set($a=7*7)$a",      "expect": "49",        "engine": "Velocity"},
    # Pebble
    {"payload": "{{7*7}}",             "expect": "49",        "engine": "Pebble"},
]


@dataclass
class SSTIResult:
    endpoint:  str
    param:     str
    payload:   str
    expected:  str
    engine:    str
    response_body: str
    confirmed: bool


class SSTIDetector:
    """
    Detects Server-Side Template Injection by injecting arithmetic probes
    and checking if the template engine evaluated them.
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
        self._ctx       = self._build_ssl_ctx()

    # ------------------------------------------------------------------

    def test_endpoint(self, endpoint: APIEndpoint) -> List[Finding]:
        findings: List[Finding] = []
        string_params = self._find_string_params(endpoint)
        if not string_params:
            return findings

        for param in string_params:
            for probe in SSTI_PROBES[:6]:  # top 6 for speed
                if self.dry_run:
                    result = self._mock_result(endpoint, param, probe)
                else:
                    result = self._probe(endpoint, param, probe)
                if result and result.confirmed:
                    findings.append(self._to_finding(result))
                    break  # one confirmed hit per param is enough

        return findings

    # ------------------------------------------------------------------

    def _find_string_params(self, endpoint: APIEndpoint) -> List[str]:
        params = []
        for p in endpoint.parameters:
            if p.type in ("string", "") or p.type is None:
                params.append(p.name)
        if endpoint.request_body:
            body = endpoint.request_body
            if isinstance(body, dict):
                props = body.get("properties") or {}
                for k, v in props.items():
                    if isinstance(v, dict) and v.get("type") == "string":
                        params.append(k)
        return params[:5]  # cap

    def _probe(
        self,
        endpoint: APIEndpoint,
        param:    str,
        probe:    Dict[str, Any],
    ) -> Optional[SSTIResult]:
        url    = f"{self.base_url}{endpoint.path}"
        method = endpoint.method.value

        if method == "GET":
            req_url = url + "?" + urlencode({param: probe["payload"]})
            body    = None
        else:
            req_url = url
            body    = json.dumps({param: probe["payload"]}).encode()

        headers = {"Content-Type": "application/json", "Accept": "*/*", "User-Agent": "entropy/0.4.0"}
        req     = urllib.request.Request(req_url, data=body, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                raw = resp.read().decode(errors="replace")
                confirmed = probe["expect"] in raw
                return SSTIResult(
                    endpoint     = f"{method} {endpoint.path}",
                    param        = param,
                    payload      = probe["payload"],
                    expected     = probe["expect"],
                    engine       = probe["engine"],
                    response_body= raw[:500],
                    confirmed    = confirmed,
                )
        except Exception:
            return None

    def _mock_result(
        self,
        endpoint: APIEndpoint,
        param:    str,
        probe:    Dict[str, Any],
    ) -> Optional[SSTIResult]:
        import random
        rng = random.Random(hash(endpoint.path + param + probe["payload"]))
        if rng.random() < 0.08:
            return SSTIResult(
                endpoint     = f"{endpoint.method.value} {endpoint.path}",
                param        = param,
                payload      = probe["payload"],
                expected     = probe["expect"],
                engine       = probe["engine"],
                response_body= f"Result: {probe['expect']} (simulated evaluation)",
                confirmed    = True,
            )
        return None

    def _build_ssl_ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    @staticmethod
    def _to_finding(result: SSTIResult) -> Finding:
        sev = Severity.CRITICAL if "RCE" in result.engine else Severity.HIGH
        return Finding(
            type        = FindingType.INJECTION,
            severity    = sev,
            title       = f"SSTI — {result.engine}",
            description = (
                f"Template injection confirmed on `{result.endpoint}` parameter `{result.param}`. "
                f"Payload `{result.payload}` produced expected output `{result.expected}`. "
                f"Detected engine: {result.engine}."
            ),
            endpoint    = result.endpoint,
            evidence    = {
                "param":    result.param,
                "payload":  result.payload,
                "expected": result.expected,
                "engine":   result.engine,
                "response_snippet": result.response_body[:300],
            },
            remediation = (
                "Never pass user input directly into template rendering functions. "
                "Use a sandboxed template engine or escape all user-controlled values "
                "before passing them to the template context."
            ),
        )
