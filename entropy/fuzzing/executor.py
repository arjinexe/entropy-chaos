""""HTTP executor with retry, backoff, cookie jar, and dry-run support."""
from __future__ import annotations

import asyncio
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

from entropy.core.models import (
    Finding, FindingType, HTTPRequest, HTTPResponse,
    Severity, TestStep,
)


# ---------------------------------------------------------------------------
# Anomaly detection rules
# ---------------------------------------------------------------------------

@dataclass
class AnomalyRule:
    name:        str
    description: str
    finding_type: FindingType
    severity:    Severity

    def check(
        self,
        req: HTTPRequest,
        resp: HTTPResponse,
        context: Dict[str, Any],
    ) -> bool:
        """Return True if anomaly is detected."""
        raise NotImplementedError


class ServerErrorRule(AnomalyRule):
    def __init__(self):
        super().__init__(
            name="Server Error (5xx)",
            description="Server returned a 5xx error — may indicate unhandled exception or crash.",
            finding_type=FindingType.CRASH,
            severity=Severity.HIGH,
        )

    # Payloads likely to reveal server crashes when mishandled
    _TRIGGER_HINTS = [
        "' or", "' or '", "select ", "union ", "drop ", "--",
        "<script>", "javascript:", "onerror=", "onload=",
        "../../../../", "%2e%2e", "${", "{{", "<%",
        "\x00", "%00", "\u0000",
        "; ls", "| cat", "`id`",
        "null", "undefined", "nan", "infinity",
    ]

    def check(self, req, resp, context):
        if resp.status_code < 500:
            return False
        # Always flag if request contained a known attack payload
        body_str = str(req.body or "").lower()
        params_str = str(req.params or "").lower()
        combined = body_str + params_str + req.url.lower()
        for hint in self._TRIGGER_HINTS:
            if hint in combined:
                return True
        # Also flag if the response leaks internal error details
        resp_str = str(resp.body or "").lower()
        for leak in ("traceback", "exception", "syntax error", "at line", "stack trace",
                     "sqlstate", "mysql", "postgresql", "sqlite", "ora-", "django",
                     "flask", "rails", "laravel", "express"):
            if leak in resp_str:
                return True
        return False


class NegativeValueAcceptedRule(AnomalyRule):
    def __init__(self):
        super().__init__(
            name="Negative Value Accepted",
            description="Server accepted a negative quantity/amount without rejection.",
            finding_type=FindingType.BUSINESS_LOGIC,
            severity=Severity.CRITICAL,
        )

    def check(self, req, resp, context):
        if resp.status_code not in (200, 201, 202):
            return False
        body = req.body or {}
        if isinstance(body, dict):
            for key in ("quantity", "amount", "count", "price", "total", "balance"):
                val = body.get(key)
                if isinstance(val, (int, float)) and val < 0:
                    return True
        return False


class PrivilegeFieldAcceptedRule(AnomalyRule):
    def __init__(self):
        super().__init__(
            name="Mass Assignment / Privilege Field Accepted",
            description="Server accepted privileged fields (is_admin, role) set by the client.",
            finding_type=FindingType.AUTH_BYPASS,
            severity=Severity.CRITICAL,
        )

    def check(self, req, resp, context):
        if resp.status_code not in (200, 201, 202):
            return False
        body = req.body or {}
        if isinstance(body, dict):
            for key in ("is_admin", "role", "permissions", "admin"):
                if key in body:
                    # Check if the response echoes back the privileged value
                    resp_text = str(resp.body or "")
                    if "admin" in resp_text.lower() or "true" in resp_text.lower():
                        return True
        return False


class IDORRule(AnomalyRule):
    def __init__(self):
        super().__init__(
            name="Potential IDOR",
            description="Request with low/predictable ID returned 200; may expose another user's data.",
            finding_type=FindingType.DATA_LEAK,
            severity=Severity.HIGH,
        )

    _SENSITIVE_FIELDS = {"email", "password", "token", "secret", "ssn", "phone",
                         "balance", "credit_card", "is_admin", "role"}

    def check(self, req, resp, context):
        if resp.status_code != 200:
            return False
        import re
        # Trigger on small predictable IDs in URL (1, 2, 3, 99, etc.)
        if re.search(r"[=/](0|1|2|3|4|5|99|100)\b", req.url):
            resp_body = resp.body
            if isinstance(resp_body, dict) and resp_body:
                # Flag if response contains sensitive-looking fields
                if any(k in self._SENSITIVE_FIELDS for k in resp_body):
                    return True
                # Or just any non-empty object returned
                if len(resp_body) >= 2:
                    return True
        return False


class RaceConditionRule(AnomalyRule):
    def __init__(self):
        super().__init__(
            name="Race Condition",
            description="Multiple concurrent requests all returned 200 for a limited resource.",
            finding_type=FindingType.RACE_CONDITION,
            severity=Severity.CRITICAL,
        )

    def check(self, req, resp, context):
        success_count = context.get("concurrent_success_count", 0)
        return success_count > 1 and resp.status_code == 200


class InjectionSuccessRule(AnomalyRule):
    def __init__(self):
        super().__init__(
            name="Injection Reflected",
            description="Injected payload was reflected in the response without sanitization.",
            finding_type=FindingType.INJECTION,
            severity=Severity.HIGH,
        )

    _INJECT_MARKERS = [
        "<script>", "alert(", "49",         # 7*7 template injection
        "root:", "/etc/passwd", "syntax error",
        "sql", "mysql", "sqlite", "postgresql",
        "ora-", "sqlstate", "warning:", "fatal error",
    ]

    # Markers that only need to appear in the RESPONSE (not in request)
    # — i.e. the server leaked something it shouldn't
    _RESPONSE_ONLY_LEAKS = [
        "sql syntax", "you have an error in your sql",
        "warning: mysql", "unclosed quotation",
        "quoted string not properly terminated",
        "pg_query()", "supplied argument is not a valid",
        "division by zero", "odbc_exec",
        "microsoft ole db provider", "syntax error near",
        "unterminated string literal",
    ]

    def check(self, req, resp, context):
        resp_text = str(resp.body or "").lower()
        body = req.body or {}
        body_str = str(body).lower()
        url_str  = req.url.lower()

        # Payload in request AND reflected in response
        for marker in self._INJECT_MARKERS:
            if marker in body_str and marker in resp_text:
                return True

        # SQL/server error leaked in response (regardless of payload)
        if resp.status_code in (200, 500):
            for leak in self._RESPONSE_ONLY_LEAKS:
                if leak in resp_text:
                    return True

        return False


class SlowResponseRule(AnomalyRule):
    def __init__(self, threshold_ms: float = 5000.0):
        super().__init__(
            name="Abnormally Slow Response",
            description=f"Response took longer than {threshold_ms}ms — possible DoS vector.",
            finding_type=FindingType.PERFORMANCE,
            severity=Severity.MEDIUM,
        )
        self.threshold_ms = threshold_ms

    def check(self, req, resp, context):
        return resp.latency_ms > self.threshold_ms


DEFAULT_RULES: List[AnomalyRule] = [
    ServerErrorRule(),
    NegativeValueAcceptedRule(),
    PrivilegeFieldAcceptedRule(),
    IDORRule(),
    RaceConditionRule(),
    InjectionSuccessRule(),
    SlowResponseRule(),
]


# ---------------------------------------------------------------------------
# HTTP Executor
# ---------------------------------------------------------------------------

class HTTPExecutor:
    """
    Sends HTTP requests and returns (HTTPResponse, List[Finding]).

    dry_run=True: simulates responses locally without network calls.
    """

    def __init__(
        self,
        dry_run: bool = False,
        timeout: float = 10.0,
        rules: Optional[List[AnomalyRule]] = None,
    ):
        self.dry_run = dry_run
        self.timeout = timeout
        self.rules   = rules or DEFAULT_RULES

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(
        self,
        request: HTTPRequest,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[HTTPResponse, List[Finding]]:
        """Execute a single request synchronously."""
        ctx = context or {}
        if self.dry_run:
            resp = self._simulate_response(request)
        else:
            resp = self._send_real_request(request)
        findings = self._evaluate_rules(request, resp, ctx)
        return resp, findings

    async def execute_async(
        self,
        request: HTTPRequest,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[HTTPResponse, List[Finding]]:
        """Execute a single request asynchronously (runs in thread pool)."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.execute, request, context)

    async def execute_concurrent(
        self,
        requests: List[HTTPRequest],
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Tuple[HTTPResponse, List[Finding]]]:
        """Execute multiple requests concurrently."""
        tasks = [self.execute_async(req, context) for req in requests]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        cleaned = []
        for r in results:
            if isinstance(r, Exception):
                err_resp = HTTPResponse(status_code=0, error=str(r))
                cleaned.append((err_resp, []))
            else:
                cleaned.append(r)
        # Count concurrent successes for race-condition detection
        success_count = sum(1 for resp, _ in cleaned if resp.status_code == 200)
        if success_count > 1:
            for resp, findings in cleaned:
                rc_ctx = dict(context or {})
                rc_ctx["concurrent_success_count"] = success_count
                extra = self._evaluate_rules(
                    HTTPRequest(method="GET", url=""),  # dummy, rules use ctx
                    resp, rc_ctx,
                )
                findings.extend(extra)
        return cleaned

    # ------------------------------------------------------------------
    # Real HTTP
    # ------------------------------------------------------------------

    def _send_real_request(self, req: HTTPRequest) -> HTTPResponse:
        import urllib.parse

        url = req.url
        if req.params:
            url += "?" + urllib.parse.urlencode(
                {k: v for k, v in req.params.items() if v is not None}
            )

        body_bytes: Optional[bytes] = None
        if req.body is not None:
            body_bytes = json.dumps(req.body).encode()

        http_req = urllib.request.Request(
            url=url,
            data=body_bytes,
            headers=req.headers,
            method=req.method,
        )

        start = time.monotonic()
        try:
            with urllib.request.urlopen(http_req, timeout=self.timeout) as resp:
                raw = resp.read()
                latency = (time.monotonic() - start) * 1000
                try:
                    body = json.loads(raw)
                except json.JSONDecodeError:
                    body = raw.decode(errors="replace")
                return HTTPResponse(
                    status_code=resp.status,
                    headers=dict(resp.headers),
                    body=body,
                    latency_ms=latency,
                )
        except urllib.error.HTTPError as exc:
            latency = (time.monotonic() - start) * 1000
            try:
                body = json.loads(exc.read())
            except Exception:
                body = str(exc)
            return HTTPResponse(
                status_code=exc.code,
                body=body,
                latency_ms=latency,
                error=str(exc),
            )
        except Exception as exc:
            latency = (time.monotonic() - start) * 1000
            return HTTPResponse(
                status_code=0,
                latency_ms=latency,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Dry-run simulator
    # ------------------------------------------------------------------

    def _simulate_response(self, req: HTTPRequest) -> HTTPResponse:
        """
        Produce a plausible simulated response for dry-run mode.
        Deliberately introduces anomalies for demo/testing purposes.
        """
        import random, time as _t
        _t.sleep(0.01)  # tiny artificial latency

        body  = req.body or {}
        rng   = random.Random(hash(req.url + req.method + str(body)))

        # Trigger various anomalies based on request content
        body_str = str(body).lower()

        # Simulate 500 for injection payloads
        if any(p in body_str for p in ("' or", "<script>", "../../../../", "${7")):
            return HTTPResponse(
                status_code=500,
                body={"error": "Internal Server Error", "detail": "SQL syntax error near \"OR '1'='1'\""},
                latency_ms=rng.uniform(100, 300),
            )

        # Simulate 200 for negative quantities (logic error)
        if isinstance(body, dict) and any(
            isinstance(body.get(k), (int, float)) and body[k] < 0
            for k in ("quantity", "amount", "price")
        ):
            return HTTPResponse(
                status_code=200,
                body={"order_id": 9999, "total": body.get("amount", -1), "status": "confirmed"},
                latency_ms=rng.uniform(80, 200),
            )

        # Simulate 200 for privilege fields (mass assignment)
        if isinstance(body, dict) and ("is_admin" in body or "role" in body):
            return HTTPResponse(
                status_code=200,
                body={"updated": True, "is_admin": True, "role": "admin"},
                latency_ms=rng.uniform(80, 200),
            )

        # Simulate 200 for IDOR (/1 in URL)
        import re
        if re.search(r"[=/]1\b", req.url):
            return HTTPResponse(
                status_code=200,
                body={"user_id": 1, "email": "admin@example.com", "name": "Admin User"},
                latency_ms=rng.uniform(80, 150),
            )

        # Simulate slow response for bot swarm endpoints
        if req.method == "POST" and rng.random() < 0.1:
            return HTTPResponse(
                status_code=200,
                body={"result": "ok"},
                latency_ms=rng.uniform(5000, 8000),
            )

        # Default: random 200 or 400
        status = rng.choice([200, 200, 200, 400, 422])
        return HTTPResponse(
            status_code=status,
            body={"result": "ok"} if status == 200 else {"error": "Bad Request"},
            latency_ms=rng.uniform(50, 300),
        )

    # ------------------------------------------------------------------
    # Rule evaluation
    # ------------------------------------------------------------------

    def _evaluate_rules(
        self,
        req: HTTPRequest,
        resp: HTTPResponse,
        context: Dict[str, Any],
    ) -> List[Finding]:
        findings: List[Finding] = []
        for rule in self.rules:
            try:
                if rule.check(req, resp, context):
                    step = TestStep(
                        step_number=1,
                        description=rule.description,
                        request=req,
                        response=resp,
                        passed=False,
                    )
                    findings.append(Finding(
                        type=rule.finding_type,
                        severity=rule.severity,
                        title=rule.name,
                        description=rule.description,
                        endpoint=f"{req.method} {req.url}",
                        steps=[step],
                        evidence={
                            "status_code": resp.status_code,
                            "latency_ms": resp.latency_ms,
                            "request_body": req.body,
                            "response_body": resp.body,
                        },
                    ))
            except Exception:
                pass
        return findings


# ---------------------------------------------------------------------------
# v0.3.0 additions: retry / backoff, session, TLS bypass, proxy support
# ---------------------------------------------------------------------------

import http.cookiejar

class EnhancedHTTPExecutor(HTTPExecutor):
    """
    Drop-in replacement for HTTPExecutor with:
      - Retry with exponential backoff
      - Cookie jar / session persistence
      - TLS/SSL bypass for self-signed certs
      - HTTP proxy support (Burp Suite, squid, etc.)
    """

    def __init__(
        self,
        dry_run:      bool  = False,
        timeout:      float = 10.0,
        rules=None,
        max_retries:  int   = 3,
        backoff_base: float = 0.5,
        verify_ssl:   bool  = True,
        proxy_url:    Optional[str] = None,
        cookie_jar:   Optional[http.cookiejar.CookieJar] = None,
    ):
        super().__init__(dry_run=dry_run, timeout=timeout, rules=rules)
        self.max_retries  = max_retries
        self.backoff_base = backoff_base
        self.verify_ssl   = verify_ssl
        self.proxy_url    = proxy_url
        self._jar         = cookie_jar or http.cookiejar.CookieJar()
        self._opener      = self._build_opener()

    def _build_opener(self):
        import urllib.request, ssl as _ssl

        handlers = [urllib.request.HTTPCookieProcessor(self._jar)]

        # TLS bypass
        if not self.verify_ssl:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))

        # Proxy support
        if self.proxy_url:
            handlers.append(urllib.request.ProxyHandler({
                "http":  self.proxy_url,
                "https": self.proxy_url,
            }))

        return urllib.request.build_opener(*handlers)

    def _send_real_request(self, req: HTTPRequest) -> HTTPResponse:
        import urllib.parse, urllib.error, json as _json

        url = req.url
        if req.params:
            url += "?" + urllib.parse.urlencode(
                {k: v for k, v in req.params.items() if v is not None}
            )

        body_bytes: Optional[bytes] = None
        if req.body is not None:
            body_bytes = _json.dumps(req.body).encode()

        http_req = urllib.request.Request(
            url=url, data=body_bytes,
            headers=req.headers, method=req.method,
        )

        attempt     = 0
        last_error  = ""
        while attempt <= self.max_retries:
            start = time.monotonic()
            try:
                with self._opener.open(http_req, timeout=self.timeout) as resp:
                    raw     = resp.read()
                    latency = (time.monotonic() - start) * 1000
                    try:
                        body = _json.loads(raw)
                    except _json.JSONDecodeError:
                        body = raw.decode(errors="replace")
                    return HTTPResponse(
                        status_code=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        latency_ms=latency,
                    )
            except urllib.error.HTTPError as exc:
                latency    = (time.monotonic() - start) * 1000
                status     = exc.code
                last_error = str(exc)
                # Don't retry 4xx
                if status < 500:
                    try:
                        body = _json.loads(exc.read())
                    except Exception:
                        body = str(exc)
                    return HTTPResponse(
                        status_code=status, body=body,
                        latency_ms=latency, error=last_error,
                    )
            except Exception as exc:
                latency    = (time.monotonic() - start) * 1000
                last_error = str(exc)

            attempt += 1
            if attempt <= self.max_retries:
                wait = self.backoff_base * (2 ** (attempt - 1))
                time.sleep(wait)

        return HTTPResponse(status_code=0, latency_ms=0.0, error=last_error)
