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

    def check(self, req, resp, context):
        return resp.status_code >= 500


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
    ]

    def check(self, req, resp, context):
        resp_text = str(resp.body or "").lower()
        body = req.body or {}
        body_str = str(body).lower()
        for marker in self._INJECT_MARKERS:
            if marker in body_str and marker in resp_text:
                return True
        return False


# ---- NEW comprehensive rules ----

class SQLInjectionRule(AnomalyRule):
    """Detect SQL injection via database error messages in response."""

    _SQL_ERRORS = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "sqlstate",
        "odbc driver",
        "ora-00933",
        "ora-00907",
        "pg::syntaxerror",
        "invalid query",
        "sql syntax",
        "mysql_fetch",
        "num_rows",
        "mysql_num_rows",
        "supplied argument is not a valid mysql",
        "division by zero",
        "sql command not properly ended",
        "unknown column",
        "table 'information_schema",
        "syntax error, unexpected",
        "#1064",
        "error in your sql syntax",
    ]

    def __init__(self):
        super().__init__(
            name="SQL Injection",
            description="Server returned database error messages — SQL injection confirmed.",
            finding_type=FindingType.INJECTION,
            severity=Severity.CRITICAL,
        )

    def check(self, req, resp, context):
        body_str = str(resp.body or "").lower()
        if resp.status_code in (200, 500):
            for err in self._SQL_ERRORS:
                if err in body_str:
                    return True
        return False


class XSSReflectionRule(AnomalyRule):
    """Detect Cross-Site Scripting — payload reflected verbatim in response."""

    _XSS_MARKERS = [
        "<script>alert(",
        "<script>",
        "javascript:alert",
        "onerror=alert",
        "onload=alert",
        "</script>",
        "<img src=x onerror",
        "<svg onload",
        "onfocus=alert",
    ]

    def __init__(self):
        super().__init__(
            name="Cross-Site Scripting (XSS)",
            description="XSS payload reflected in response without HTML encoding.",
            finding_type=FindingType.INJECTION,
            severity=Severity.HIGH,
        )

    def check(self, req, resp, context):
        if resp.status_code not in (200, 201, 301, 302):
            return False
        resp_text = str(resp.body or "").lower()
        req_str   = (str(req.body or "") + str(req.params or "") + req.url).lower()
        for marker in self._XSS_MARKERS:
            m = marker.lower()
            if m in req_str and m in resp_text:
                return True
        return False


class PathTraversalRule(AnomalyRule):
    """Detect path traversal / local file inclusion."""

    _LFI_MARKERS = [
        "root:x:0:0",
        "daemon:x:",
        "/bin/bash",
        "/bin/sh",
        "windows/system32",
        "[boot loader]",
        "for 16-bit app support",
    ]

    def __init__(self):
        super().__init__(
            name="Path Traversal / LFI",
            description="Server returned local file contents — path traversal vulnerability confirmed.",
            finding_type=FindingType.DATA_LEAK,
            severity=Severity.CRITICAL,
        )

    def check(self, req, resp, context):
        resp_text = str(resp.body or "").lower()
        if resp.status_code == 200:
            for marker in self._LFI_MARKERS:
                if marker.lower() in resp_text:
                    return True
        return False


class InformationDisclosureRule(AnomalyRule):
    """Detect server-side error messages leaking implementation details."""

    _LEAK_PATTERNS = [
        "stack trace",
        "traceback (most recent call",
        "exception in thread",
        "at java.lang.",
        "at org.springframework",
        "fatal error:",
        "call stack:",
        "php fatal error",
        "php parse error",
        "php warning:",
        "php notice:",
        "warning: include",
        "failed to open stream",
        "no such file or directory",
        "permission denied",
        "error on line",
        "undefined variable:",
        "undefined index:",
        "call to undefined function",
        "cannot redeclare",
        "access denied for user",
        "using password: yes",
        "server error in '/' application",
        "runtime error",
        "applicationexception",
    ]

    def __init__(self):
        super().__init__(
            name="Information Disclosure",
            description="Server leaks internal error details, stack traces or configuration.",
            finding_type=FindingType.DATA_LEAK,
            severity=Severity.MEDIUM,
        )

    def check(self, req, resp, context):
        resp_text = str(resp.body or "").lower()
        for pattern in self._LEAK_PATTERNS:
            if pattern in resp_text:
                return True
        return False


class CommandInjectionRule(AnomalyRule):
    """Detect command injection via OS command output in response."""

    _CMD_MARKERS = [
        "uid=",
        "gid=",
        "total 0\n",
        "drwxr",
        "etc/passwd",
        "volume serial number",
        "directory of c:",
    ]

    def __init__(self):
        super().__init__(
            name="Command Injection",
            description="Server returned OS command output — command injection confirmed.",
            finding_type=FindingType.INJECTION,
            severity=Severity.CRITICAL,
        )

    def check(self, req, resp, context):
        resp_text = str(resp.body or "").lower()
        if resp.status_code == 200:
            for marker in self._CMD_MARKERS:
                if marker in resp_text:
                    return True
        return False


class OpenRedirectRule(AnomalyRule):
    """Detect open redirect vulnerabilities."""

    def __init__(self):
        super().__init__(
            name="Open Redirect",
            description="Server redirects to an attacker-controlled external URL.",
            finding_type=FindingType.LOGIC_ERROR,
            severity=Severity.MEDIUM,
        )

    def check(self, req, resp, context):
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            # Injected external redirect
            req_str = req.url + str(req.params or "") + str(req.body or "")
            if "evil.com" in location or "attacker.com" in location:
                return True
            # Generic: redirects outside the original host
            if location.startswith("http") and "localhost" not in location:
                from urllib.parse import urlparse
                try:
                    orig_host  = urlparse(req.url).netloc
                    redir_host = urlparse(location).netloc
                    if orig_host and redir_host and orig_host != redir_host:
                        # Only flag if we injected something that looks like a URL
                        if "http://" in req_str or "evil" in req_str:
                            return True
                except Exception:
                    pass
        return False


class AuthBypassOnMethodRule(AnomalyRule):
    """Detect HTTP method bypass — endpoint 401s on GET but accepts POST."""

    def __init__(self):
        super().__init__(
            name="Auth Bypass via HTTP Method",
            description="Endpoint returned 401/403 for one method but 200 for another — possible method bypass.",
            finding_type=FindingType.AUTH_BYPASS,
            severity=Severity.HIGH,
        )

    def check(self, req, resp, context):
        baseline_status = context.get("baseline_status")
        if baseline_status in (401, 403) and resp.status_code == 200:
            # Same endpoint, different method
            if context.get("method_variant"):
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
    SQLInjectionRule(),
    XSSReflectionRule(),
    PathTraversalRule(),
    InformationDisclosureRule(),
    CommandInjectionRule(),
    OpenRedirectRule(),
    AuthBypassOnMethodRule(),
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
        timeout: float = 5.0,
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
        url_str  = req.url.lower()

        # SQL injection — return DB error
        if any(p in body_str for p in ("' or", "' union", "1=1", "drop table", "insert into")):
            return HTTPResponse(
                status_code=500,
                body={"error": "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '\\\"OR '1'='1\\\"' at line 1"},
                latency_ms=rng.uniform(100, 300),
            )

        # XSS reflection
        if "<script>" in body_str or "alert(" in body_str:
            reflected = str(body)
            return HTTPResponse(
                status_code=200,
                body={"message": f"Search results for: {reflected}", "count": 0},
                latency_ms=rng.uniform(60, 150),
            )

        # Path traversal
        if "etc/passwd" in body_str or "../" * 3 in body_str or "..%2f" in url_str:
            return HTTPResponse(
                status_code=200,
                body={"content": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"},
                latency_ms=rng.uniform(80, 200),
            )

        # General injection → server error
        if any(p in body_str for p in ("${7", "{{7", "; ls", "| cat")):
            return HTTPResponse(
                status_code=500,
                body={"error": "Internal Server Error", "detail": "PHP Fatal Error: Uncaught exception"},
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
        timeout:      float = 5.0,
        rules=None,
        max_retries:  int   = 2,
        backoff_base: float = 0.3,
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
