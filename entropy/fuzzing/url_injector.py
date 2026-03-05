"""URL parameter injector for spec-less sites.

When no OpenAPI spec is available, we discover URL parameters from:
- Query strings in crawled URLs (e.g. ?id=1&cat=2)
- Common parameter names for PHP/web apps
- Form inputs mapped to GET endpoints

Then we inject SQLi / XSS / LFI / cmd payloads directly into those params
via GET requests and analyse responses.
"""
from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from entropy.core.models import (
    Finding, FindingType, HTTPRequest, HTTPResponse, Severity, TestStep,
)


# ---------------------------------------------------------------------------
# Common injectable param names for web apps
# ---------------------------------------------------------------------------

COMMON_INJECTABLE_PARAMS: List[str] = [
    # IDs / IDOR
    "id", "user_id", "uid", "item_id", "product_id", "order_id",
    "cat", "artist", "category", "pid", "cid", "aid",
    # Search / text
    "q", "query", "search", "keyword", "keywords", "s", "term",
    "name", "username", "email", "user",
    # Files / paths
    "file", "path", "url", "img", "image", "pic", "src",
    "page", "template", "theme", "include", "load",
    # Misc
    "action", "cmd", "exec", "command", "debug", "test",
    "redirect", "next", "return", "returnUrl", "callback", "ref",
    "sort", "order", "filter", "type", "format",
    # PHP-specific
    "p", "c", "m", "op", "do", "act", "mode",
]

# Payloads per attack type
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "1' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "1 AND 1=1",
    "1 AND 1=2",
]

TIME_SQLI = [
    ("MySQL",      "1' AND SLEEP(5)-- ",          4.5),
    ("MSSQL",      "1'; WAITFOR DELAY '0:0:5'-- ", 4.5),
    ("PostgreSQL", "1'; SELECT pg_sleep(5)-- ",    4.5),
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"'><script>alert(1)</script>",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../windows/system32/drivers/etc/hosts",
    "....//....//....//etc/passwd",
    "/etc/passwd",
]

CMD_PAYLOADS = [
    "; id",
    "| id",
    "; cat /etc/passwd",
    "& whoami",
]

SQLI_INDICATORS = [
    "you have an error in your sql syntax",
    "warning: mysql", "unclosed quotation mark",
    "sqlstate", "ora-00933", "pg::syntaxerror",
    "mysql_fetch", "sql syntax", "#1064",
    "microsoft ole db", "supplied argument is not a valid mysql",
    "unknown column", "error in your sql syntax",
    "sqlite error", "syntax error, unexpected",
]

XSS_INDICATORS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "onerror=alert", "onload=alert",
]

LFI_INDICATORS = [
    "root:x:0:0", "daemon:x:", "/bin/bash",
    "windows/system32", "[boot loader]",
]

CMD_INDICATORS = ["uid=", "gid=", "total 0\n", "drwxr", "nobody:", "root:"]


# ---------------------------------------------------------------------------
# URL Param Injector
# ---------------------------------------------------------------------------

class URLParamInjector:
    """
    Injects attack payloads into URL query parameters discovered
    during crawling or from common param name wordlists.

    Works entirely via GET requests, no spec required.
    """

    def __init__(
        self,
        base_url:    str,
        timeout:     float = 8.0,
        verify_ssl:  bool  = True,
        concurrency: int   = 8,
        verbose:     bool  = False,
    ):
        self.base_url    = base_url.rstrip("/")
        self.timeout     = timeout
        self.verify_ssl  = verify_ssl
        self.concurrency = concurrency
        self.verbose     = verbose
        self._ctx        = self._build_ssl_ctx()

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def test_endpoints(
        self,
        endpoint_param_map: Dict[str, List[str]],
    ) -> List[Finding]:
        """
        endpoint_param_map: {"/search.php": ["q", "cat"], ...}
        Returns all confirmed findings.
        """
        tasks: List[Tuple[str, str]] = []
        for path, params in endpoint_param_map.items():
            for param in params:
                tasks.append((path, param))

        all_findings: List[Finding] = []
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futs = {pool.submit(self._test_param, path, param): (path, param)
                    for path, param in tasks}
            for fut in as_completed(futs):
                try:
                    findings = fut.result()
                    all_findings.extend(findings)
                except Exception:
                    pass

        return self._dedup(all_findings)

    def build_param_map_from_urls(self, urls: List[str]) -> Dict[str, List[str]]:
        """Extract path→params mapping from crawled URLs."""
        from urllib.parse import urlparse, parse_qs
        result: Dict[str, List[str]] = {}
        for url in urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            path = parsed.path
            params = list(parse_qs(parsed.query).keys())
            if path not in result:
                result[path] = []
            for p in params:
                if p not in result[path]:
                    result[path].append(p)
        return result

    def inject_common_params(self, paths: List[str]) -> List[Finding]:
        """
        For each path, try injecting common parameter names.
        Useful when crawled URLs have no query strings.
        """
        param_map = {path: list(COMMON_INJECTABLE_PARAMS[:20]) for path in paths}
        return self.test_endpoints(param_map)

    # ------------------------------------------------------------------
    # Per-param testing
    # ------------------------------------------------------------------

    def _test_param(self, path: str, param: str) -> List[Finding]:
        findings: List[Finding] = []
        url_base = self.base_url + path

        # Baseline response (benign value)
        baseline_resp = self._get(url_base, {param: "1"})
        if baseline_resp is None:
            return findings

        # --- Error-based SQLi ---
        for payload in SQLI_PAYLOADS[:6]:
            resp = self._get(url_base, {param: payload})
            if resp and self._matches(str(resp.body or ""), SQLI_INDICATORS):
                findings.append(self._finding(
                    path, param, payload, "GET",
                    FindingType.INJECTION, Severity.CRITICAL,
                    "SQL Injection (Error-Based)",
                    f"GET parameter `{param}` on `{path}` returned SQL error — injection confirmed.",
                    "Use parameterised queries. Never interpolate URL params into SQL.",
                    resp,
                ))
                break

        # --- Time-based blind SQLi ---
        if not any(f.type == FindingType.INJECTION for f in findings):
            for label, payload, threshold in TIME_SQLI:
                resp = self._get(url_base, {param: payload})
                if resp and resp.latency_ms / 1000 >= threshold:
                    findings.append(self._finding(
                        path, param, payload, "GET",
                        FindingType.INJECTION, Severity.CRITICAL,
                        f"Blind SQL Injection (Time-Based / {label})",
                        f"Parameter `{param}` caused {resp.latency_ms/1000:.1f}s delay — time-based blind SQLi.",
                        "Use parameterised queries.",
                        resp,
                    ))
                    break

        # --- Boolean-based blind SQLi ---
        if not any(f.type == FindingType.INJECTION for f in findings):
            r_true  = self._get(url_base, {param: "1' OR '1'='1"})
            r_false = self._get(url_base, {param: "1' OR '1'='2"})
            if (r_true and r_false
                    and r_true.status_code != 404
                    and abs(len(str(r_true.body or "")) - len(str(r_false.body or ""))) > 50):
                findings.append(self._finding(
                    path, param, "1' OR '1'='1", "GET",
                    FindingType.INJECTION, Severity.HIGH,
                    "Blind SQL Injection (Boolean-Based)",
                    f"Parameter `{param}` returns different content sizes for true/false conditions.",
                    "Use parameterised queries.",
                    r_true,
                ))

        # --- XSS ---
        for payload in XSS_PAYLOADS[:4]:
            resp = self._get(url_base, {param: payload})
            if resp and payload.lower() in str(resp.body or "").lower():
                resp_text = str(resp.body or "")
                import html as _html
                encoded = _html.escape(payload)
                if encoded not in resp_text or payload in resp_text:
                    findings.append(self._finding(
                        path, param, payload, "GET",
                        FindingType.INJECTION, Severity.HIGH,
                        "Cross-Site Scripting (XSS)",
                        f"XSS payload reflected in response for GET param `{param}` on `{path}`.",
                        "HTML-encode all output. Use Content-Security-Policy.",
                        resp,
                    ))
                    break

        # --- LFI (only for file-like param names) ---
        file_hints = {"file", "path", "img", "image", "pic", "src", "page",
                      "template", "include", "load", "dir", "f", "filename"}
        if param.lower() in file_hints or any(h in param.lower() for h in file_hints):
            for payload in LFI_PAYLOADS[:4]:
                resp = self._get(url_base, {param: payload})
                if resp and self._matches(str(resp.body or ""), LFI_INDICATORS):
                    findings.append(self._finding(
                        path, param, payload, "GET",
                        FindingType.DATA_LEAK, Severity.CRITICAL,
                        "Path Traversal / Local File Inclusion",
                        f"Parameter `{param}` disclosed local file contents on `{path}`.",
                        "Validate and sanitise file paths. Use strict allow-lists.",
                        resp,
                    ))
                    break

        # --- IDOR: compare low numeric IDs ---
        id_hints = {"id", "user_id", "uid", "product_id", "item_id", "order_id", "cid", "pid"}
        if param.lower() in id_hints:
            resp_1 = self._get(url_base, {param: "1"})
            resp_2 = self._get(url_base, {param: "2"})
            if (resp_1 and resp_2
                    and resp_1.status_code == 200 and resp_2.status_code == 200
                    and str(resp_1.body) != str(resp_2.body)):
                sensitive = {"email", "password", "token", "ssn", "phone",
                             "balance", "credit", "secret", "is_admin"}
                r_body = str(resp_1.body or "").lower()
                if any(s in r_body for s in sensitive):
                    findings.append(self._finding(
                        path, param, "1", "GET",
                        FindingType.IDOR, Severity.HIGH,
                        "Potential IDOR — Sensitive Data Exposed",
                        f"Sequentially guessing `{param}=1` returns sensitive-looking data on `{path}`.",
                        "Authorise every resource request against the authenticated user.",
                        resp_1,
                    ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get(self, url: str, params: Dict[str, str]) -> Optional[HTTPResponse]:
        qs  = urllib.parse.urlencode(params)
        full = f"{url}?{qs}"
        headers = {"User-Agent": "entropy-chaos/0.4.4 (security-scanner)"}
        req = urllib.request.Request(full, headers=headers, method="GET")
        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                raw     = resp.read().decode(errors="replace")
                latency = (time.monotonic() - start) * 1000
                return HTTPResponse(status_code=resp.status, body=raw, latency_ms=latency)
        except urllib.error.HTTPError as exc:
            latency = (time.monotonic() - start) * 1000
            try:
                body = exc.read().decode(errors="replace")
            except Exception:
                body = ""
            return HTTPResponse(status_code=exc.code, body=body, latency_ms=latency)
        except Exception:
            latency = (time.monotonic() - start) * 1000
            return HTTPResponse(status_code=0, body="", latency_ms=latency)

    def _matches(self, text: str, indicators: List[str]) -> bool:
        tl = text.lower()
        return any(ind.lower() in tl for ind in indicators)

    def _finding(
        self,
        path: str, param: str, payload: str, method: str,
        ftype: FindingType, severity: Severity,
        title: str, description: str, remediation: str,
        resp: Optional[HTTPResponse],
    ) -> Finding:
        req = HTTPRequest(method=method, url=self.base_url + path,
                          params={param: payload})
        step = TestStep(
            step_number=1,
            description=f"{method} {path}?{param}={payload}",
            request=req, response=resp, passed=False,
        )
        return Finding(
            type=ftype, severity=severity, title=title,
            description=description, remediation=remediation,
            endpoint=f"{method} {path}",
            persona="URLParamInjector",
            steps=[step],
            evidence={"param": param, "payload": payload,
                      "status": resp.status_code if resp else 0},
        )

    def _dedup(self, findings: List[Finding]) -> List[Finding]:
        seen: set = set()
        result: List[Finding] = []
        for f in findings:
            key = (f.type, f.endpoint, f.title[:40])
            if key not in seen:
                seen.add(key)
                result.append(f)
        return result

    def _build_ssl_ctx(self):
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        return ctx
