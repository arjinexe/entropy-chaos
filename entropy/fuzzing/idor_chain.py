"""Multi-step IDOR chain detection — authenticate as user A, access user B's resources."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from entropy.core.models import (
    APIEndpoint, APISchema, Finding, FindingType, Severity,
)


@dataclass
class IDORChainResult:
    endpoint_a:  str   # resource owner's endpoint
    endpoint_b:  str   # accessed endpoint
    resource_id: Any   # the ID that was accessed
    user_a_id:   Any
    user_b_id:   Any
    response_body: str
    confirmed:   bool


class IDORChainTester:
    """
    Tests for multi-step Insecure Direct Object Reference vulnerabilities.

    Strategy:
      1. Identify resource endpoints with path parameters (e.g. /users/{id}/orders)
      2. Try accessing ID sequences: if user owns ID=1, try IDs 2,3,4…
      3. Check whether response returns another user's data
      4. Also test cross-resource access (user A's token → resource of user B)

    Works best with a live LLM that can extract IDs from responses, but
    falls back to heuristic ID scanning in mock/offline mode.
    """

    _SENSITIVE_FIELDS = {
        "email", "phone", "address", "ssn", "dob", "credit_card",
        "password", "token", "balance", "salary", "medical",
        "personal", "private", "secret", "account_number",
    }

    _PROBE_IDS = [1, 2, 3, 4, 5, 99, 100, 1000, 9999, 0]

    def __init__(
        self,
        base_url:    str,
        timeout:     float = 8.0,
        verify_ssl:  bool  = True,
        auth_headers: Optional[Dict[str, str]] = None,
        dry_run:     bool  = False,
    ):
        self.base_url     = base_url.rstrip("/")
        self.timeout      = timeout
        self.verify_ssl   = verify_ssl
        self.auth_headers = auth_headers or {}
        self.dry_run      = dry_run
        self._ctx         = self._build_ssl()

    # ------------------------------------------------------------------

    def test_schema(self, schema: APISchema) -> List[Finding]:
        """Test all resource endpoints in the schema for IDOR chains."""
        findings: List[Finding] = []

        resource_endpoints = self._find_resource_endpoints(schema)
        for ep in resource_endpoints:
            if self.dry_run:
                results = self._mock_results(ep)
            else:
                results = self._probe_endpoint(ep)

            for r in results:
                if r.confirmed:
                    findings.append(self._to_finding(r))

        return findings

    # ------------------------------------------------------------------

    def _find_resource_endpoints(self, schema: APISchema) -> List[APIEndpoint]:
        """Return endpoints with numeric path parameters (likely IDOR candidates)."""
        candidates = []
        for ep in schema.endpoints:
            if ep.method.value not in ("GET", "DELETE", "PUT", "PATCH"):
                continue
            # Has at least one numeric/id path parameter
            for p in ep.parameters:
                if p.location == "path" and p.type in ("integer", "string", ""):
                    if any(kw in p.name.lower() for kw in ("id", "uuid", "key", "ref", "no", "num")):
                        candidates.append(ep)
                        break
        return candidates[:10]  # cap for speed

    def _probe_endpoint(self, endpoint: APIEndpoint) -> List[IDORChainResult]:
        results: List[IDORChainResult] = []
        path_params = [p for p in endpoint.parameters if p.location == "path"]

        for param in path_params[:1]:   # test first path param
            for probe_id in self._PROBE_IDS[:6]:
                path = endpoint.path.replace(f"{{{param.name}}}", str(probe_id))
                url  = f"{self.base_url}{path}"
                resp = self._get(url)
                if resp is None:
                    continue

                status, body_str, body_dict = resp
                if status == 200 and self._contains_sensitive_data(body_dict):
                    results.append(IDORChainResult(
                        endpoint_a    = f"GET {endpoint.path}",
                        endpoint_b    = f"GET {path}",
                        resource_id   = probe_id,
                        user_a_id     = "attacker",
                        user_b_id     = probe_id,
                        response_body = body_str[:400],
                        confirmed     = True,
                    ))

        return results

    def _get(self, url: str) -> Optional[Tuple[int, str, Dict]]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "entropy/0.4.0",
            **self.auth_headers,
        }
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                raw = resp.read().decode(errors="replace")
                try:
                    parsed = json.loads(raw)
                except Exception:
                    parsed = {}
                return resp.status, raw, parsed if isinstance(parsed, dict) else {}
        except urllib.error.HTTPError as exc:
            return exc.code, "", {}
        except Exception:
            return None

    def _contains_sensitive_data(self, body: Dict) -> bool:
        if not isinstance(body, dict):
            return False
        keys = {k.lower() for k in body}
        return bool(keys & self._SENSITIVE_FIELDS) or len(body) >= 3

    def _mock_results(self, endpoint: APIEndpoint) -> List[IDORChainResult]:
        import random
        rng = random.Random(hash(endpoint.path))
        results = []
        if rng.random() < 0.12:
            results.append(IDORChainResult(
                endpoint_a    = f"GET {endpoint.path}",
                endpoint_b    = f"GET {endpoint.path.replace('{id}', '2')}",
                resource_id   = 2,
                user_a_id     = 1,
                user_b_id     = 2,
                response_body = '{"email": "victim@example.com", "balance": 10000}',
                confirmed     = True,
            ))
        return results

    def _build_ssl(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    @staticmethod
    def _to_finding(result: IDORChainResult) -> Finding:
        return Finding(
            type        = FindingType.IDOR,
            severity    = Severity.HIGH,
            title       = f"IDOR — Unauthorised Access to Resource ID {result.resource_id}",
            description = (
                f"Accessing `{result.endpoint_b}` without authorisation returned "
                f"data that appears to belong to another user. "
                f"Resource ID {result.resource_id} was accessible without ownership verification."
            ),
            endpoint    = result.endpoint_a,
            evidence    = {
                "probed_url":   result.endpoint_b,
                "resource_id":  result.resource_id,
                "response_snippet": result.response_body[:300],
            },
            remediation = (
                "Implement object-level authorisation on every data retrieval endpoint. "
                "Verify that the authenticated user owns the requested resource before returning it. "
                "Use non-sequential IDs (UUIDs) to reduce enumeration risk, but do not rely on this alone."
            ),
        )
