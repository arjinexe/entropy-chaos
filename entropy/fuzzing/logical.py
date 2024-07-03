""""Logical fuzzer — schema-aware payload mutation beyond random bytes."""
from __future__ import annotations

import random
from typing import Any, Dict, List, Optional

from entropy.core.models import APIEndpoint, APIParameter, APISchema
from entropy.llm.backends import BaseLLM


# ---------------------------------------------------------------------------
# Static payload libraries
# ---------------------------------------------------------------------------

_STRING_PAYLOADS: List[Any] = [
    # Boundary values
    "",
    " ",
    "\t\n\r",
    "a" * 256,
    "a" * 65536,
    # Type confusion
    0,
    True,
    None,
    [],
    {},
    # SQL injection
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "1 UNION SELECT NULL,NULL--",
    # NoSQL injection
    {"$gt": ""},
    {"$ne": None},
    {"$where": "1==1"},
    # XSS
    "<script>alert(1)</script>",
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
    # Template injection
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    # Path traversal
    "../../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f",
    # Command injection
    "; ls -la",
    "| cat /etc/passwd",
    "` id `",
    # Unicode / encoding
    "\x00",
    "\uFFFD",
    "𝕳𝖊𝖑𝖑𝖔",
    "%00",
    "%0d%0a",
]

_INTEGER_PAYLOADS: List[Any] = [
    0, -1, -9999999,
    2**31 - 1,   # INT32 max
    2**31,       # INT32 overflow
    2**63 - 1,   # INT64 max
    2**63,       # INT64 overflow
    0.1,         # float instead of int
    "NaN",
    "Infinity",
    "-Infinity",
    None,
    "",
    True,
    [],
]

_BOOLEAN_PAYLOADS: List[Any] = [
    True, False,
    0, 1, -1,
    "true", "false", "TRUE", "FALSE",
    "yes", "no",
    None, "",
    [], {},
]

_OBJECT_PAYLOADS: List[Any] = [
    None,
    [],
    "",
    0,
    "null",
    {"$gt": ""},
    {"__proto__": {"admin": True}},
    {"constructor": {"prototype": {"admin": True}}},
]

_ARRAY_PAYLOADS: List[Any] = [
    None,
    {},
    "",
    [None] * 10000,
    [{"$where": "1==1"}],
    [0, -1, 2**63],
]

_TYPE_PAYLOAD_MAP: Dict[str, List[Any]] = {
    "string":  _STRING_PAYLOADS,
    "integer": _INTEGER_PAYLOADS,
    "number":  _INTEGER_PAYLOADS,
    "boolean": _BOOLEAN_PAYLOADS,
    "object":  _OBJECT_PAYLOADS,
    "array":   _ARRAY_PAYLOADS,
}


# ---------------------------------------------------------------------------
# Business-logic specific mutations
# ---------------------------------------------------------------------------

def _business_logic_mutations(endpoint: APIEndpoint) -> List[Dict[str, Any]]:
    """
    Return payloads specifically crafted to probe business logic.
    These are based on common vulnerability patterns in e-commerce,
    fintech, and SaaS APIs.
    """
    mutations: List[Dict[str, Any]] = []

    # Discover what fields the endpoint uses
    all_fields: List[str] = [p.name for p in endpoint.parameters]
    if endpoint.request_body and isinstance(endpoint.request_body, dict):
        props = endpoint.request_body.get("schema", {}).get("properties", {})
        all_fields.extend(props.keys())

    field_set = set(all_fields)

    # --- Price / amount manipulation ---
    for f in ("price", "unit_price", "amount", "total", "cost"):
        if f in field_set:
            mutations += [
                {f: 0},
                {f: -1},
                {f: 0.001},
                {f: 999999999},
                {f: "0"},
                {f: None},
            ]

    # --- Quantity manipulation ---
    for f in ("quantity", "count", "qty", "num_items"):
        if f in field_set:
            mutations += [
                {f: 0},
                {f: -1},
                {f: 2**31},
                {f: 0.5},
            ]

    # --- Discount / coupon double-apply ---
    for f in ("coupon_code", "promo_code", "discount_code", "voucher"):
        if f in field_set:
            mutations += [
                {f: "SAVE100", "quantity": 1},
                {f: "SAVE100", f + "2": "SAVE100"},  # attempt to send twice
            ]

    # --- Status / state transitions ---
    for f in ("status", "state", "phase", "step"):
        if f in field_set:
            states = ["completed", "approved", "paid", "shipped", "admin", "verified"]
            mutations += [{f: s} for s in states]

    # --- Privilege escalation ---
    mutations.append({
        "is_admin": True,
        "role": "admin",
        "permissions": ["*"],
        "verified": True,
        "email_verified": True,
    })

    # --- ID confusion ---
    for f in ("user_id", "account_id", "owner_id", "creator_id"):
        if f in field_set:
            mutations += [{f: 1}, {f: 0}, {f: -1}, {f: "admin"}]

    return mutations


# ---------------------------------------------------------------------------
# Fuzzer
# ---------------------------------------------------------------------------

class LogicalFuzzer:
    """
    Generates intelligent, schema-aware fuzz payloads for API endpoints.

    Two modes:
      1. Static library: returns pre-defined payloads per field type.
      2. LLM-enhanced: asks the LLM for context-specific payloads.
    """

    def __init__(self, llm: BaseLLM, use_llm: bool = True, seed: int = 42):
        self.llm     = llm
        self.use_llm = use_llm
        random.seed(seed)

    # ------------------------------------------------------------------

    def generate_payloads(
        self,
        endpoint: APIEndpoint,
        max_per_param: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Return a list of request bodies / param dicts to test against the endpoint.
        """
        payloads: List[Dict[str, Any]] = []

        # 1. Per-parameter type-based fuzzing
        for param in endpoint.parameters:
            type_payloads = _TYPE_PAYLOAD_MAP.get(param.type, _STRING_PAYLOADS)
            sample = random.sample(
                type_payloads, min(max_per_param, len(type_payloads))
            )
            for value in sample:
                payloads.append({param.name: value})

        # 2. Business logic mutations
        payloads.extend(_business_logic_mutations(endpoint))

        # 3. LLM-generated payloads
        if self.use_llm:
            try:
                payloads.extend(self._llm_payloads(endpoint, max_per_param))
            except Exception:
                pass  # degrade gracefully

        # Deduplicate (by string representation)
        seen: set = set()
        unique: List[Dict[str, Any]] = []
        for p in payloads:
            key = str(sorted(str(p)))
            if key not in seen:
                seen.add(key)
                unique.append(p)

        return unique

    def generate_body(self, endpoint: APIEndpoint) -> Dict[str, Any]:
        """Generate a single valid-looking baseline request body."""
        body: Dict[str, Any] = {}
        if endpoint.request_body:
            schema = endpoint.request_body.get("schema", {})
            properties = schema.get("properties", {})
            for name, prop in properties.items():
                body[name] = self._realistic_value(name, prop.get("type", "string"))
        for param in endpoint.parameters:
            if param.location == "body":
                body[param.name] = self._realistic_value(param.name, param.type)
        return body

    # ------------------------------------------------------------------

    def _llm_payloads(
        self,
        endpoint: APIEndpoint,
        count: int,
    ) -> List[Dict[str, Any]]:
        import json
        params_desc = ", ".join(
            f"{p.name} ({p.type})" for p in endpoint.parameters
        )
        body_schema = ""
        if endpoint.request_body:
            body_schema = json.dumps(endpoint.request_body.get("schema", {}))[:300]

        prompt = (
            f"Generate {count} adversarial fuzz payloads for:\n"
            f"  Endpoint: {endpoint.method.value} {endpoint.path}\n"
            f"  Parameters: {params_desc or 'none'}\n"
            f"  Body schema: {body_schema or 'none'}\n\n"
            "Focus on business logic abuse, injection, and type confusion.\n"
            "Return JSON: {\"payloads\": [{...}, ...]}"
        )
        data = self.llm.complete_json(prompt)
        raw = data.get("payloads", [])
        return [p for p in raw if isinstance(p, dict)]

    @staticmethod
    def _realistic_value(field_name: str, field_type: str) -> Any:
        """Generate a plausible realistic value based on field name and type."""
        fn = field_name.lower()
        if "email" in fn:
            return "test.user@example.com"
        if "password" in fn or "pwd" in fn:
            return "TestPass123!"
        if "phone" in fn:
            return "+1-555-0100"
        if "price" in fn or "amount" in fn or "total" in fn:
            return 29.99
        if "quantity" in fn or "count" in fn or "qty" in fn:
            return 1
        if "id" in fn:
            return random.randint(1000, 9999)
        if "name" in fn:
            return "Test User"
        if "date" in fn or "time" in fn:
            return "2024-06-15T10:00:00Z"
        if "url" in fn or "link" in fn:
            return "https://example.com"
        if "code" in fn or "coupon" in fn:
            return "TEST10"
        if field_type == "integer":
            return random.randint(1, 100)
        if field_type in ("number", "float"):
            return round(random.uniform(1.0, 100.0), 2)
        if field_type == "boolean":
            return True
        return f"test-value-{random.randint(100, 999)}"
