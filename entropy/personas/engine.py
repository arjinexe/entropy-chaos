"""Attack personas — each models a different threat actor archetype."""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from entropy.core.models import (
    APIEndpoint, APISchema, AttackVector,
    HTTPRequest, PersonaType,
)
from entropy.llm.backends import BaseLLM


# ---------------------------------------------------------------------------
# Persona configuration
# ---------------------------------------------------------------------------

@dataclass
class PersonaConfig:
    type:        PersonaType
    concurrency: int   = 1      # simultaneous requests
    delay_ms:    int   = 300    # ms between steps
    max_steps:   int   = 10     # max actions per session
    custom_name: str   = ""
    custom_desc: str   = ""


# ---------------------------------------------------------------------------
# Base Persona
# ---------------------------------------------------------------------------

class BasePersona:
    """
    Abstract base for all synthetic user personas.
    Subclasses override `build_request_sequence` to define their behaviour.
    """

    name:        str = "Base Persona"
    description: str = "Generic persona"

    def __init__(self, config: PersonaConfig, llm: BaseLLM, schema: APISchema):
        self.config = config
        self.llm    = llm
        self.schema = schema
        self._state: Dict[str, Any] = {}   # shared session state (tokens, IDs, etc.)

    # ------------------------------------------------------------------

    def build_request_sequence(
        self,
        vector: AttackVector,
    ) -> List[HTTPRequest]:
        """
        Return an ordered list of HTTP requests that implement the attack vector.
        Subclasses provide specialised implementations.
        """
        raise NotImplementedError

    def _make_request(
        self,
        endpoint: APIEndpoint,
        body: Optional[Any] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> HTTPRequest:
        url = f"{self.schema.base_url.rstrip('/')}{endpoint.path}"
        # Fill path parameters with plausible values
        for param in endpoint.parameters:
            if param.location == "path":
                url = url.replace(
                    f"{{{param.name}}}",
                    str(self._state.get(param.name, self._generate_value(param.type))),
                )
        base_headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._state.get("token"):
            base_headers["Authorization"] = f"Bearer {self._state['token']}"
        base_headers.update(headers or {})
        return HTTPRequest(
            method=endpoint.method.value,
            url=url,
            headers=base_headers,
            params=params or {},
            body=body,
        )

    @staticmethod
    def _generate_value(field_type: str) -> Any:
        if field_type == "integer":
            return random.randint(1, 9999)
        if field_type == "boolean":
            return random.choice([True, False])
        if field_type == "number":
            return round(random.uniform(0.01, 999.99), 2)
        return f"test-{random.randint(1000, 9999)}"

    def _ask_llm_for_payload(
        self, endpoint: APIEndpoint, hints: List[str]
    ) -> Dict[str, Any]:
        """Ask LLM to generate a context-aware fuzz payload for the endpoint."""
        schema_json = ""
        if endpoint.request_body:
            import json
            schema_json = json.dumps(endpoint.request_body, indent=2)[:500]

        prompt = (
            f"Generate a fuzz payload for: {endpoint.method.value} {endpoint.path}\n"
            f"Body schema: {schema_json}\n"
            f"Payload hints (fields to target): {hints}\n"
            f"Persona type: {self.config.type.value}\n"
            "Return JSON: {\"payload\": {...}}"
        )
        try:
            data = self.llm.complete_json(prompt)
            return data.get("payload", {})
        except Exception:
            # Fallback: generate a payload from hints
            return {hint: self._generate_value("string") for hint in hints}


# ---------------------------------------------------------------------------
# Concrete Personas
# ---------------------------------------------------------------------------

class MaliciousInsiderPersona(BasePersona):
    """
    Has valid credentials; attempts privilege escalation and IDOR.
    Slow, deliberate — mimics a real insider threat.
    """
    name        = "Malicious Insider"
    description = (
        "Authenticated user who methodically probes resource boundaries, "
        "replaces IDs, and attempts to access other users' data."
    )

    def build_request_sequence(self, vector: AttackVector) -> List[HTTPRequest]:
        requests: List[HTTPRequest] = []
        if not vector.endpoint:
            return requests

        ep = vector.endpoint
        hints = vector.payload.get("hints", [])

        # Step 1: Legitimate request (establish baseline)
        body = self._ask_llm_for_payload(ep, hints)
        requests.append(self._make_request(ep, body=body))

        # Step 2: Swap IDs to target another user
        tampered_body = dict(body)
        for field in ["user_id", "account_id", "owner_id", "id"]:
            if field in tampered_body or field in hints:
                tampered_body[field] = 1  # try to access user #1 (admin)
        requests.append(self._make_request(ep, body=tampered_body))

        # Step 3: Try adding privilege fields
        tampered_body["is_admin"]    = True
        tampered_body["role"]        = "admin"
        tampered_body["permissions"] = ["read", "write", "admin"]
        requests.append(self._make_request(ep, body=tampered_body))

        return requests


class ImpatientConsumerPersona(BasePersona):
    """
    Rapidly retries, double-submits forms, ignores flow.
    """
    name        = "Impatient Consumer"
    description = (
        "Submits the same request multiple times in quick succession, "
        "skips intermediate steps, and double-submits checkout/payment forms."
    )

    def build_request_sequence(self, vector: AttackVector) -> List[HTTPRequest]:
        requests: List[HTTPRequest] = []
        if not vector.endpoint:
            return requests

        ep    = vector.endpoint
        hints = vector.payload.get("hints", [])
        body  = self._ask_llm_for_payload(ep, hints)

        # Repeat the same request 5× rapidly (double-submit)
        for _ in range(5):
            requests.append(self._make_request(ep, body=body))

        # Try with a coupon/promo applied twice
        for discount_field in ["coupon_code", "promo_code", "discount_id", "voucher"]:
            if discount_field in hints:
                body[discount_field] = "SAVE50"
                requests.append(self._make_request(ep, body=body))
                requests.append(self._make_request(ep, body=body))

        return requests


class BotSwarmPersona(BasePersona):
    """
    Hundreds of coordinated concurrent requests.
    Designed for race-condition and resource-exhaustion testing.
    """
    name        = "Bot Swarm"
    description = (
        "Coordinates up to 100 concurrent requests targeting limited resources "
        "to trigger race conditions and inventory depletion."
    )

    def build_request_sequence(self, vector: AttackVector) -> List[HTTPRequest]:
        requests: List[HTTPRequest] = []
        if not vector.endpoint:
            return requests

        ep    = vector.endpoint
        hints = vector.payload.get("hints", [])
        body  = self._ask_llm_for_payload(ep, hints)

        # Build a large batch of identical requests
        count = min(self.config.concurrency, 100)
        for _ in range(count):
            requests.append(self._make_request(ep, body=body))

        return requests


class ConfusedUserPersona(BasePersona):
    """
    Sends wrong types, missing fields, invalid transitions.
    """
    name        = "Confused User"
    description = (
        "Sends malformed, semantically incorrect, or out-of-order requests "
        "to trigger unhandled edge cases and unexpected server behaviour."
    )

    _BAD_VALUES = [None, "", -1, 0, "null", "undefined", "NaN",
                   "' OR '1'='1", {"$gt": ""}, [], True]

    def build_request_sequence(self, vector: AttackVector) -> List[HTTPRequest]:
        requests: List[HTTPRequest] = []
        if not vector.endpoint:
            return requests

        ep = vector.endpoint

        # Send one request per parameter with a bad value
        for param in ep.parameters[:5]:
            for bad in random.sample(self._BAD_VALUES, min(3, len(self._BAD_VALUES))):
                if param.location == "query":
                    requests.append(self._make_request(ep, params={param.name: bad}))
                else:
                    requests.append(self._make_request(ep, body={param.name: bad}))

        # Send completely empty body
        requests.append(self._make_request(ep, body={}))
        # Send null body
        requests.append(self._make_request(ep, body=None))

        return requests


class PenetrationTesterPersona(BasePersona):
    """
    Systematic security tester: injects known attack strings.
    """
    name        = "Penetration Tester"
    description = (
        "Injects SQLi, XSS, SSTI, path traversal, and other known attack "
        "strings into every reachable input field."
    )

    _INJECT_PAYLOADS = [
        "' OR '1'='1' --",
        "<script>alert(document.domain)</script>",
        "{{7*7}}",
        "${7*7}",
        "../../../../etc/passwd",
        "; ls -la",
        "UNION SELECT NULL,NULL,NULL--",
        "\x00",
        "%00",
        "admin'--",
    ]

    def build_request_sequence(self, vector: AttackVector) -> List[HTTPRequest]:
        requests: List[HTTPRequest] = []
        if not vector.endpoint:
            return requests

        ep = vector.endpoint

        for payload in self._INJECT_PAYLOADS[:6]:
            # Inject into every string parameter
            body: Dict[str, Any] = {}
            for param in ep.parameters:
                if param.type == "string":
                    body[param.name] = payload
            if ep.request_body:
                body["_injected"] = payload

            if body:
                requests.append(self._make_request(ep, body=body))
            else:
                requests.append(
                    self._make_request(ep, params={"q": payload, "search": payload})
                )

        # Try JWT alg:none attack
        requests.append(self._make_request(
            ep,
            headers={
                "Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."
            },
        ))

        return requests


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_PERSONA_MAP = {
    PersonaType.MALICIOUS_INSIDER:  MaliciousInsiderPersona,
    PersonaType.IMPATIENT_CONSUMER: ImpatientConsumerPersona,
    PersonaType.BOT_SWARM:          BotSwarmPersona,
    PersonaType.CONFUSED_USER:      ConfusedUserPersona,
    PersonaType.PENETRATION_TESTER: PenetrationTesterPersona,
}


def create_persona(
    persona_type: PersonaType,
    config: PersonaConfig,
    llm: BaseLLM,
    schema: APISchema,
) -> BasePersona:
    cls = _PERSONA_MAP.get(persona_type, ConfusedUserPersona)
    return cls(config, llm, schema)


def all_persona_configs(concurrency: int = 10) -> List[PersonaConfig]:
    """Return one PersonaConfig for every built-in persona type."""
    return [
        PersonaConfig(PersonaType.MALICIOUS_INSIDER,  concurrency=1,           delay_ms=400),
        PersonaConfig(PersonaType.IMPATIENT_CONSUMER, concurrency=5,           delay_ms=50),
        PersonaConfig(PersonaType.BOT_SWARM,          concurrency=concurrency, delay_ms=10),
        PersonaConfig(PersonaType.CONFUSED_USER,      concurrency=1,           delay_ms=200),
        PersonaConfig(PersonaType.PENETRATION_TESTER, concurrency=1,           delay_ms=300),
    ]
