"""Build LLM-driven attack vector trees from API schemas."""
from __future__ import annotations

import json
from typing import List

from entropy.core.models import (
    APIEndpoint, APISchema,
    AttackNode, AttackTree, AttackVector,
    PersonaType, Severity,
)
from entropy.llm.backends import BaseLLM


# ---------------------------------------------------------------------------
# Severity helper
# ---------------------------------------------------------------------------

def _parse_severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError:
        return Severity.MEDIUM


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class AttackTreeGenerator:
    """
    Uses the LLM to derive an AttackTree from an APISchema.

    The tree has one root node (the overall target) with child nodes
    representing distinct attack goals (auth bypass, logic abuse, etc.).
    Each child node contains concrete AttackVectors.
    """

    _SYSTEM_PROMPT = (
        "You are an expert penetration tester and chaos engineer. "
        "Your task is to analyse API endpoints and generate realistic attack scenarios "
        "that a sophisticated attacker would attempt. Focus on business logic flaws, "
        "race conditions, authorization issues, and unexpected state transitions. "
        "Always respond with valid JSON only—no markdown, no explanations."
    )

    def __init__(self, llm: BaseLLM):
        self._llm = llm

    # ------------------------------------------------------------------

    def generate(self, schema: APISchema) -> AttackTree:
        """Build a full AttackTree for the given schema."""
        root = AttackNode(
            name=f"Attack: {schema.title}",
            goal=f"Compromise or destabilise {schema.title} v{schema.version}",
            severity=Severity.CRITICAL,
        )

        # Group endpoints into logical attack surfaces
        auth_endpoints    = [e for e in schema.endpoints if e.security]
        mutating_endpoints = [e for e in schema.endpoints
                              if e.method.value in ("POST", "PUT", "PATCH", "DELETE")]
        read_endpoints    = [e for e in schema.endpoints if e.method.value == "GET"]

        # Generate attack nodes for each surface
        if mutating_endpoints:
            root.children.append(
                self._generate_logic_node(mutating_endpoints, schema)
            )
        if auth_endpoints or schema.security_schemes:
            root.children.append(
                self._generate_auth_node(schema)
            )
        if read_endpoints:
            root.children.append(
                self._generate_idor_node(read_endpoints, schema)
            )
        root.children.append(
            self._generate_race_condition_node(mutating_endpoints or schema.endpoints, schema)
        )
        root.children.append(
            self._generate_injection_node(schema.endpoints, schema)
        )

        return AttackTree(root=root)

    # ------------------------------------------------------------------
    # Node generators
    # ------------------------------------------------------------------

    def _generate_logic_node(
        self, endpoints: List[APIEndpoint], schema: APISchema
    ) -> AttackNode:
        prompt = self._build_prompt(
            "Generate business logic attack scenarios",
            endpoints[:6],
            schema,
            extra=(
                "Focus on: double-spending, negative values, price manipulation, "
                "state machine bypass, and mass assignment. "
                "Return JSON: {\"attack_nodes\": [{\"name\", \"goal\", \"severity\", "
                "\"endpoint\", \"vectors\": [{\"description\", \"payload_hints\", "
                "\"expected_anomaly\"}]}]}"
            ),
        )
        return self._parse_llm_node_response(
            prompt,
            default_name="Business Logic Abuse",
            default_goal="Exploit missing server-side business rule validation",
            persona=PersonaType.MALICIOUS_INSIDER,
        )

    def _generate_auth_node(self, schema: APISchema) -> AttackNode:
        secured = [e for e in schema.endpoints if e.security][:6]
        prompt = self._build_prompt(
            "Generate authentication and authorisation bypass attacks",
            secured,
            schema,
            extra=(
                "Focus on: JWT weaknesses, RBAC bypass, token replay, "
                "privilege escalation, and broken object-level authorisation. "
                "Return JSON: {\"attack_nodes\": [...]}"
            ),
        )
        return self._parse_llm_node_response(
            prompt,
            default_name="Authentication Bypass",
            default_goal="Gain unauthorised access by exploiting auth mechanisms",
            persona=PersonaType.PENETRATION_TESTER,
        )

    def _generate_idor_node(
        self, endpoints: List[APIEndpoint], schema: APISchema
    ) -> AttackNode:
        # Filter endpoints with path parameters (likely IDs)
        idor_candidates = [
            e for e in endpoints if "{" in e.path
        ][:6] or endpoints[:6]

        prompt = self._build_prompt(
            "Generate Insecure Direct Object Reference (IDOR) attack scenarios",
            idor_candidates,
            schema,
            extra=(
                "Focus on: replacing own resource IDs with other users' IDs, "
                "horizontal privilege escalation, and data enumeration. "
                "Return JSON: {\"attack_nodes\": [...]}"
            ),
        )
        return self._parse_llm_node_response(
            prompt,
            default_name="IDOR / Broken Object-Level Auth",
            default_goal="Access or modify resources belonging to other users",
            persona=PersonaType.MALICIOUS_INSIDER,
        )

    def _generate_race_condition_node(
        self, endpoints: List[APIEndpoint], schema: APISchema
    ) -> AttackNode:
        prompt = self._build_prompt(
            "Generate race condition and concurrency attack scenarios",
            endpoints[:6],
            schema,
            extra=(
                "Focus on: simultaneous requests on limited resources, "
                "double-submit, TOCTOU, and inventory depletion. "
                "Return JSON: {\"attack_nodes\": [...]}"
            ),
        )
        return self._parse_llm_node_response(
            prompt,
            default_name="Race Conditions",
            default_goal="Exploit concurrency weaknesses to corrupt state",
            persona=PersonaType.BOT_SWARM,
        )

    def _generate_injection_node(
        self, endpoints: List[APIEndpoint], schema: APISchema
    ) -> AttackNode:
        prompt = self._build_prompt(
            "Generate injection attack scenarios (SQL, NoSQL, template, command)",
            endpoints[:6],
            schema,
            extra=(
                "Focus on: SQLi, NoSQL operator injection, SSTI, "
                "and header injection via user-controlled input. "
                "Return JSON: {\"attack_nodes\": [...]}"
            ),
        )
        return self._parse_llm_node_response(
            prompt,
            default_name="Injection Attacks",
            default_goal="Inject malicious payloads through unvalidated inputs",
            persona=PersonaType.PENETRATION_TESTER,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_prompt(
        self,
        task: str,
        endpoints: List[APIEndpoint],
        schema: APISchema,
        extra: str = "",
    ) -> str:
        ep_lines = "\n".join(
            f"  {e.method.value} {e.path} — {e.summary or e.description or 'no description'}"
            for e in endpoints
        )
        return (
            f"Task: {task}\n\n"
            f"Target API: {schema.title} (base URL: {schema.base_url})\n\n"
            f"Endpoints to analyse:\n{ep_lines}\n\n"
            f"{extra}\n"
            "Attack tree attack nodes in JSON only:"
        )

    def _parse_llm_node_response(
        self,
        prompt: str,
        default_name: str,
        default_goal: str,
        persona: PersonaType,
    ) -> AttackNode:
        parent = AttackNode(
            name=default_name,
            goal=default_goal,
            severity=Severity.HIGH,
        )

        try:
            data = self._llm.complete_json(prompt, system=self._SYSTEM_PROMPT)
            raw_nodes = data.get("attack_nodes", [data])  # fallback: treat whole obj as one node
            if not isinstance(raw_nodes, list):
                raw_nodes = [raw_nodes]

            for rn in raw_nodes:
                if not isinstance(rn, dict):
                    continue
                vectors: List[AttackVector] = []
                for rv in rn.get("vectors", []):
                    vectors.append(AttackVector(
                        description=rv.get("description", ""),
                        payload={"hints": rv.get("payload_hints", [])},
                        expected_anomaly=rv.get("expected_anomaly", ""),
                        persona_type=persona,
                    ))
                child = AttackNode(
                    name=rn.get("name", default_name),
                    goal=rn.get("goal", default_goal),
                    severity=_parse_severity(rn.get("severity", "high")),
                    vectors=vectors or [
                        AttackVector(
                            description=rn.get("goal", default_goal),
                            persona_type=persona,
                        )
                    ],
                )
                parent.children.append(child)

        except Exception as exc:
            # Graceful degradation: add a single generic vector
            parent.vectors.append(
                AttackVector(
                    description=f"{default_goal} (LLM parse error: {exc})",
                    persona_type=persona,
                )
            )

        return parent
