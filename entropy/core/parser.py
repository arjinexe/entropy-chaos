""""Parse OpenAPI (2/3), Swagger, and auto-detect spec format."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import yaml  # PyYAML

from entropy.core.models import (
    APIEndpoint, APIParameter, APISchema, RequestMethod
)


class OpenAPIParser:
    """
    Parse OpenAPI 3.x or Swagger 2.x documents (JSON or YAML).
    Returns an APISchema ready for attack-tree generation.
    """

    def __init__(self, spec: Dict[str, Any]):
        self._spec = spec
        self._version = self._detect_version()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path) -> "OpenAPIParser":
        path = Path(path)
        raw = path.read_text(encoding="utf-8")
        if path.suffix in (".yaml", ".yml"):
            spec = yaml.safe_load(raw)
        else:
            spec = json.loads(raw)
        return cls(spec)

    @classmethod
    def from_dict(cls, spec: Dict[str, Any]) -> "OpenAPIParser":
        return cls(spec)

    def parse(self) -> APISchema:
        if self._version == 3:
            return self._parse_openapi3()
        return self._parse_swagger2()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _detect_version(self) -> int:
        if "openapi" in self._spec:
            return 3
        return 2  # swagger 2.x

    def _parse_openapi3(self) -> APISchema:
        info      = self._spec.get("info", {})
        servers   = self._spec.get("servers", [{}])
        base_url  = servers[0].get("url", "http://localhost") if servers else "http://localhost"
        endpoints = self._extract_endpoints_v3()
        return APISchema(
            title=info.get("title", "Unknown API"),
            version=info.get("version", "0.0.0"),
            base_url=base_url,
            endpoints=endpoints,
            security_schemes=self._spec.get("components", {}).get("securitySchemes", {}),
        )

    def _parse_swagger2(self) -> APISchema:
        info     = self._spec.get("info", {})
        host     = self._spec.get("host", "localhost")
        scheme   = (self._spec.get("schemes") or ["http"])[0]
        base_url = f"{scheme}://{host}{self._spec.get('basePath', '')}"
        endpoints = self._extract_endpoints_v2()
        return APISchema(
            title=info.get("title", "Unknown API"),
            version=info.get("version", "0.0.0"),
            base_url=base_url,
            endpoints=endpoints,
            security_schemes=self._spec.get("securityDefinitions", {}),
        )

    # ---- OpenAPI 3 endpoint extraction --------------------------------

    def _extract_endpoints_v3(self) -> List[APIEndpoint]:
        endpoints: List[APIEndpoint] = []
        components = self._spec.get("components", {})

        for path, path_item in self._spec.get("paths", {}).items():
            for method_str, op in path_item.items():
                if method_str.upper() not in RequestMethod.__members__:
                    continue
                try:
                    method = RequestMethod(method_str.upper())
                except ValueError:
                    continue

                params = self._parse_params_v3(
                    path_item.get("parameters", []) + op.get("parameters", []),
                    components,
                )
                body = self._parse_request_body_v3(op.get("requestBody"), components)

                endpoints.append(APIEndpoint(
                    path=path,
                    method=method,
                    summary=op.get("summary", ""),
                    description=op.get("description", ""),
                    parameters=params,
                    request_body=body,
                    responses=op.get("responses", {}),
                    tags=op.get("tags", []),
                    security=op.get("security", []),
                ))
        return endpoints

    def _parse_params_v3(
        self,
        raw_params: List[Dict[str, Any]],
        components: Dict[str, Any],
    ) -> List[APIParameter]:
        result: List[APIParameter] = []
        seen: set = set()
        for p in raw_params:
            # Resolve $ref
            if "$ref" in p:
                p = self._resolve_ref(p["$ref"], components)
            if not p:
                continue
            key = (p.get("name", ""), p.get("in", ""))
            if key in seen:
                continue
            seen.add(key)
            schema = p.get("schema", {})
            result.append(APIParameter(
                name=p.get("name", ""),
                location=p.get("in", "query"),
                type=schema.get("type", "string"),
                required=p.get("required", False),
                schema=schema,
                example=p.get("example") or schema.get("example"),
            ))
        return result

    def _parse_request_body_v3(
        self,
        raw_body: Optional[Dict[str, Any]],
        components: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if not raw_body:
            return None
        content = raw_body.get("content", {})
        for media_type, media in content.items():
            schema = media.get("schema", {})
            if "$ref" in schema:
                schema = self._resolve_ref(schema["$ref"], components) or schema
            return {"media_type": media_type, "schema": schema}
        return None

    # ---- Swagger 2 endpoint extraction --------------------------------

    def _extract_endpoints_v2(self) -> List[APIEndpoint]:
        endpoints: List[APIEndpoint] = []
        definitions = self._spec.get("definitions", {})

        for path, path_item in self._spec.get("paths", {}).items():
            for method_str, op in path_item.items():
                if method_str.upper() not in RequestMethod.__members__:
                    continue
                try:
                    method = RequestMethod(method_str.upper())
                except ValueError:
                    continue

                params = self._parse_params_v2(op.get("parameters", []), definitions)
                body   = self._extract_body_v2(op.get("parameters", []), definitions)

                endpoints.append(APIEndpoint(
                    path=path,
                    method=method,
                    summary=op.get("summary", ""),
                    description=op.get("description", ""),
                    parameters=params,
                    request_body=body,
                    responses=op.get("responses", {}),
                    tags=op.get("tags", []),
                ))
        return endpoints

    def _parse_params_v2(
        self,
        raw_params: List[Dict[str, Any]],
        definitions: Dict[str, Any],
    ) -> List[APIParameter]:
        result: List[APIParameter] = []
        for p in raw_params:
            if p.get("in") == "body":
                continue  # handled separately
            result.append(APIParameter(
                name=p.get("name", ""),
                location=p.get("in", "query"),
                type=p.get("type", "string"),
                required=p.get("required", False),
                schema=p,
                example=p.get("x-example"),
            ))
        return result

    def _extract_body_v2(
        self,
        raw_params: List[Dict[str, Any]],
        definitions: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        for p in raw_params:
            if p.get("in") == "body":
                schema = p.get("schema", {})
                if "$ref" in schema:
                    schema = self._resolve_ref_v2(schema["$ref"], definitions) or schema
                return {"media_type": "application/json", "schema": schema}
        return None

    # ---- $ref resolution ----------------------------------------------

    def _resolve_ref(
        self, ref: str, components: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Resolve a #/components/... reference."""
        parts = ref.lstrip("#/").split("/")
        # parts = ["components", "parameters", "SomeName"] etc.
        node: Any = self._spec
        for part in parts:
            if isinstance(node, dict):
                node = node.get(part)
            else:
                return None
        return node if isinstance(node, dict) else None

    def _resolve_ref_v2(
        self, ref: str, definitions: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Resolve a #/definitions/... reference."""
        name = ref.split("/")[-1]
        return definitions.get(name)
