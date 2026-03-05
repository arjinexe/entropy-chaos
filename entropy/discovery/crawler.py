"""Crawl a target to find API endpoints when no spec is available."""
from __future__ import annotations

import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

from entropy.core.models import APIEndpoint, APIParameter, APISchema, RequestMethod


# ---------------------------------------------------------------------------
# Common API paths wordlist
# ---------------------------------------------------------------------------

COMMON_API_PATHS: List[str] = [
    # OpenAPI / docs
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api-docs/", "/api/docs", "/api/v1/docs",
    "/api/v2/docs", "/swagger-ui.html", "/swagger-ui/",
    "/redoc", "/docs", "/v1/api-docs", "/v2/api-docs",
    # Health / metadata
    "/health", "/healthz", "/ping", "/status", "/ready", "/live",
    "/metrics", "/info", "/_health", "/_status", "/actuator/health",
    "/actuator", "/actuator/info", "/actuator/metrics",
    # Auth
    "/auth/login", "/auth/logout", "/auth/register", "/auth/token",
    "/auth/refresh", "/login", "/logout", "/register", "/signup",
    "/token", "/oauth/token", "/oauth2/token", "/api/auth/login",
    "/api/token", "/api/login", "/api/register",
    # Users
    "/users", "/user", "/api/users", "/api/v1/users", "/api/v2/users",
    "/users/me", "/me", "/profile", "/account", "/accounts",
    "/api/me", "/api/profile", "/api/account",
    # Common CRUD
    "/api/items", "/api/products", "/api/orders", "/api/payments",
    "/api/v1/items", "/api/v1/products", "/api/v1/orders",
    "/items", "/products", "/orders", "/payments", "/cart",
    # Admin
    "/admin", "/admin/", "/api/admin", "/dashboard", "/manage",
    # GraphQL
    "/graphql", "/api/graphql", "/gql", "/query",
    # Misc
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3", "/rest", "/rest/v1",
    "/search", "/api/search", "/export", "/import",
    "/upload", "/download", "/files", "/media", "/assets",
    "/notifications", "/messages", "/events", "/webhooks",
    "/config", "/settings", "/preferences", "/reports",
    "/stats", "/analytics", "/logs", "/audit",
    # PHP-specific paths (common in legacy/test apps)
    "/index.php", "/login.php", "/register.php", "/search.php",
    "/products.php", "/product.php", "/cart.php", "/checkout.php",
    "/userinfo.php", "/listproducts.php", "/productdetails.php",
    "/guestbook.php", "/comment.php", "/signup.php", "/user.php",
    "/admin.php", "/admin/index.php", "/panel.php",
    "/api.php", "/ajax.php", "/upload.php", "/download.php",
]

OPENAPI_DISCOVERY_PATHS: List[str] = [
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/api-docs", "/api-docs.json", "/api-docs.yaml",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/api/openapi.json", "/api/swagger.json",
    "/docs/openapi.json", "/docs/swagger.json",
]

JS_API_PATTERN = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|request)\s*\(\s*[`'"]([^`'"]{3,200})[`'"]""",
    re.IGNORECASE,
)
HREF_PATTERN   = re.compile(r"""href=["']([^"'#][^"']{0,200})["']""", re.IGNORECASE)
SRC_PATTERN    = re.compile(r"""src=["']([^"']+\.js[^"']{0,50})["']""", re.IGNORECASE)
FORM_PATTERN   = re.compile(r"""<form[^>]*action=["']([^"']+)["'][^>]*>""", re.IGNORECASE)
METHOD_PATTERN = re.compile(r"""<form[^>]*method=["']([^"']+)["']""", re.IGNORECASE)
INPUT_PATTERN  = re.compile(r"""<input[^>]+name=["']([^"']+)["']""", re.IGNORECASE)
LINK_PATTERN   = re.compile(r"""["'](/(?:api|v\d|rest)[^"'\s>]{0,100})["']""", re.IGNORECASE)
QUERY_URL_PAT  = re.compile(r"""href=["']([^"']+\?[^"']+)["']""", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class DiscoveryResult:
    base_url:        str
    discovered_urls: List[str] = field(default_factory=list)
    schema:          Optional[APISchema] = None
    endpoints:       List[APIEndpoint] = field(default_factory=list)
    spec_url:        Optional[str] = None
    js_endpoints:    List[str] = field(default_factory=list)
    duration_s:      float = 0.0

    @property
    def total_found(self) -> int:
        return len(self.endpoints) + len(self.js_endpoints)


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

class ActiveCrawler:
    """
    Discover API endpoints for a target URL without a spec file.

    Strategies:
      1. OpenAPI/Swagger auto-detection
      2. robots.txt + sitemap.xml
      3. Common path wordlist (including PHP paths)
      4. Recursive HTML link following (depth-limited)
      5. Form action + input name extraction
      6. Query parameter discovery and parameterisation
      7. JS file mining for fetch/axios calls
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = 8.0,
        max_paths: int = 300,
        max_depth: int = 2,
        verify_ssl: bool = True,
        proxy: Optional[str] = None,
        verbose: bool = False,
    ):
        self.base_url     = base_url.rstrip("/")
        self.timeout      = timeout
        self.max_paths    = max_paths
        self.max_depth    = max_depth
        self.verify_ssl   = verify_ssl
        self.proxy        = proxy
        self.verbose      = verbose
        self._visited:    Set[str] = set()
        self._ctx         = self._build_ssl_ctx()
        self._parsed_base = urlparse(self.base_url)

    # ------------------------------------------------------------------

    def crawl(self) -> DiscoveryResult:
        start  = time.monotonic()
        result = DiscoveryResult(base_url=self.base_url)

        # 1. Try OpenAPI spec first
        spec_url, schema = self._discover_openapi()
        if schema:
            result.spec_url   = spec_url
            result.schema     = schema
            result.endpoints  = schema.endpoints
            result.duration_s = time.monotonic() - start
            return result

        # 2. robots.txt + sitemap
        robots_paths  = self._parse_robots()
        sitemap_paths = self._parse_sitemap()

        # 3. Common path wordlist
        all_paths = list(dict.fromkeys(
            COMMON_API_PATHS[:self.max_paths] + robots_paths + sitemap_paths
        ))
        probed = self._probe_paths(all_paths)
        result.discovered_urls = list(probed)

        # 4. Recursive HTML crawl
        seed_urls = [self.base_url] + probed[:10]
        html_urls, form_endpoints = self._crawl_html(seed_urls)
        for url in html_urls:
            if url not in result.discovered_urls:
                result.discovered_urls.append(url)

        # 5. Mine JS files
        js_urls = self._find_js_urls(result.discovered_urls + [self.base_url])
        for js_url in js_urls[:15]:
            extracted = self._mine_js(js_url)
            result.js_endpoints.extend(extracted)

        # 6. Convert to APIEndpoint objects
        result.endpoints = self._urls_to_endpoints(
            result.discovered_urls + result.js_endpoints,
            form_endpoints=form_endpoints,
        )

        result.duration_s = time.monotonic() - start
        self._log(
            f"  ✓ Discovery done in {result.duration_s:.1f}s — "
            f"{len(result.endpoints)} endpoints"
        )
        return result

    # ------------------------------------------------------------------
    # OpenAPI auto-detection
    # ------------------------------------------------------------------

    def _discover_openapi(self) -> Tuple[Optional[str], Optional[APISchema]]:
        for path in OPENAPI_DISCOVERY_PATHS:
            url = self.base_url + path
            try:
                body, status = self._get(url)
                if status == 200 and isinstance(body, dict) and (
                    "openapi" in body or "swagger" in body or "paths" in body
                ):
                    from entropy.core.parser import OpenAPIParser
                    schema = OpenAPIParser.from_dict(body).parse()
                    schema.base_url = self.base_url
                    return url, schema
            except Exception:
                pass
        return None, None

    # ------------------------------------------------------------------
    # robots.txt / sitemap
    # ------------------------------------------------------------------

    def _parse_robots(self) -> List[str]:
        paths: List[str] = []
        try:
            body, status = self._get_raw(self.base_url + "/robots.txt")
            if status == 200 and body:
                for line in body.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("disallow:", "allow:")):
                        _, _, path = line.partition(":")
                        path = path.strip().split()[0] if path.strip() else ""
                        if path and path != "/" and not path.startswith("*"):
                            paths.append(path)
        except Exception:
            pass
        return paths[:50]

    def _parse_sitemap(self) -> List[str]:
        paths: List[str] = []
        try:
            body, status = self._get_raw(self.base_url + "/sitemap.xml")
            if status == 200 and body:
                for loc in re.findall(r"<loc>([^<]+)</loc>", body)[:100]:
                    p = urlparse(loc).path
                    if p and p != "/":
                        paths.append(p)
        except Exception:
            pass
        return paths[:50]

    # ------------------------------------------------------------------
    # Path probing
    # ------------------------------------------------------------------

    def _probe_paths(self, paths: List[str]) -> List[str]:
        found: List[str] = []
        for path in paths:
            if path in self._visited:
                continue
            self._visited.add(path)
            url = self.base_url + path if path.startswith("/") else path
            try:
                _, status = self._get(url)
                if status not in (404, 410, 0):
                    found.append(url)
                    if self.verbose:
                        self._log(f"    [{status}] {url}")
            except Exception:
                pass
        return found

    # ------------------------------------------------------------------
    # Recursive HTML crawl
    # ------------------------------------------------------------------

    def _crawl_html(
        self, seed_urls: List[str], depth: int = 0
    ) -> Tuple[List[str], List[Dict]]:
        found_urls:     List[str]  = []
        form_endpoints: List[Dict] = []
        queue = list(seed_urls)

        while queue and depth <= self.max_depth:
            next_queue: List[str] = []
            for url in queue[:20]:
                if url in self._visited:
                    continue
                self._visited.add(url)

                body, status = self._get_raw(url)
                if not body or status not in (200, 301, 302):
                    continue

                # Follow <a href> links
                for href in HREF_PATTERN.findall(body):
                    full = self._resolve_url(href, url)
                    if full and full not in self._visited and full not in found_urls:
                        found_urls.append(full)
                        if self._is_same_origin(full):
                            next_queue.append(full)

                # URLs with query strings
                for query_url in QUERY_URL_PAT.findall(body):
                    full = self._resolve_url(query_url, url)
                    if full and full not in found_urls:
                        found_urls.append(full)

                # Forms: extract action + method + input names
                actions = FORM_PATTERN.findall(body)
                methods = METHOD_PATTERN.findall(body)
                inputs  = INPUT_PATTERN.findall(body)
                for i, action in enumerate(actions):
                    full_action = self._resolve_url(action, url)
                    if not full_action:
                        continue
                    method = methods[i].upper() if i < len(methods) else "POST"
                    form_endpoints.append({
                        "path":   urlparse(full_action).path,
                        "method": method,
                        "params": inputs,
                    })
                    if full_action not in found_urls:
                        found_urls.append(full_action)

            queue = next_queue
            depth += 1

        return found_urls, form_endpoints

    # ------------------------------------------------------------------
    # JS mining
    # ------------------------------------------------------------------

    def _find_js_urls(self, urls: List[str]) -> List[str]:
        js_urls: List[str] = []
        seen: Set[str] = set()
        for url in urls[:15]:
            try:
                body, status = self._get_raw(url)
                if not body or status != 200:
                    continue
                for src in SRC_PATTERN.findall(body):
                    full = self._resolve_url(src, url)
                    if full and full not in seen:
                        seen.add(full)
                        js_urls.append(full)
                for href in HREF_PATTERN.findall(body):
                    if ".js" in href:
                        full = self._resolve_url(href, url)
                        if full and full not in seen:
                            seen.add(full)
                            js_urls.append(full)
            except Exception:
                pass
        return js_urls

    def _mine_js(self, js_url: str) -> List[str]:
        endpoints: List[str] = []
        try:
            body, status = self._get_raw(js_url)
            if status == 200 and body:
                for m in JS_API_PATTERN.finditer(body):
                    ep = m.group(1)
                    if ep.startswith("/"):
                        endpoints.append(self.base_url + ep)
                    elif ep.startswith("http"):
                        endpoints.append(ep)
                for m in LINK_PATTERN.finditer(body):
                    full = self.base_url + m.group(1)
                    if full not in endpoints:
                        endpoints.append(full)
        except Exception:
            pass
        return endpoints[:30]

    # ------------------------------------------------------------------
    # URL → APIEndpoint conversion
    # ------------------------------------------------------------------

    def _urls_to_endpoints(
        self,
        urls: List[str],
        form_endpoints: Optional[List[Dict]] = None,
    ) -> List[APIEndpoint]:
        endpoints: List[APIEndpoint] = []
        seen: Set[str] = set()

        def _add(path: str, method: RequestMethod,
                 params: Optional[List[str]] = None,
                 query_params: Optional[Dict] = None):
            key = f"{method.value}:{path}"
            if key in seen:
                return
            seen.add(key)

            parameters: List[APIParameter] = []

            # Query string params
            for pname in (query_params or {}):
                parameters.append(APIParameter(
                    name=pname, location="query",
                    required=False, type="string",
                ))

            # Form field params
            for pname in (params or []):
                parameters.append(APIParameter(
                    name=pname, location="body",
                    required=False, type="string",
                ))

            # Parameterise numeric path segments (e.g. /users/1 → /users/{id})
            path_p = re.sub(r"/(\d+)(?=/|$)", r"/{id}", path)
            if path_p != path:
                parameters.append(APIParameter(
                    name="id", location="path",
                    required=True, type="integer",
                ))

            endpoints.append(APIEndpoint(
                path=path_p,
                method=method,
                summary=f"Discovered: {method.value} {path_p}",
                description="Auto-discovered via active crawling",
                tags=["discovered"],
                parameters=parameters,
                request_body=(
                    {"properties": {p: {"type": "string"} for p in (params or [])}}
                    if params else None
                ),
            ))

        for url in urls:
            parsed      = urlparse(url)
            path        = parsed.path or "/"
            query_dict  = parse_qs(parsed.query) if parsed.query else {}
            path_lower  = path.lower()

            method = RequestMethod.GET
            if any(k in path_lower for k in ("/create", "/add", "/new", "/register",
                                               "/login", "/upload", "/submit", "/signup")):
                method = RequestMethod.POST
            elif any(k in path_lower for k in ("/update", "/edit", "/modify")):
                method = RequestMethod.PATCH
            elif any(k in path_lower for k in ("/delete", "/remove", "/destroy")):
                method = RequestMethod.DELETE

            _add(path, method, query_params=query_dict if query_dict else None)

            # For GET endpoints with query params, also register a POST variant
            if query_dict and method == RequestMethod.GET:
                _add(path, RequestMethod.POST, params=list(query_dict.keys()))

        for fe in (form_endpoints or []):
            path   = fe.get("path", "/")
            m_str  = fe.get("method", "POST").upper()
            params = fe.get("params", [])
            try:
                method = RequestMethod(m_str)
            except ValueError:
                method = RequestMethod.POST
            _add(path, method, params=params)

        return endpoints

    # ------------------------------------------------------------------
    # URL helpers
    # ------------------------------------------------------------------

    def _resolve_url(self, href: str, base: str) -> Optional[str]:
        try:
            href = href.strip()
            if not href or href.startswith(("mailto:", "javascript:", "tel:", "#", "data:")):
                return None
            full   = urljoin(base, href)
            parsed = urlparse(full)
            if parsed.netloc and parsed.netloc != self._parsed_base.netloc:
                return None
            return urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, parsed.query, ""
            ))
        except Exception:
            return None

    def _is_same_origin(self, url: str) -> bool:
        try:
            return urlparse(url).netloc == self._parsed_base.netloc
        except Exception:
            return False

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _build_ssl_ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    def _get(self, url: str) -> Tuple[Optional[dict], int]:
        try:
            raw, status = self._get_raw(url)
            if raw:
                try:
                    return json.loads(raw), status
                except Exception:
                    return None, status
            return None, status
        except Exception:
            return None, 0

    def _get_raw(self, url: str) -> Tuple[Optional[str], int]:
        headers = {
            "User-Agent": "entropy-chaos/0.3.0 (security-scanner)",
            "Accept": "application/json, text/html, */*",
        }
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                return resp.read().decode(errors="replace"), resp.status
        except urllib.error.HTTPError as exc:
            return None, exc.code
        except Exception:
            return None, 0

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)
