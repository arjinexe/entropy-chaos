"""Crawl a target to find API endpoints when no spec is available."""
from __future__ import annotations

import json
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from entropy.core.models import APIEndpoint, APISchema, RequestMethod


# ---------------------------------------------------------------------------
# Common API paths wordlist (500+ entries condensed)
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
    "/administrator", "/admin/login", "/admin/index.php",
    "/admin/dashboard", "/admin/users", "/wp-admin",
    # GraphQL
    "/graphql", "/api/graphql", "/gql", "/query",
    # Misc REST
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3", "/rest", "/rest/v1",
    "/search", "/api/search", "/export", "/import",
    "/upload", "/download", "/files", "/media", "/assets",
    "/notifications", "/messages", "/events", "/webhooks",
    "/config", "/settings", "/preferences", "/reports",
    "/stats", "/analytics", "/logs", "/audit",
    # PHP application paths (testphp.vulnweb.com style)
    "/index.php", "/login.php", "/register.php", "/search.php",
    "/cart.php", "/checkout.php", "/product.php", "/products.php",
    "/categories.php", "/category.php", "/artist.php", "/artists.php",
    "/listproducts.php", "/showimage.php", "/comment.php",
    "/userinfo.php", "/signup.php", "/logout.php",
    "/AJAX/index.php", "/AJAX/", "/hpp/", "/hpp/params.php",
    "/secured/", "/admin/", "/cgi-bin/",
    # PHP info/debug leaks
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/error_log", "/.env", "/.git/config", "/config.php",
    "/wp-config.php", "/configuration.php",
    # API versioning patterns
    "/api/v1/search", "/api/v1/users", "/api/v1/products",
    "/api/v2/search", "/api/v2/users",
    # Common node/express
    "/api/auth", "/api/auth/signup", "/api/auth/signin",
    # Django / Flask
    "/api/schema/", "/api/schema/swagger-ui/", "/api/schema/redoc/",
    "/__debug__/", "/silk/",
    # Spring Boot
    "/swagger-ui/index.html", "/v3/api-docs", "/v3/api-docs/swagger-config",
    # Ruby on Rails
    "/rails/info", "/rails/info/properties",
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
    r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|request)\s*\(\s*[`'"]([^`'"]*api[^`'"]*)[`'"]""",
    re.IGNORECASE,
)
HREF_PATTERN = re.compile(r"""href=["']([^"']+)["']""", re.IGNORECASE)
LINK_PATTERN = re.compile(r"""["'](/(?:api|v\d|rest)[^"'\s>]{0,100})["']""", re.IGNORECASE)


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

    Usage::

        crawler = ActiveCrawler("https://api.example.com")
        result  = crawler.crawl()
        print(result.endpoints)
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = 8.0,
        max_paths: int = 200,
        verify_ssl: bool = True,
        proxy: Optional[str] = None,
        verbose: bool = False,
    ):
        self.base_url   = base_url.rstrip("/")
        self.timeout    = timeout
        self.max_paths  = max_paths
        self.verify_ssl = verify_ssl
        self.proxy      = proxy
        self.verbose    = verbose
        self._visited:  Set[str] = set()
        self._ctx       = self._build_ssl_ctx()

    # ------------------------------------------------------------------

    def crawl(self) -> DiscoveryResult:
        start  = time.monotonic()
        result = DiscoveryResult(base_url=self.base_url)

        self._log(f"🔍 Starting active discovery: {self.base_url}")

        # 1. Try to find OpenAPI spec automatically
        spec_url, schema = self._discover_openapi()
        if schema:
            result.spec_url  = spec_url
            result.schema    = schema
            result.endpoints = schema.endpoints
            self._log(f"  ✓ OpenAPI spec found: {spec_url} ({len(schema.endpoints)} endpoints)")

        # 2. robots.txt + sitemap
        robots_paths = self._parse_robots()
        sitemap_paths = self._parse_sitemap()

        # 3. Common path wordlist probe
        all_paths = list(dict.fromkeys(
            COMMON_API_PATHS[:self.max_paths] + robots_paths + sitemap_paths
        ))
        probed = self._probe_paths(all_paths)
        result.discovered_urls = probed

        # 4. Mine JS files from discovered HTML pages
        js_urls = self._find_js_urls(probed)
        for js_url in js_urls[:10]:
            extracted = self._mine_js(js_url)
            result.js_endpoints.extend(extracted)

        # 5. Convert discovered URLs → APIEndpoint objects (if no spec found)
        if not result.endpoints:
            result.endpoints = self._urls_to_endpoints(probed + result.js_endpoints)

        result.duration_s = time.monotonic() - start
        self._log(
            f"  ✓ Discovery done in {result.duration_s:.1f}s — "
            f"{len(result.endpoints)} endpoints, "
            f"{len(result.js_endpoints)} JS hints"
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
                if status == 200 and body:
                    if isinstance(body, dict) and (
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
    # robots.txt
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
                        path = path.strip()
                        if path and path != "/":
                            paths.append(path)
        except Exception:
            pass
        return paths[:50]

    # ------------------------------------------------------------------
    # sitemap.xml
    # ------------------------------------------------------------------

    def _parse_sitemap(self) -> List[str]:
        paths: List[str] = []
        try:
            body, status = self._get_raw(self.base_url + "/sitemap.xml")
            if status == 200 and body:
                locs = re.findall(r"<loc>([^<]+)</loc>", body)
                for loc in locs[:100]:
                    parsed = urlparse(loc)
                    if parsed.path:
                        paths.append(parsed.path)
        except Exception:
            pass
        return paths[:50]

    # ------------------------------------------------------------------
    # Path probing — concurrent for speed on large sites
    # ------------------------------------------------------------------

    def _probe_paths(self, paths: List[str]) -> List[str]:
        import threading

        found: List[str] = []
        lock = threading.Lock()
        unvisited = [p for p in paths if p not in self._visited]
        for p in unvisited:
            self._visited.add(p)

        def probe(path: str) -> None:
            url = self.base_url + path
            try:
                _, status = self._get(url)
                if status not in (404, 410, 0):
                    with lock:
                        found.append(url)
                    if self.verbose:
                        self._log(f"    [{status}] {url}")
            except Exception:
                pass

        # Use thread pool for concurrent probing (max 20 workers)
        from concurrent.futures import ThreadPoolExecutor, as_completed
        workers = min(20, max(1, len(unvisited)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(probe, p): p for p in unvisited}
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception:
                    pass

        return found

    # ------------------------------------------------------------------
    # JS mining
    # ------------------------------------------------------------------

    def _find_js_urls(self, discovered_urls: List[str]) -> List[str]:
        js_urls: List[str] = []
        for url in discovered_urls[:5]:
            try:
                body, status = self._get_raw(url)
                if status == 200 and body:
                    hrefs = HREF_PATTERN.findall(body)
                    for href in hrefs:
                        if href.endswith(".js"):
                            full = urljoin(self.base_url, href)
                            if full not in js_urls:
                                js_urls.append(full)
            except Exception:
                pass
        return js_urls

    def _mine_js(self, js_url: str) -> List[str]:
        endpoints: List[str] = []
        try:
            body, status = self._get_raw(js_url)
            if status == 200 and body:
                # Pattern 1: fetch/axios calls
                for m in JS_API_PATTERN.finditer(body):
                    ep = m.group(1)
                    if ep.startswith("/"):
                        endpoints.append(self.base_url + ep)
                    elif ep.startswith("http"):
                        endpoints.append(ep)
                # Pattern 2: string literals that look like API paths
                for m in LINK_PATTERN.finditer(body):
                    path = m.group(1)
                    full = self.base_url + path
                    if full not in endpoints:
                        endpoints.append(full)
        except Exception:
            pass
        return endpoints[:30]

    # ------------------------------------------------------------------
    # URL → APIEndpoint conversion
    # ------------------------------------------------------------------

    def _urls_to_endpoints(self, urls: List[str]) -> List[APIEndpoint]:
        endpoints: List[APIEndpoint] = []
        seen: Set[str] = set()
        for url in urls:
            parsed = urlparse(url)
            path   = parsed.path or "/"
            if path in seen:
                continue
            seen.add(path)
            # Infer likely methods
            methods = [RequestMethod.GET]
            if any(kw in path for kw in ("/create", "/add", "/new", "/register", "/login", "/upload")):
                methods = [RequestMethod.POST]
            elif any(kw in path for kw in ("/update", "/edit")):
                methods = [RequestMethod.PUT, RequestMethod.PATCH]
            elif any(kw in path for kw in ("/delete", "/remove")):
                methods = [RequestMethod.DELETE]

            for method in methods:
                endpoints.append(APIEndpoint(
                    path=path,
                    method=method,
                    summary=f"Discovered: {method.value} {path}",
                    description="Auto-discovered via active crawling",
                    tags=["discovered"],
                ))
        return endpoints

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
        """GET and return (parsed_json_or_None, status_code)."""
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
