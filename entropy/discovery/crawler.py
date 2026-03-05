"""Smart crawler: form parsing, same-domain BFS, JS mining, param extraction.

Design goals (v0.4.4):
- Never follow links off the target domain — no infinite loops
- Depth-limited BFS (default 4 levels), page-capped (default 80)
- Full HTML form extraction: action, method, every input field
- Query-param extraction from discovered URLs
- Concurrent wordlist probing with ThreadPoolExecutor
- Auto OpenAPI spec detection
- robots.txt + sitemap.xml integration
"""
from __future__ import annotations

import json
import re
import ssl
import time
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

from entropy.core.models import APIEndpoint, APIParameter, APISchema, RequestMethod


# ---------------------------------------------------------------------------
# Wordlists
# ---------------------------------------------------------------------------

COMMON_API_PATHS: List[str] = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api-docs/", "/api/docs", "/api/v1/docs",
    "/api/v2/docs", "/swagger-ui.html", "/swagger-ui/",
    "/redoc", "/docs", "/v1/api-docs", "/v2/api-docs",
    "/health", "/healthz", "/ping", "/status", "/ready", "/live",
    "/metrics", "/info", "/_health", "/_status", "/actuator/health",
    "/actuator", "/actuator/info", "/actuator/metrics",
    "/auth/login", "/auth/logout", "/auth/register", "/auth/token",
    "/auth/refresh", "/login", "/logout", "/register", "/signup",
    "/token", "/oauth/token", "/oauth2/token", "/api/auth/login",
    "/api/token", "/api/login", "/api/register",
    "/users", "/user", "/api/users", "/api/v1/users", "/api/v2/users",
    "/users/me", "/me", "/profile", "/account", "/accounts",
    "/api/me", "/api/profile", "/api/account",
    "/api/items", "/api/products", "/api/orders", "/api/payments",
    "/api/v1/items", "/api/v1/products", "/api/v1/orders",
    "/items", "/products", "/orders", "/payments", "/cart",
    "/admin", "/admin/", "/api/admin", "/dashboard", "/manage",
    "/administrator", "/admin/login", "/admin/index.php",
    "/admin/dashboard", "/admin/users", "/wp-admin",
    "/graphql", "/api/graphql", "/gql", "/query",
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3", "/rest", "/rest/v1",
    "/search", "/api/search", "/export", "/import",
    "/upload", "/download", "/files", "/media", "/assets",
    "/notifications", "/messages", "/events", "/webhooks",
    "/config", "/settings", "/preferences", "/reports",
    "/stats", "/analytics", "/logs", "/audit",
    "/index.php", "/login.php", "/register.php", "/search.php",
    "/cart.php", "/checkout.php", "/product.php", "/products.php",
    "/categories.php", "/category.php", "/artist.php", "/artists.php",
    "/listproducts.php", "/showimage.php", "/comment.php",
    "/userinfo.php", "/signup.php", "/logout.php",
    "/AJAX/index.php", "/AJAX/", "/hpp/", "/hpp/params.php",
    "/secured/", "/cgi-bin/",
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/error_log", "/.env", "/.git/config", "/config.php",
    "/wp-config.php", "/configuration.php",
    "/Mod_Rewrite_Shop/", "/Mod_Rewrite_Shop/details.php",
    "/AJAX/infocateg.php", "/AJAX/listproducts.php",
    "/guestbook.php", "/privacy.php",
    "/api/auth", "/api/auth/signup", "/api/auth/signin",
    "/api/schema/", "/api/schema/swagger-ui/", "/api/schema/redoc/",
    "/__debug__/", "/silk/",
    "/swagger-ui/index.html", "/v3/api-docs",
    "/wp-json/", "/wp-json/wp/v2/", "/wp-json/wp/v2/users",
    "/wp-login.php", "/xmlrpc.php",
    "/.git/HEAD", "/.svn/entries", "/backup.sql", "/dump.sql",
    "/db.php", "/database.php", "/connect.php",
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
LINK_PATTERN   = re.compile(r"""[\"'](/(?:api|v\d|rest)[^\"'\s>]{0,100})[\"']""", re.IGNORECASE)
HREF_PATTERN   = re.compile(r"""href\s*=\s*[\"']([^\"'#\s]{1,500})[\"']""", re.IGNORECASE)
FORM_PATTERN   = re.compile(r"""<form\b([^>]*)>(.*?)</form>""", re.IGNORECASE | re.DOTALL)
INPUT_PATTERN  = re.compile(r"""<(?:input|textarea|select)\b([^>]*)/?>""", re.IGNORECASE)
ATTR_PATTERN   = re.compile(r"""(\w[\w-]*)\s*=\s*(?:[\"']([^\"']*)[\"']|(\S+))""")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class FormInput:
    name:       str
    input_type: str  = "text"
    value:      str  = ""
    required:   bool = False


@dataclass
class FormSpec:
    """An HTML form discovered during crawling."""
    action:   str
    method:   str                 = "GET"
    inputs:   List[FormInput]     = field(default_factory=list)
    page_url: str                 = ""
    enctype:  str                 = "application/x-www-form-urlencoded"

    _CSRF_NAMES = frozenset({
        "csrf", "csrf_token", "_token", "token", "__requestverificationtoken",
        "csrfmiddlewaretoken", "authenticity_token", "_csrf", "csrfkey",
        "xsrf", "xsrftoken", "_xsrf",
    })

    @property
    def has_csrf_token(self) -> bool:
        return any(i.name.lower() in self._CSRF_NAMES for i in self.inputs)

    @property
    def injectable_inputs(self) -> List[FormInput]:
        skip = {"submit", "button", "reset", "image", "file", "checkbox", "radio"}
        return [i for i in self.inputs if i.input_type.lower() not in skip]

    def to_dict(self) -> Dict:
        return {
            "action": self.action,
            "method": self.method,
            "inputs": [{"name": i.name, "type": i.input_type} for i in self.inputs],
            "has_csrf": self.has_csrf_token,
        }


@dataclass
class DiscoveryResult:
    base_url:        str
    discovered_urls: List[str]       = field(default_factory=list)
    schema:          Optional[APISchema] = None
    endpoints:       List[APIEndpoint]  = field(default_factory=list)
    forms:           List[FormSpec]     = field(default_factory=list)
    spec_url:        Optional[str]      = None
    js_endpoints:    List[str]          = field(default_factory=list)
    duration_s:      float              = 0.0

    @property
    def total_found(self) -> int:
        return len(self.endpoints) + len(self.js_endpoints)


# ---------------------------------------------------------------------------
# Smart Crawler
# ---------------------------------------------------------------------------

class ActiveCrawler:
    """
    Discover API endpoints and HTML forms without a spec file.

    - BFS link following, same-domain only (no off-domain drift)
    - Depth-limited + page-capped to prevent infinite loops
    - Full HTML form extraction (action, method, inputs)
    - Concurrent wordlist probing
    - JS API path mining
    - robots.txt + sitemap.xml
    - OpenAPI auto-detection
    """

    def __init__(
        self,
        base_url:   str,
        timeout:    float = 6.0,
        max_paths:  int   = 300,
        max_pages:  int   = 80,
        max_depth:  int   = 4,
        verify_ssl: bool  = True,
        proxy:      Optional[str] = None,
        verbose:    bool  = False,
    ):
        parsed = urlparse(base_url.rstrip("/"))
        self.base_url    = f"{parsed.scheme}://{parsed.netloc}"
        self.base_domain = parsed.netloc.lower()
        self.timeout     = timeout
        self.max_paths   = max_paths
        self.max_pages   = max_pages
        self.max_depth   = max_depth
        self.verify_ssl  = verify_ssl
        self.proxy       = proxy
        self.verbose     = verbose
        self._visited_paths: Set[str] = set()
        self._ctx = self._build_ssl_ctx()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def crawl(self) -> DiscoveryResult:
        start  = time.monotonic()
        result = DiscoveryResult(base_url=self.base_url)

        self._log(f"🔍 Smart crawl: {self.base_url}")

        # 1. Auto-detect OpenAPI spec
        spec_url, schema = self._discover_openapi()
        if schema:
            result.spec_url  = spec_url
            result.schema    = schema
            result.endpoints = list(schema.endpoints)
            self._log(f"  ✓ OpenAPI spec: {spec_url} ({len(schema.endpoints)} endpoints)")

        # 2. Concurrent wordlist probing
        robots_paths  = self._parse_robots()
        sitemap_paths = self._parse_sitemap()
        all_paths = list(dict.fromkeys(
            COMMON_API_PATHS[:self.max_paths] + robots_paths + sitemap_paths
        ))
        probed_urls = self._probe_paths(all_paths)
        result.discovered_urls = probed_urls
        self._log(f"  ✓ Wordlist: {len(probed_urls)} live paths")

        # 3. BFS link following (same-domain, depth-limited)
        bfs_urls, bfs_forms = self._bfs_crawl(self.base_url)
        result.forms.extend(bfs_forms)
        seen_urls = set(result.discovered_urls)
        for u in bfs_urls:
            if u not in seen_urls:
                result.discovered_urls.append(u)
                seen_urls.add(u)
        self._log(f"  ✓ BFS crawl: {len(bfs_urls)} pages, {len(bfs_forms)} forms")

        # 4. JS mining
        js_urls = self._collect_js_urls(result.discovered_urls[:25])
        for js_url in js_urls[:15]:
            for ep in self._mine_js(js_url):
                result.js_endpoints.append(ep)
        if result.js_endpoints:
            self._log(f"  ✓ JS mining: {len(result.js_endpoints)} hints")

        # 5. Convert to APIEndpoint objects (if no spec found)
        if not result.endpoints:
            result.endpoints = self._urls_to_endpoints(
                result.discovered_urls + result.js_endpoints, result.forms
            )

        # 6. Enrich existing endpoints with form-discovered params
        self._enrich_from_forms(result.endpoints, result.forms)

        result.duration_s = time.monotonic() - start
        self._log(
            f"  ✓ Done {result.duration_s:.1f}s — "
            f"{len(result.endpoints)} endpoints, {len(result.forms)} forms"
        )
        return result

    # ------------------------------------------------------------------
    # BFS (same-domain, depth-limited, no infinite loops)
    # ------------------------------------------------------------------

    def _bfs_crawl(self, start_url: str) -> Tuple[List[str], List[FormSpec]]:
        visited:    Set[str]       = set()
        found_urls: List[str]      = []
        forms:      List[FormSpec] = []
        queue: deque = deque([(start_url, 0)])

        while queue and len(visited) < self.max_pages:
            url, depth = queue.popleft()
            url = self._normalise_url(url)
            if not url or url in visited:
                continue
            if not self._is_same_domain(url):
                continue
            visited.add(url)
            found_urls.append(url)

            html, status = self._get_raw(url)
            if not html or status == 0:
                continue

            page_forms = self._parse_forms(html, url)
            forms.extend(page_forms)

            if depth < self.max_depth:
                for link in self._extract_links(html, url):
                    norm = self._normalise_url(link)
                    if norm and norm not in visited and self._is_same_domain(norm):
                        queue.append((norm, depth + 1))

        return found_urls, forms

    def _is_same_domain(self, url: str) -> bool:
        try:
            host = urlparse(url).netloc.lower()
            return host == self.base_domain or host.endswith("." + self.base_domain)
        except Exception:
            return False

    def _normalise_url(self, url: str) -> Optional[str]:
        if not url:
            return None
        if url.startswith("http://") or url.startswith("https://"):
            pass
        elif url.startswith("//"):
            scheme = urlparse(self.base_url).scheme
            url = f"{scheme}:{url}"
        elif url.startswith("/"):
            url = self.base_url + url
        else:
            return None
        url = url.split("#")[0].strip()
        ext = url.rsplit(".", 1)[-1].lower().split("?")[0]
        if ext in ("png","jpg","jpeg","gif","ico","svg","woff","woff2",
                   "ttf","eot","css","pdf","zip","gz","tar","mp4","mp3","webp"):
            return None
        return url

    def _extract_links(self, html: str, page_url: str) -> List[str]:
        links = []
        for m in HREF_PATTERN.finditer(html):
            href = m.group(1).strip()
            if href:
                abs_url = urljoin(page_url, href)
                norm    = self._normalise_url(abs_url)
                if norm and self._is_same_domain(norm):
                    links.append(norm)
        return links

    # ------------------------------------------------------------------
    # Form parsing
    # ------------------------------------------------------------------

    def _parse_forms(self, html: str, page_url: str) -> List[FormSpec]:
        forms: List[FormSpec] = []
        for form_m in FORM_PATTERN.finditer(html):
            tag_attrs = self._parse_attrs(form_m.group(1))
            action  = tag_attrs.get("action", "") or page_url
            method  = tag_attrs.get("method", "GET").upper()
            enctype = tag_attrs.get("enctype", "application/x-www-form-urlencoded")

            # Absolute action URL
            if not action.startswith("http"):
                action = urljoin(page_url, action)

            if not self._is_same_domain(action):
                continue   # skip forms that post to external domains

            inputs: List[FormInput] = []
            for inp_m in INPUT_PATTERN.finditer(form_m.group(2)):
                inp_attrs = self._parse_attrs(inp_m.group(1))
                name  = inp_attrs.get("name", "")
                itype = inp_attrs.get("type", "text")
                value = inp_attrs.get("value", "")
                if name:
                    inputs.append(FormInput(name=name, input_type=itype, value=value,
                                            required="required" in inp_m.group(1).lower()))

            if method in ("GET", "POST"):
                forms.append(FormSpec(action=action, method=method,
                                      inputs=inputs, page_url=page_url,
                                      enctype=enctype))
        return forms

    def _parse_attrs(self, s: str) -> Dict[str, str]:
        result = {}
        for m in ATTR_PATTERN.finditer(s):
            key = m.group(1).lower()
            val = m.group(2) if m.group(2) is not None else (m.group(3) or "")
            result[key] = val
        return result

    # ------------------------------------------------------------------
    # OpenAPI auto-detection
    # ------------------------------------------------------------------

    def _discover_openapi(self) -> Tuple[Optional[str], Optional[APISchema]]:
        for path in OPENAPI_DISCOVERY_PATHS:
            url = self.base_url + path
            try:
                body, status = self._get_json(url)
                if status == 200 and isinstance(body, dict):
                    if "openapi" in body or "swagger" in body or "paths" in body:
                        from entropy.core.parser import OpenAPIParser
                        schema = OpenAPIParser.from_dict(body).parse()
                        schema.base_url = self.base_url
                        return url, schema
            except Exception:
                pass
        return None, None

    # ------------------------------------------------------------------
    # robots.txt + sitemap
    # ------------------------------------------------------------------

    def _parse_robots(self) -> List[str]:
        paths: List[str] = []
        try:
            body, status = self._get_raw(self.base_url + "/robots.txt")
            if status == 200 and body:
                for line in body.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("disallow:", "allow:")):
                        _, _, p = line.partition(":")
                        p = p.strip().split("?")[0]
                        if p and p != "/":
                            paths.append(p)
        except Exception:
            pass
        return paths[:80]

    def _parse_sitemap(self) -> List[str]:
        paths: List[str] = []
        try:
            body, status = self._get_raw(self.base_url + "/sitemap.xml")
            if status == 200 and body:
                for loc in re.findall(r"<loc>([^<]+)</loc>", body)[:150]:
                    parsed = urlparse(loc)
                    if parsed.path and self._is_same_domain(loc):
                        paths.append(parsed.path)
        except Exception:
            pass
        return paths[:80]

    # ------------------------------------------------------------------
    # Concurrent wordlist probing
    # ------------------------------------------------------------------

    def _probe_paths(self, paths: List[str]) -> List[str]:
        found: List[str] = []
        lock  = threading.Lock()
        unvisited = [p for p in paths if p not in self._visited_paths]
        for p in unvisited:
            self._visited_paths.add(p)

        def probe(path: str) -> None:
            url = self.base_url + path
            try:
                _, status = self._get_json(url)
                if status not in (404, 410, 0):
                    with lock:
                        found.append(url)
                    if self.verbose:
                        self._log(f"    [{status}] {url}")
            except Exception:
                pass

        workers = min(50, max(1, len(unvisited)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(probe, p) for p in unvisited]
            for fut in as_completed(futs):
                try:
                    fut.result()
                except Exception:
                    pass
        return found

    # ------------------------------------------------------------------
    # JS mining
    # ------------------------------------------------------------------

    def _collect_js_urls(self, page_urls: List[str]) -> List[str]:
        js_urls: List[str] = []
        seen: Set[str] = set()
        for url in page_urls:
            try:
                html, status = self._get_raw(url)
                if status == 200 and html:
                    for m in re.finditer(r"""src\s*=\s*[\"']([^\"']+\.js[^\"']*)[\"']""", html, re.I):
                        abs_js = self._normalise_url(urljoin(url, m.group(1)))
                        if abs_js and abs_js not in seen and self._is_same_domain(abs_js):
                            js_urls.append(abs_js)
                            seen.add(abs_js)
            except Exception:
                pass
        return js_urls[:20]

    def _mine_js(self, js_url: str) -> List[str]:
        endpoints: List[str] = []
        try:
            body, status = self._get_raw(js_url)
            if status == 200 and body:
                for m in JS_API_PATTERN.finditer(body):
                    ep = m.group(1)
                    full = (self.base_url + ep) if ep.startswith("/") else ep
                    if full not in endpoints:
                        endpoints.append(full)
                for m in LINK_PATTERN.finditer(body):
                    full = self.base_url + m.group(1)
                    if full not in endpoints:
                        endpoints.append(full)
        except Exception:
            pass
        return endpoints[:40]

    # ------------------------------------------------------------------
    # URL → APIEndpoint conversion
    # ------------------------------------------------------------------

    def _urls_to_endpoints(
        self,
        urls:  List[str],
        forms: Optional[List[FormSpec]] = None,
    ) -> List[APIEndpoint]:
        endpoints: List[APIEndpoint] = []
        seen: Set[str] = set()

        def add(path: str, method: RequestMethod, params: List[APIParameter]) -> None:
            key = f"{method.value}:{path}"
            if key in seen:
                return
            seen.add(key)
            endpoints.append(APIEndpoint(
                path=path, method=method,
                summary=f"Discovered: {method.value} {path}",
                description="Auto-discovered via active crawling",
                tags=["discovered"],
                parameters=params,
            ))

        for url in urls:
            parsed = urlparse(url)
            path   = parsed.path or "/"
            params: List[APIParameter] = []
            if parsed.query:
                for name in parse_qs(parsed.query):
                    params.append(APIParameter(name=name, location="query", type="string"))

            lpath = path.lower()
            methods = [RequestMethod.GET]
            if any(k in lpath for k in ("/create", "/add", "/new", "/register",
                                         "/login", "/upload", "/submit")):
                methods = [RequestMethod.GET, RequestMethod.POST]
            elif any(k in lpath for k in ("/update", "/edit")):
                methods = [RequestMethod.PUT, RequestMethod.PATCH]
            elif any(k in lpath for k in ("/delete", "/remove")):
                methods = [RequestMethod.DELETE]

            for m in methods:
                add(path, m, list(params))

        if forms:
            for form in forms:
                parsed = urlparse(form.action)
                if not self._is_same_domain(form.action):
                    continue
                path   = parsed.path or "/"
                method = RequestMethod.POST if form.method == "POST" else RequestMethod.GET
                loc    = "body" if method == RequestMethod.POST else "query"
                params = [
                    APIParameter(name=i.name, location=loc, type="string")
                    for i in form.injectable_inputs
                ]
                add(path, method, params)

        return endpoints

    def _enrich_from_forms(
        self,
        endpoints: List[APIEndpoint],
        forms: List[FormSpec],
    ) -> None:
        ep_map = {f"{ep.method.value}:{ep.path}": ep for ep in endpoints}
        for form in forms:
            path   = urlparse(form.action).path or "/"
            method = "POST" if form.method == "POST" else "GET"
            ep     = ep_map.get(f"{method}:{path}")
            if not ep:
                continue
            existing = {p.name for p in ep.parameters}
            for inp in form.injectable_inputs:
                if inp.name not in existing:
                    loc = "body" if method == "POST" else "query"
                    ep.parameters.append(APIParameter(name=inp.name, location=loc, type="string"))

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _build_ssl_ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    def _get_json(self, url: str) -> Tuple[Optional[dict], int]:
        raw, status = self._get_raw(url)
        if raw:
            try:
                return json.loads(raw), status
            except Exception:
                return None, status
        return None, status

    def _get_raw(self, url: str) -> Tuple[Optional[str], int]:
        headers = {
            "User-Agent": "entropy-chaos/0.4.4 (security-scanner)",
            "Accept":     "text/html,application/json,*/*",
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
        print(msg)
