""""Auth handling — static tokens, OAuth flows, credential pools."""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Credential:
    username:  str = ""
    password:  str = ""
    api_key:   str = ""
    token:     str = ""
    role:      str = "user"     # user | admin | moderator | …
    extra:     Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthConfig:
    """Configuration for one authentication scheme."""

    # --- Login endpoint (username/password) ---
    login_url:        Optional[str] = None
    login_method:     str = "POST"
    login_body_tpl:   Optional[Dict[str, str]] = None   # {"email": "{username}", "password": "{password}"}
    token_field:      str = "token"   # JSON path in login response, e.g. "access_token" or "data.token"

    # --- API key ---
    api_key_header:   str = "X-API-Key"

    # --- Bearer token ---
    bearer_header:    str = "Authorization"
    bearer_prefix:    str = "Bearer"

    # --- Cookie ---
    cookie_name:      Optional[str] = None

    # --- OAuth2 client credentials ---
    oauth2_token_url: Optional[str] = None
    oauth2_client_id: Optional[str] = None
    oauth2_client_secret: Optional[str] = None
    oauth2_scope:     str = ""

    # --- Refresh ---
    refresh_url:      Optional[str] = None
    refresh_field:    str = "refresh_token"

    # --- Timing ---
    token_ttl_seconds: int = 3600
    auto_refresh:      bool = True


class AuthManager:
    """
    Manages credentials and injects the correct auth headers into requests.

    Usage:
        auth = AuthManager(config, credential)
        auth.login()
        headers = auth.inject_headers({})
    """

    def __init__(self, config: AuthConfig, credential: Credential):
        self.config     = config
        self.credential = credential
        self._token:          Optional[str] = None
        self._refresh_token:  Optional[str] = None
        self._token_obtained: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def login(self) -> bool:
        """
        Perform the login flow and store the resulting token.
        Returns True if login succeeded.
        """
        cfg = self.config
        cred = self.credential

        # 1. Static token already provided
        if cred.token:
            self._token = cred.token
            return True

        # 2. OAuth2 client credentials
        if cfg.oauth2_token_url:
            return self._oauth2_client_credentials()

        # 3. Username/password login
        if cfg.login_url and (cred.username or cred.password):
            return self._password_login()

        # 4. API key — no login step needed, injected in headers
        if cred.api_key:
            return True

        return False

    def inject_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Return a new headers dict with auth credentials injected."""
        result = dict(headers)
        cfg    = self.config
        cred   = self.credential

        # Auto-refresh if token is about to expire
        if self._token and cfg.auto_refresh and self._should_refresh():
            self._refresh()

        if self._token:
            result[cfg.bearer_header] = f"{cfg.bearer_prefix} {self._token}"
        elif cred.api_key:
            result[cfg.api_key_header] = cred.api_key
        elif cred.token:
            result[cfg.bearer_header] = f"{cfg.bearer_prefix} {cred.token}"

        return result

    def inject_cookies(self) -> Dict[str, str]:
        """Return cookies dict if cookie-based auth is used."""
        if self.config.cookie_name and self._token:
            return {self.config.cookie_name: self._token}
        return {}

    @property
    def is_authenticated(self) -> bool:
        return bool(self._token or self.credential.api_key or self.credential.token)

    # ------------------------------------------------------------------
    # Internal flows
    # ------------------------------------------------------------------

    def _password_login(self) -> bool:
        cfg  = self.config
        cred = self.credential
        tpl  = cfg.login_body_tpl or {"username": "{username}", "password": "{password}"}
        body = {
            k: v.format(username=cred.username, password=cred.password)
            for k, v in tpl.items()
        }
        body.update(cred.extra)
        try:
            resp_data = self._http_post(cfg.login_url, body)
            token = self._extract_field(resp_data, cfg.token_field)
            if token:
                self._token          = token
                self._token_obtained = time.monotonic()
                self._refresh_token  = self._extract_field(resp_data, cfg.refresh_field)
                return True
        except Exception as exc:
            print(f"  [auth] Login failed: {exc}")
        return False

    def _oauth2_client_credentials(self) -> bool:
        cfg = self.config
        data = urllib.parse.urlencode({
            "grant_type":    "client_credentials",
            "client_id":     cfg.oauth2_client_id or "",
            "client_secret": cfg.oauth2_client_secret or "",
            "scope":         cfg.oauth2_scope,
        }).encode()
        req = urllib.request.Request(
            cfg.oauth2_token_url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read())
            self._token          = result.get("access_token", "")
            self._token_obtained = time.monotonic()
            return bool(self._token)
        except Exception as exc:
            print(f"  [auth] OAuth2 failed: {exc}")
            return False

    def _refresh(self) -> bool:
        cfg = self.config
        if not (cfg.refresh_url and self._refresh_token):
            return False
        try:
            resp_data = self._http_post(cfg.refresh_url, {cfg.refresh_field: self._refresh_token})
            token = self._extract_field(resp_data, cfg.token_field)
            if token:
                self._token          = token
                self._token_obtained = time.monotonic()
                return True
        except Exception:
            pass
        return False

    def _should_refresh(self) -> bool:
        elapsed = time.monotonic() - self._token_obtained
        return elapsed > (self.config.token_ttl_seconds * 0.8)

    @staticmethod
    def _http_post(url: str, body: Dict[str, Any]) -> Dict[str, Any]:
        data = json.dumps(body).encode()
        req  = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())

    @staticmethod
    def _extract_field(data: Any, field_path: str) -> Optional[str]:
        """Extract a value from a nested dict using dot-notation path."""
        if not isinstance(data, dict):
            return None
        parts = field_path.split(".")
        node  = data
        for part in parts:
            if not isinstance(node, dict):
                return None
            node = node.get(part)
        return str(node) if node else None


# ---------------------------------------------------------------------------
# Credential Pool  — multi-user testing
# ---------------------------------------------------------------------------

class CredentialPool:
    """
    Manages a pool of credentials for testing with multiple identities.
    Useful for IDOR testing (switching between user A and user B).
    """

    def __init__(self, credentials: List[Credential], config: AuthConfig):
        self.credentials = credentials
        self.config      = config
        self._managers:  List[AuthManager] = [AuthManager(config, c) for c in credentials]
        self._index:     int = 0

    def login_all(self) -> int:
        """Login all credentials. Returns count of successful logins."""
        return sum(1 for m in self._managers if m.login())

    def next(self) -> AuthManager:
        """Round-robin credential cycling."""
        manager      = self._managers[self._index % len(self._managers)]
        self._index += 1
        return manager

    def get_by_role(self, role: str) -> Optional[AuthManager]:
        for m, c in zip(self._managers, self.credentials):
            if c.role == role:
                return m
        return None

    @property
    def user_count(self) -> int:
        return len(self.credentials)

    @classmethod
    def from_list(cls, pairs: List[Dict[str, str]], config: AuthConfig) -> "CredentialPool":
        """
        Convenience constructor from a list of dicts.

        pairs: [{"username": "alice", "password": "s3cr3t", "role": "user"}, ...]
        """
        creds = [
            Credential(
                username=p.get("username",""),
                password=p.get("password",""),
                api_key=p.get("api_key",""),
                token=p.get("token",""),
                role=p.get("role","user"),
            )
            for p in pairs
        ]
        return cls(creds, config)
