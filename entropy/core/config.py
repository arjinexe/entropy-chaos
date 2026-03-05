"""Config loading for entropy — entropy.yml, .env, ENTROPY_* env vars."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml as _yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from entropy.core.models import PersonaType


# ---------------------------------------------------------------------------
# Scan profiles
# ---------------------------------------------------------------------------

@dataclass
class ScanProfile:
    name:        str
    description: str
    personas:    List[PersonaType]
    concurrency: int
    delay_ms:    int
    fail_on:     str    # critical | high | medium | low | any | none
    max_steps:   int
    llm_enrichment: bool


PROFILES: Dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description="Fast scan — critical findings only, 2 personas",
        personas=[PersonaType.PENETRATION_TESTER, PersonaType.CONFUSED_USER],
        concurrency=5,
        delay_ms=50,
        fail_on="critical",
        max_steps=5,
        llm_enrichment=False,
    ),
    "standard": ScanProfile(
        name="standard",
        description="Balanced scan — critical+high, 3 personas",
        personas=[PersonaType.MALICIOUS_INSIDER, PersonaType.PENETRATION_TESTER, PersonaType.BOT_SWARM],
        concurrency=10,
        delay_ms=100,
        fail_on="high",
        max_steps=8,
        llm_enrichment=True,
    ),
    "full": ScanProfile(
        name="full",
        description="Thorough scan — all severities, all personas",
        personas=list(PersonaType),
        concurrency=20,
        delay_ms=30,
        fail_on="high",
        max_steps=15,
        llm_enrichment=True,
    ),
    "stealth": ScanProfile(
        name="stealth",
        description="Low-noise scan — minimal footprint, slow requests",
        personas=[PersonaType.MALICIOUS_INSIDER, PersonaType.CONFUSED_USER],
        concurrency=1,
        delay_ms=2000,
        fail_on="high",
        max_steps=5,
        llm_enrichment=True,
    ),
    "ci": ScanProfile(
        name="ci",
        description="CI-optimised — fast, no live HTTP, mock LLM",
        personas=[PersonaType.PENETRATION_TESTER, PersonaType.CONFUSED_USER],
        concurrency=5,
        delay_ms=0,
        fail_on="high",
        max_steps=6,
        llm_enrichment=False,
    ),
}


# ---------------------------------------------------------------------------
# .env loader (no python-dotenv dependency)
# ---------------------------------------------------------------------------

def load_dotenv(path: str | Path = ".env") -> None:
    """Parse a .env file and set environment variables (if not already set)."""
    env_path = Path(path)
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key   = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


# ---------------------------------------------------------------------------
# YAML Config loader
# ---------------------------------------------------------------------------

_PERSONA_ALIAS = {p.value: p for p in PersonaType}


def load_config_file(path: str | Path | None = None) -> Dict[str, Any]:
    """
    Load entropy.yml from the given path or auto-discover in cwd.
    Returns a raw dict (empty dict if no file found).
    """
    if not HAS_YAML:
        return {}
    search = [path] if path else ["entropy.yml", "entropy.yaml", ".entropy.yml"]
    for candidate in search:
        p = Path(candidate)
        if p.exists():
            return _yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return {}


def build_config_from_yaml(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Convert entropy.yml dict into EntropyConfig kwargs. Env vars win over YAML."""
    cfg: Dict[str, Any] = {}

    # ── 1. Profile expansion (lowest priority base) ───────────────────────
    profile_name = raw.get("profile", "standard")
    if profile_name in PROFILES:
        prof = PROFILES[profile_name]
        cfg["scan_profile"]    = profile_name
        cfg["personas"]        = [p for p in prof.personas if p != PersonaType.CUSTOM]
        cfg["concurrency"]     = prof.concurrency
        cfg["fail_on"]         = prof.fail_on
        cfg["max_steps"]       = prof.max_steps
        cfg["enrich_with_llm"] = prof.llm_enrichment

    # ── 2. Target — accept "target" or "target_url" ───────────────────────
    target = raw.get("target") or raw.get("target_url")
    if target:
        cfg["target_url"] = str(target)

    spec = raw.get("spec") or raw.get("spec_file")
    if spec:
        cfg["spec_file"] = str(spec)

    # ── 3. LLM ────────────────────────────────────────────────────────────
    llm = raw.get("llm", {})
    if isinstance(llm, str):
        cfg["llm_backend"] = llm
    elif isinstance(llm, dict):
        _sif(cfg, "llm_backend",  llm.get("backend"))
        _sif(cfg, "llm_model",    llm.get("model"))
        _sif(cfg, "llm_base_url", llm.get("base_url"))
        _sif(cfg, "llm_api_key",  llm.get("api_key") or llm.get("api-key"))

    # ── 4. Scan block ─────────────────────────────────────────────────────
    scan = raw.get("scan", {})
    if isinstance(scan, dict):
        # live: true  →  dry_run: false
        if "live" in scan:
            cfg["dry_run"] = not bool(scan["live"])
        _bool_field(cfg, "dry_run",               scan, "dry_run", "dry-run")
        _bool_field(cfg, "auto_discover",          scan, "discover", "auto_discover")
        _bool_field(cfg, "baseline_diff",          scan, "baseline_diff", "baseline-diff")
        _bool_field(cfg, "rate_limit_check",       scan, "rate_limit_check", "rate-limit-check")
        _bool_field(cfg, "save_history",           scan, "save_history", "save-history")
        _bool_field(cfg, "enrich_with_llm",        scan, "llm_enrichment", "enrich_with_llm")
        _bool_field(cfg, "cvss_scoring",           scan, "cvss_scoring", "cvss-scoring")
        _bool_field(cfg, "verbose",                scan, "verbose")
        _int_field(cfg,  "concurrency",            scan, "concurrency")
        _int_field(cfg,  "max_steps",              scan, "max_steps", "max-steps")
        _int_field(cfg,  "rate_limit_max_probes",  scan, "rate_limit_probes", "rate-limit-probes")
        _float_field(cfg, "timeout",               scan, "timeout")
        _sif(cfg, "fail_on",          scan.get("fail_on")      or scan.get("fail-on"))
        _sif(cfg, "diff_target",      scan.get("diff_target")  or scan.get("diff-target"))
        _sif(cfg, "diff_auth_header", scan.get("diff_auth_header") or scan.get("diff-auth-header"))
        _sif(cfg, "history_db",       scan.get("history_db")   or scan.get("history-db"))
        _sif(cfg, "custom_persona",   scan.get("custom_persona") or scan.get("custom-persona"))

    # ── 5. HTTP options ───────────────────────────────────────────────────
    http = raw.get("http", {})
    if isinstance(http, dict):
        _bool_field(cfg, "verify_ssl",   http, "verify_ssl", "verify-ssl")
        _int_field(cfg,  "max_retries",  http, "max_retries", "max-retries", "retries")
        _float_field(cfg, "timeout",     http, "timeout")
        _float_field(cfg, "backoff_base",http, "backoff_base", "backoff-base")
        _sif(cfg, "proxy_url", http.get("proxy") or http.get("proxy_url"))

    # ── 6. Personas ───────────────────────────────────────────────────────
    personas_raw = raw.get("personas")
    if isinstance(personas_raw, list):
        resolved = [_PERSONA_ALIAS[p] for p in personas_raw
                    if isinstance(p, str) and p in _PERSONA_ALIAS]
        if resolved:
            cfg["personas"] = resolved
    elif isinstance(personas_raw, dict):
        p_list = personas_raw.get("list", [])
        resolved = [_PERSONA_ALIAS[p] for p in p_list if p in _PERSONA_ALIAS]
        if resolved:
            cfg["personas"] = resolved
        _sif(cfg, "custom_persona", personas_raw.get("custom_persona"))

    # ── 7. Output ─────────────────────────────────────────────────────────
    output = raw.get("output", {})
    if isinstance(output, str):
        cfg["output_dir"] = output
    elif isinstance(output, dict):
        _sif(cfg, "output_dir",   output.get("dir") or output.get("output_dir"))
        _sif(cfg, "sarif_output", output.get("sarif"))
        _sif(cfg, "junit_output", output.get("junit"))
        _sif(cfg, "fail_on",      output.get("fail_on") or output.get("fail-on"))
        _bool_field(cfg, "html_report", output, "html")

    # backward-compat top-level output_dir
    if "output_dir" in raw and "output_dir" not in cfg:
        cfg["output_dir"] = raw["output_dir"]

    # ── 8. Dashboard ──────────────────────────────────────────────────────
    dashboard = raw.get("dashboard", {})
    if isinstance(dashboard, bool):
        cfg["dashboard"] = dashboard
    elif isinstance(dashboard, dict):
        _bool_field(cfg, "dashboard",      dashboard, "enabled")
        _int_field(cfg,  "dashboard_port", dashboard, "port")

    # ── 9. Watch mode ─────────────────────────────────────────────────────
    watch = raw.get("watch", {})
    if isinstance(watch, bool):
        cfg["watch"] = watch
    elif isinstance(watch, dict):
        _bool_field(cfg, "watch",          watch, "enabled")
        _int_field(cfg,  "watch_interval", watch, "interval", "watch_interval")
        files = watch.get("files") or watch.get("watch_files")
        if isinstance(files, list):
            cfg["watch_files"] = [str(f) for f in files]

    # ── 10. Alerts / webhooks ─────────────────────────────────────────────
    alerts = raw.get("alerts", {})
    if isinstance(alerts, dict):
        _sif(cfg, "webhook_url",   alerts.get("webhook") or alerts.get("webhook_url"))
        _sif(cfg, "slack_webhook", alerts.get("slack_webhook") or alerts.get("slack"))

    # ── 11. WebSocket ─────────────────────────────────────────────────────
    ws = raw.get("websocket", {})
    if isinstance(ws, str):
        cfg["websocket_url"] = ws
    elif isinstance(ws, dict):
        _sif(cfg, "websocket_url", ws.get("url"))

    # ── 12. GitHub / GitLab ───────────────────────────────────────────────
    github = raw.get("github", {})
    if isinstance(github, dict):
        _sif(cfg, "github_repo", github.get("repo"))

    gitlab = raw.get("gitlab", {})
    if isinstance(gitlab, dict):
        _sif(cfg, "gitlab_project", gitlab.get("project"))

    # ── 13. Backward-compat top-level direct fields ───────────────────────
    for key in ("dry_run", "verbose", "concurrency", "timeout", "fail_on"):
        if key in raw and key not in cfg:
            cfg[key] = raw[key]

    # ── 14. Environment variables — highest priority ───────────────────────
    _apply_env_overrides(cfg)

    return cfg


# ---------------------------------------------------------------------------
# Field helpers
# ---------------------------------------------------------------------------

def _sif(cfg: Dict, key: str, value: Any) -> None:
    """Set cfg[key] only when value is not None / empty string."""
    if value is not None and value != "":
        cfg[key] = value


def _bool_field(cfg: Dict, key: str, section: Dict, *names: str) -> None:
    for name in names:
        if name in section:
            cfg[key] = bool(section[name])
            return


def _int_field(cfg: Dict, key: str, section: Dict, *names: str) -> None:
    for name in names:
        if name in section:
            try:
                cfg[key] = int(section[name])
                return
            except (TypeError, ValueError):
                pass


def _float_field(cfg: Dict, key: str, section: Dict, *names: str) -> None:
    for name in names:
        if name in section:
            try:
                cfg[key] = float(section[name])
                return
            except (TypeError, ValueError):
                pass


def _apply_env_overrides(cfg: Dict[str, Any]) -> None:
    """Apply ENTROPY_* env vars plus LLM provider API key auto-detection."""
    bool_keys = {"dry_run", "verbose", "verify_ssl",
                 "baseline_diff", "rate_limit_check", "save_history"}

    mapping = {
        "ENTROPY_TARGET":       "target_url",
        "ENTROPY_SPEC":         "spec_file",
        "ENTROPY_LLM":          "llm_backend",
        "ENTROPY_LLM_MODEL":    "llm_model",
        "ENTROPY_LLM_API_KEY":  "llm_api_key",
        "ENTROPY_LLM_URL":      "llm_base_url",
        "ENTROPY_OUTPUT":       "output_dir",
        "ENTROPY_FAIL_ON":      "fail_on",
        "ENTROPY_DRY_RUN":      "dry_run",
        "ENTROPY_VERBOSE":      "verbose",
        "ENTROPY_PROFILE":      "scan_profile",
        "ENTROPY_PROXY":        "proxy_url",
        "ENTROPY_HISTORY_DB":   "history_db",
        "ENTROPY_SARIF":        "sarif_output",
        "ENTROPY_WEBHOOK":      "webhook_url",
        "ENTROPY_SLACK":        "slack_webhook",
        "ENTROPY_DIFF_TARGET":  "diff_target",
    }
    for env_key, cfg_key in mapping.items():
        val = os.getenv(env_key)
        if val is not None:
            cfg[cfg_key] = (val.lower() in ("1", "true", "yes")) if cfg_key in bool_keys else val

    # Auto-detect LLM provider API key from standard env var names
    backend = cfg.get("llm_backend", "mock")
    if not cfg.get("llm_api_key"):
        provider_env = {
            "anthropic":   "ANTHROPIC_API_KEY",
            "openai":      "OPENAI_API_KEY",
            "gemini":      "GEMINI_API_KEY",
            "mistral":     "MISTRAL_API_KEY",
            "groq":        "GROQ_API_KEY",
            "cohere":      "COHERE_API_KEY",
            "huggingface": "HF_API_KEY",
            "together":    "TOGETHER_API_KEY",
        }
        env_var = provider_env.get(backend)
        if env_var:
            val = os.getenv(env_var)
            if val:
                cfg["llm_api_key"] = val


# ---------------------------------------------------------------------------
# Example entropy.yml template
# ---------------------------------------------------------------------------

ENTROPY_YML_TEMPLATE = """\
# entropy.yml
# Copy to project root, then: entropy run
# Full docs: https://github.com/yourusername/entropy-chaos

# ── Profile ─────────────────────────────────────────────────────────────────
# Presets: quick | standard | full | stealth | ci
profile: standard

# ── Target ──────────────────────────────────────────────────────────────────
target: http://localhost:8000
spec: openapi.yaml                # OpenAPI 3.x, Swagger 2.x, or .graphql SDL

# ── LLM ─────────────────────────────────────────────────────────────────────
llm:
  backend: mock                   # mock|anthropic|openai|gemini|mistral|groq|ollama|huggingface
  model: ""                       # empty = backend default
  # api_key: ""                   # use env var: ANTHROPIC_API_KEY / OPENAI_API_KEY / etc.
  # base_url: ""                  # custom endpoint (LM Studio, vLLM, Ollama)

# ── Scan behaviour ───────────────────────────────────────────────────────────
scan:
  live: false                     # true = real HTTP requests; false = simulation
  discover: false                 # crawl target to find endpoints (no spec needed)
  concurrency: 10
  timeout: 10
  baseline_diff: true             # filter false positives via control-request diff
  rate_limit_check: true          # detect missing/bypassable rate limits
  save_history: true              # persist run to ~/.entropy/history.db
  # diff_target: https://staging.api.com   # compare --target vs this URL
  # custom_persona: ./my_persona.yaml

# ── HTTP options ─────────────────────────────────────────────────────────────
http:
  verify_ssl: true                # false = accept self-signed TLS certs
  max_retries: 3
  # proxy: http://127.0.0.1:8080  # route through Burp Suite / squid

# ── Personas ─────────────────────────────────────────────────────────────────
personas:
  - malicious_insider
  - impatient_consumer
  - bot_swarm
  - confused_user
  - penetration_tester

# ── Output ───────────────────────────────────────────────────────────────────
output:
  dir: entropy-report
  html: true
  fail_on: high                   # critical | high | medium | low | any | none
  # sarif: results.sarif          # GitHub Code Scanning
  # junit: entropy-report/junit.xml

# ── Dashboard (optional) ─────────────────────────────────────────────────────
# dashboard:
#   enabled: false
#   port: 8080

# ── Watch mode (optional) ────────────────────────────────────────────────────
# watch:
#   enabled: false
#   interval: 300                 # seconds between automatic re-runs
#   files:
#     - openapi.yaml              # also re-run when this file changes

# ── Alerts (optional) ────────────────────────────────────────────────────────
# alerts:
#   slack_webhook: https://hooks.slack.com/services/...
#   webhook: https://myserver.example.com/entropy-hook

# ── WebSocket fuzzing (optional) ─────────────────────────────────────────────
# websocket:
#   url: ws://localhost:8080/ws

# ── GitHub issue integration (optional) ──────────────────────────────────────
# github:
#   repo: owner/repo
#   open_issues: false

# Env overrides (highest priority): ENTROPY_TARGET, ENTROPY_LLM, ENTROPY_FAIL_ON, etc.
"""
