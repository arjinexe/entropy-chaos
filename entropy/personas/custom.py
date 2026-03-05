"""Custom attack persona loader — define attacker profiles in YAML."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml as _yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

VALID_ATTACK_FOCUS = {
    "privilege_escalation", "data_exfiltration", "idor", "injection",
    "race_condition", "auth_bypass", "mass_assignment", "business_logic",
    "ssrf", "xxe", "deserialization", "rate_limit_bypass",
}

VALID_AUTH_LEVELS = {"anonymous", "read", "read_write", "admin"}


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

@dataclass
class CustomPersonaSpec:
    name:                str
    description:         str                      = ""
    auth_level:          str                      = "read_write"
    attack_focus:        List[str]                = field(default_factory=list)
    endpoints_whitelist: List[str]                = field(default_factory=list)  # empty = all
    endpoints_blacklist: List[str]                = field(default_factory=list)
    payload_overrides:   Dict[str, Any]           = field(default_factory=dict)
    headers:             Dict[str, str]           = field(default_factory=dict)
    concurrency:         int                      = 5
    max_steps:           int                      = 8
    delay_ms:            int                      = 0
    notes:               str                      = ""

    # ---------------------------------------------------------------------------

    @classmethod
    def from_yaml(cls, path: str) -> "CustomPersonaSpec":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Persona file not found: {path}")

        if HAS_YAML:
            with open(p) as f:
                data = _yaml.safe_load(f)
        else:
            # Fallback: minimal YAML parser for simple flat structures
            data = _parse_simple_yaml(p.read_text())

        return cls._from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict) -> "CustomPersonaSpec":
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: Dict) -> "CustomPersonaSpec":
        if not data.get("name"):
            raise ValueError("Custom persona YAML must have a 'name' field")

        auth_level = data.get("auth_level", "read_write")
        if auth_level not in VALID_AUTH_LEVELS:
            raise ValueError(f"auth_level must be one of: {VALID_AUTH_LEVELS}")

        focus = data.get("attack_focus", [])
        invalid = [f for f in focus if f not in VALID_ATTACK_FOCUS]
        if invalid:
            import warnings
            warnings.warn(f"Unknown attack_focus values: {invalid} — they will be ignored")
            focus = [f for f in focus if f in VALID_ATTACK_FOCUS]

        return cls(
            name                = data["name"],
            description         = data.get("description", ""),
            auth_level          = auth_level,
            attack_focus        = focus,
            endpoints_whitelist = data.get("endpoints_whitelist", []),
            endpoints_blacklist = data.get("endpoints_blacklist", []),
            payload_overrides   = data.get("payload_overrides", {}),
            headers             = data.get("headers", {}),
            concurrency         = int(data.get("concurrency", 5)),
            max_steps           = int(data.get("max_steps", 8)),
            delay_ms            = int(data.get("delay_ms", 0)),
            notes               = data.get("notes", ""),
        )

    def to_yaml(self) -> str:
        """Serialize to YAML string."""
        if HAS_YAML:
            return _yaml.dump(self.__dict__, default_flow_style=False, allow_unicode=True)
        return json.dumps(self.__dict__, indent=2)

    def endpoint_allowed(self, path: str) -> bool:
        if self.endpoints_blacklist and any(path.startswith(b) for b in self.endpoints_blacklist):
            return False
        if self.endpoints_whitelist:
            return any(path.startswith(w) for w in self.endpoints_whitelist)
        return True


# ---------------------------------------------------------------------------
# Simple YAML parser (fallback if pyyaml not installed)
# ---------------------------------------------------------------------------

def _parse_simple_yaml(text: str) -> Dict:
    """Parse simple single-level YAML without pyyaml dependency."""
    result: Dict = {}
    current_list: Optional[List] = None
    current_key:  Optional[str]  = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue

        # List item
        stripped = line.lstrip()
        if stripped.startswith("- "):
            val = stripped[2:].strip().strip('"').strip("'")
            if current_list is not None:
                current_list.append(val)
            continue

        # Key: value
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip().strip('"').strip("'")

            current_list = None
            current_key  = key

            if not val:
                # Might be a list parent — peek handled on next iterations
                result[key] = []
                current_list = result[key]
            else:
                # Type coercion
                if val.lower() == "true":
                    result[key] = True
                elif val.lower() == "false":
                    result[key] = False
                elif val.isdigit():
                    result[key] = int(val)
                else:
                    result[key] = val

    return result


# ---------------------------------------------------------------------------
# Template
# ---------------------------------------------------------------------------

PERSONA_YAML_TEMPLATE = """\
# Entropy Custom Persona Template
# Documentation: https://github.com/yourusername/entropy-chaos#custom-personas

name: "My Custom Persona"
description: "Authenticated internal user attempting to escalate privileges"

# Auth level: anonymous | read | read_write | admin
auth_level: read_write

# Which attack classes this persona focuses on
# Options: privilege_escalation, data_exfiltration, idor, injection,
#          race_condition, auth_bypass, mass_assignment, business_logic,
#          ssrf, xxe, deserialization, rate_limit_bypass
attack_focus:
  - privilege_escalation
  - idor
  - mass_assignment

# Limit testing to specific path prefixes (empty = all endpoints)
endpoints_whitelist:
  - /api/v1/users
  - /api/v1/reports

# Skip these paths entirely
endpoints_blacklist:
  - /api/v1/health
  - /api/v1/metrics

# Force these fields into every request body
payload_overrides:
  is_admin: true
  role: "admin"

# Extra headers for every request
headers:
  X-Department: finance
  X-Employee-ID: "12345"

# Execution settings
concurrency: 5
max_steps: 8
delay_ms: 0   # ms between requests (0 = no delay)

notes: "Simulates a finance team member who knows the API structure"
"""
