"""SARIF v2.1 reporter for GitHub Code Scanning and other SAST integrations."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from entropy.core.models import EntropyReport, Finding, Severity


# SARIF level mapping
_LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "none",
}

_OWASP_TAGS = {
    "injection":           ["A03:2021"],
    "auth_bypass":         ["A07:2021"],
    "data_leak":           ["A02:2021"],
    "business_logic":      ["A04:2021"],
    "race_condition":      ["A04:2021"],
    "crash":               ["A06:2021"],
    "performance":         ["A04:2021"],
    "idor":                ["A01:2021"],
    "ssrf":                ["A10:2021"],
    "xxe":                 ["A05:2021"],
    "ssti":                ["A03:2021"],
    "smuggling":           ["A04:2021"],
    "parameter_pollution": ["A04:2021"],
    "deserialization":     ["A08:2021"],
    "csrf":                ["A01:2021"],
}

class SARIFReporter:

    TOOL_NAME    = "entropy-chaos"
    from entropy import __version__ as _pkg_version
    TOOL_VERSION = _pkg_version
    TOOL_URI     = "https://github.com/yourusername/entropy-chaos"

    def save(self, report: EntropyReport, path: Path) -> Path:
        sarif = self._build(report)
        path.write_text(json.dumps(sarif, indent=2))
        return path

    def _build(self, report: EntropyReport) -> Dict[str, Any]:
        rules   = self._build_rules(report.findings)
        results = [self._finding_to_result(f, i) for i, f in enumerate(report.findings)]

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name":            self.TOOL_NAME,
                            "version":         self.TOOL_VERSION,
                            "informationUri":  self.TOOL_URI,
                            "rules":           rules,
                        }
                    },
                    "results":          results,
                    "invocations": [
                        {
                            "executionSuccessful": report.status.value == "completed",
                            "startTimeUtc":        report.started_at.isoformat() + "Z",
                            "endTimeUtc":          (
                                report.finished_at.isoformat() + "Z"
                                if report.finished_at else None
                            ),
                        }
                    ],
                    "properties": {
                        "target": report.target,
                        "stats":  report.stats,
                    },
                }
            ],
        }

    def _build_rules(self, findings: List[Finding]) -> List[Dict]:
        seen: set = set()
        rules: List[Dict] = []
        for f in findings:
            rule_id = f"ENTROPY-{f.type.value.upper().replace('_', '-')}"
            if rule_id in seen:
                continue
            seen.add(rule_id)
            tags = _OWASP_TAGS.get(f.type.value, [])
            rules.append({
                "id": rule_id,
                "name": f.type.value.replace("_", " ").title(),
                "shortDescription": {"text": f.title},
                "fullDescription":  {"text": f.description},
                "defaultConfiguration": {
                    "level": _LEVEL_MAP.get(f.severity, "warning")
                },
                "properties": {
                    "tags": ["security", "api"] + tags,
                    "precision": "medium",
                    "problem.severity": f.severity.value,
                },
                "helpUri": f"{self.TOOL_URI}#readme",
            })
        return rules

    def _finding_to_result(self, f: Finding, index: int) -> Dict:
        rule_id = f"ENTROPY-{f.type.value.upper().replace('_', '-')}"
        return {
            "ruleId":  rule_id,
            "level":   _LEVEL_MAP.get(f.severity, "warning"),
            "message": {
                "text": f"{f.title}\n\n{f.description}"
                        + (f"\n\nRemediation: {f.remediation}" if f.remediation else "")
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri":       f.endpoint.split()[-1] if f.endpoint else "/",
                            "uriBaseId": "%SRCROOT%",
                        }
                    },
                    "logicalLocations": [
                        {
                            "name":         f.endpoint,
                            "kind":         "function",
                            "fullyQualifiedName": f.endpoint,
                        }
                    ],
                }
            ],
            "fingerprints": {
                "entropy/v1": f"{f.type.value}|{f.title}|{f.endpoint}",
            },
            "properties": {
                "severity":     f.severity.value,
                "finding_type": f.type.value,
                "persona":      f.persona,
                "cvss":         f.evidence.get("cvss_score"),
                "evidence":     f.evidence,
            },
        }
