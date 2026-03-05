"""Markdown and JSON report generation."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from entropy.core.models import EntropyReport, Finding, Severity
from entropy.llm.backends import BaseLLM


# ---------------------------------------------------------------------------
# Severity emoji / colour helpers
# ---------------------------------------------------------------------------

_SEV_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🟢",
    Severity.INFO:     "🔵",
}

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


# ---------------------------------------------------------------------------
# Markdown Reporter
# ---------------------------------------------------------------------------

class MarkdownReporter:
    """
    Renders a full pentest-style Markdown report from an EntropyReport.
    """

    def __init__(self, llm: Optional[BaseLLM] = None):
        self.llm = llm

    # ------------------------------------------------------------------

    def render(self, report: EntropyReport) -> str:
        lines = []

        # Header
        lines += self._header(report)

        # Executive summary (LLM-generated if available)
        lines += self._executive_summary(report)

        # Statistics
        lines += self._statistics(report)

        # Findings grouped by severity
        lines += self._findings_section(report)

        # Appendix: reproduction guide
        lines += self._appendix(report)

        return "\n".join(lines)

    def save(self, report: EntropyReport, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(report), encoding="utf-8")
        return path

    # ------------------------------------------------------------------

    def _header(self, report: EntropyReport) -> list:
        duration = ""
        if report.finished_at:
            secs = (report.finished_at - report.started_at).total_seconds()
            duration = f"**Duration:** {secs:.1f}s"
        return [
            "# 🌪️ Entropy Chaos Engineering Report",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Target** | `{report.target}` |",
            f"| **Report ID** | `{report.id}` |",
            f"| **Generated** | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} |",
            f"| **Status** | {report.status.value.upper()} |",
            f"| **Total Findings** | {len(report.findings)} |",
            duration,
            "",
            "---",
            "",
        ]

    def _executive_summary(self, report: EntropyReport) -> list:
        summary_text = ""
        if self.llm and report.findings:
            try:
                finding_titles = ", ".join(f.title for f in report.findings[:10])
                prompt = (
                    f"Write a concise executive summary (3-4 sentences) for a security report.\n"
                    f"Target: {report.target}\n"
                    f"Findings: {finding_titles}\n"
                    f"Total issues: {len(report.findings)}\n"
                    "Return JSON: {\"executive_summary\": \"...\"}"
                )
                data = self.llm.complete_json(prompt)
                summary_text = data.get("executive_summary", "")
            except Exception:
                pass

        if not summary_text:
            critical = sum(1 for f in report.findings if f.severity == Severity.CRITICAL)
            high     = sum(1 for f in report.findings if f.severity == Severity.HIGH)
            if not report.findings:
                summary_text = (
                    "Entropy completed chaos testing with **no findings**. "
                    "The target API demonstrated strong resilience against all tested attack scenarios."
                )
            else:
                summary_text = (
                    f"Entropy identified **{len(report.findings)} security findings** "
                    f"({critical} critical, {high} high) against `{report.target}`. "
                    "Immediate attention is required for all critical and high-severity findings. "
                    "Full reproduction steps are provided for each finding below."
                )

        return [
            "## 📋 Executive Summary",
            "",
            summary_text,
            "",
            "---",
            "",
        ]

    def _statistics(self, report: EntropyReport) -> list:
        summary = report.summary()
        rows = [
            "## 📊 Finding Statistics",
            "",
            "| Severity | Count | Risk |",
            "|----------|-------|------|",
        ]
        for sev in _SEV_ORDER:
            count = summary.get(sev.value, 0)
            emoji = _SEV_EMOJI[sev]
            rows.append(f"| {emoji} {sev.value.capitalize()} | {count} | {'●' * min(count, 10)} |")

        stats = report.stats
        if stats:
            rows += [
                "",
                "### Test Execution Stats",
                "",
                f"- **Requests sent:** {stats.get('requests_sent', 'N/A')}",
                f"- **Personas used:** {stats.get('personas_used', 'N/A')}",
                f"- **Endpoints tested:** {stats.get('endpoints_tested', 'N/A')}",
                f"- **Attack vectors executed:** {stats.get('vectors_executed', 'N/A')}",
            ]

        rows += ["", "---", ""]
        return rows

    def _findings_section(self, report: EntropyReport) -> list:
        if not report.findings:
            return ["## 🔍 Findings", "", "_No findings detected._", "", "---", ""]

        lines = ["## 🔍 Findings", ""]

        # Group by severity
        by_severity: dict = {sev: [] for sev in _SEV_ORDER}
        for f in report.findings:
            by_severity[f.severity].append(f)

        for sev in _SEV_ORDER:
            findings = by_severity[sev]
            if not findings:
                continue
            emoji = _SEV_EMOJI[sev]
            lines.append(f"### {emoji} {sev.value.capitalize()} ({len(findings)})")
            lines.append("")
            for finding in findings:
                lines += self._render_finding(finding)

        lines += ["---", ""]
        return lines

    def _render_finding(self, finding: Finding) -> list:
        lines = [
            f"#### [{finding.type.value.replace('_', ' ').title()}] {finding.title}",
            "",
            f"**Finding ID:** `{finding.id}`  ",
            f"**Endpoint:** `{finding.endpoint}`  ",
            f"**Persona:** `{finding.persona or 'N/A'}`  ",
            f"**Discovered:** {finding.discovered_at.strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            f"**Description:** {finding.description}",
            "",
        ]

        if finding.remediation:
            lines += [
                "**Remediation:**",
                f"> {finding.remediation}",
                "",
            ]

        if finding.steps:
            lines += ["**Reproduction Steps:**", ""]
            for step in finding.steps:
                lines.append(f"{step.step_number}. {step.description}")
                if step.request:
                    req = step.request
                    body_str = json.dumps(req.body, indent=6) if req.body else "None"
                    lines += [
                        "   ```http",
                        f"   {req.method} {req.url}",
                        *(f"   {k}: {v}" for k, v in (req.headers or {}).items()),
                        "",
                        f"   {body_str}",
                        "   ```",
                    ]
                if step.response:
                    resp = step.response
                    body_str = json.dumps(resp.body, indent=6) if resp.body else str(resp.body)
                    lines += [
                        f"   **Response:** `{resp.status_code}` ({resp.latency_ms:.0f}ms)",
                        "   ```json",
                        f"   {body_str[:500]}",
                        "   ```",
                    ]
                lines.append("")

        if finding.evidence:
            lines += [
                "<details>",
                "<summary>Raw Evidence</summary>",
                "",
                "```json",
                json.dumps(finding.evidence, indent=2, default=str)[:1000],
                "```",
                "",
                "</details>",
                "",
            ]

        lines += ["---", ""]
        return lines

    def _appendix(self, report: EntropyReport) -> list:
        lines = [
            "## 📎 Appendix",
            "",
            "### How to use this report",
            "",
            "1. **Triage** all Critical and High findings immediately.",
            "2. Use the **Reproduction Steps** to confirm each finding in your environment.",
            "3. Apply the **Remediation** guidance before the next deployment.",
            "4. Re-run Entropy after fixes to confirm resolution.",
            "",
            "### About Entropy",
            "",
            "This report was generated by **Entropy** — an AI-powered autonomous chaos engineering",
            "and logical fuzzing framework. Entropy uses LLM-driven synthetic personas to discover",
            "business logic flaws that traditional scanners miss.",
            "",
            f"_Report generated: {datetime.utcnow().isoformat()}Z_",
        ]
        return lines


# ---------------------------------------------------------------------------
# JSON Reporter
# ---------------------------------------------------------------------------

class JSONReporter:
    """Serialises EntropyReport to machine-readable JSON."""

    def render(self, report: EntropyReport) -> str:
        data = {
            "id":          report.id,
            "target":      report.target,
            "status":      report.status.value,
            "started_at":  report.started_at.isoformat(),
            "finished_at": report.finished_at.isoformat() if report.finished_at else None,
            "summary":     report.summary(),
            "stats":       report.stats,
            "findings":    [f.to_dict() for f in report.findings],
        }
        return json.dumps(data, indent=2, default=str)

    def save(self, report: EntropyReport, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(report), encoding="utf-8")
        return path


# ---------------------------------------------------------------------------
# CI/CD exit-code helper
# ---------------------------------------------------------------------------

def get_exit_code(report: EntropyReport, fail_on: str = "high") -> int:
    """
    Return 0 (pass) or 1 (fail) based on finding severity.
    fail_on: "critical" | "high" | "medium" | "low" | "any"
    """
    thresholds = {
        "critical": [Severity.CRITICAL],
        "high":     [Severity.CRITICAL, Severity.HIGH],
        "medium":   [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
        "low":      [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW],
        "any":      list(Severity),
    }
    fail_severities = thresholds.get(fail_on, thresholds["high"])
    for finding in report.findings:
        if finding.severity in fail_severities:
            return 1
    return 0
