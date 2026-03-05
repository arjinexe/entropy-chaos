"""CI/CD helpers — GitHub/GitLab annotations, JUnit output, exit codes."""
from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from entropy.core.models import EntropyReport, Finding, Severity


# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------

def detect_ci_environment() -> str:
    """Return the name of the detected CI environment, or 'local'."""
    if os.getenv("GITHUB_ACTIONS"):
        return "github_actions"
    if os.getenv("GITLAB_CI"):
        return "gitlab_ci"
    if os.getenv("CIRCLECI"):
        return "circleci"
    if os.getenv("JENKINS_URL"):
        return "jenkins"
    if os.getenv("CI"):
        return "generic_ci"
    return "local"


# ---------------------------------------------------------------------------
# GitHub Actions
# ---------------------------------------------------------------------------

class GitHubActionsIntegration:
    """
    Emits GitHub Actions workflow commands for annotations and summary.
    https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
    """

    @staticmethod
    def annotate(report: EntropyReport) -> None:
        """Print workflow commands to annotate the Actions run."""
        for finding in report.findings:
            level = "error" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"
            # ::error:: or ::warning:: command
            msg = (
                f"{finding.title} — "
                f"{finding.description[:120]} "
                f"[{finding.type.value}]"
            )
            print(f"::{level} title=Entropy: {finding.severity.value.upper()}::{msg}")

    @staticmethod
    def write_summary(report: EntropyReport, summary_file: Optional[str] = None) -> None:
        """
        Write a Markdown summary to $GITHUB_STEP_SUMMARY.
        Falls back to stdout if the env var is not set.
        """
        from entropy.reporting.reporter import MarkdownReporter
        md = MarkdownReporter().render(report)

        target = summary_file or os.getenv("GITHUB_STEP_SUMMARY")
        if target:
            Path(target).write_text(md, encoding="utf-8")
        else:
            print(md)

    @staticmethod
    def set_outputs(report: EntropyReport) -> None:
        """Write key metrics as GitHub Actions outputs."""
        outputs_file = os.getenv("GITHUB_OUTPUT")
        lines = [
            f"total_findings={len(report.findings)}",
            f"critical={sum(1 for f in report.findings if f.severity == Severity.CRITICAL)}",
            f"high={sum(1 for f in report.findings if f.severity == Severity.HIGH)}",
            f"status={report.status.value}",
        ]
        if outputs_file:
            with open(outputs_file, "a") as fh:
                fh.write("\n".join(lines) + "\n")
        else:
            for line in lines:
                print(f"  [output] {line}")


# ---------------------------------------------------------------------------
# GitLab CI — JUnit XML
# ---------------------------------------------------------------------------

class GitLabCIIntegration:
    """
    Produces a JUnit-compatible XML report for GitLab CI test reports.
    https://docs.gitlab.com/ee/ci/testing/unit_test_reports.html
    """

    @staticmethod
    def to_junit_xml(report: EntropyReport) -> str:
        """Return a JUnit XML string from the report."""
        root = ET.Element("testsuites")
        suite = ET.SubElement(root, "testsuite",
                              name="Entropy Chaos Engineering",
                              tests=str(len(report.findings)),
                              failures=str(len(report.findings)),
                              time=str(
                                  (report.finished_at - report.started_at).total_seconds()
                                  if report.finished_at else 0
                              ))

        for finding in report.findings:
            tc = ET.SubElement(suite, "testcase",
                               classname=finding.type.value,
                               name=finding.title,
                               time="0")
            failure = ET.SubElement(tc, "failure",
                                    message=finding.description,
                                    type=finding.severity.value)
            failure.text = (
                f"Endpoint: {finding.endpoint}\n"
                f"Severity: {finding.severity.value}\n"
                f"Description: {finding.description}\n"
                f"Remediation: {finding.remediation}\n"
            )

        return ET.tostring(root, encoding="unicode", xml_declaration=False)

    @staticmethod
    def save_junit(report: EntropyReport, path: str = "entropy-junit.xml") -> Path:
        p = Path(path)
        p.write_text(GitLabCIIntegration.to_junit_xml(report), encoding="utf-8")
        return p


# ---------------------------------------------------------------------------
# Generic PR comment formatter
# ---------------------------------------------------------------------------

def format_pr_comment(report: EntropyReport) -> str:
    """
    Format a concise Markdown comment suitable for posting on a GitHub PR
    or GitLab Merge Request.
    """
    summary = report.summary()
    crit = summary.get("critical", 0)
    high = summary.get("high", 0)
    med  = summary.get("medium", 0)
    low  = summary.get("low", 0)

    status_emoji = "✅" if not report.findings else ("🚨" if (crit + high) > 0 else "⚠️")

    lines = [
        f"## {status_emoji} Entropy Security Report",
        "",
        f"> **Target:** `{report.target}`",
        "",
        "| 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low |",
        "|-------------|---------|-----------|--------|",
        f"| {crit} | {high} | {med} | {low} |",
        "",
    ]

    if report.findings:
        lines.append("### Top Findings")
        lines.append("")
        for f in sorted(report.findings, key=lambda x: _SEV_SORT[x.severity])[:5]:
            lines.append(f"- **{f.severity.value.upper()}** — {f.title} (`{f.endpoint}`)")
        lines.append("")
        lines.append("_See the full report artifact for reproduction steps._")
    else:
        lines.append("_No security findings detected. Great work! 🎉_")

    return "\n".join(lines)


_SEV_SORT = {
    Severity.CRITICAL: 0,
    Severity.HIGH:     1,
    Severity.MEDIUM:   2,
    Severity.LOW:      3,
    Severity.INFO:     4,
}


# ---------------------------------------------------------------------------
# GitHub Actions workflow template (YAML)
# ---------------------------------------------------------------------------

GITHUB_ACTIONS_WORKFLOW = """\
# .github/workflows/entropy.yml
# Entropy: AI-Powered Chaos Engineering in CI/CD
name: Entropy Security Test

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  entropy:
    runs-on: ubuntu-latest
    name: Chaos Engineering & Logical Fuzzing

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Entropy
        run: pip install entropy-chaos  # or: pip install -e .

      - name: Start target application
        run: docker-compose up -d
        # Or: ./scripts/start-dev-server.sh

      - name: Run Entropy
        run: |
          entropy run \\
            --spec openapi.yaml \\
            --target http://localhost:8000 \\
            --llm mock \\
            --output entropy-report \\
            --fail-on high
        env:
          ENTROPY_LLM_BACKEND: mock  # or: openai, ollama

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: entropy-report
          path: entropy-report/

      - name: Write PR summary
        if: always()
        run: entropy report summary --input entropy-report/report.json
"""

GITLAB_CI_TEMPLATE = """\
# Add this job to your .gitlab-ci.yml
entropy-chaos-test:
  stage: test
  image: python:3.11-slim
  services:
    - docker:dind
  before_script:
    - pip install entropy-chaos
  script:
    - entropy run
        --spec openapi.yaml
        --target http://localhost:8000
        --llm mock
        --output entropy-report
        --fail-on high
        --junit entropy-junit.xml
  artifacts:
    when: always
    reports:
      junit: entropy-junit.xml
    paths:
      - entropy-report/
    expire_in: 30 days
"""
