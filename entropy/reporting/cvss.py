""""CVSS v3.1 scoring for entropy findings."""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.parse
from dataclasses import dataclass
from typing import Dict, Optional

from entropy.core.models import Finding, FindingType, Severity


# ---------------------------------------------------------------------------
# CVSS v3.1 Metrics
# ---------------------------------------------------------------------------

@dataclass
class CVSSMetrics:
    # Base metrics
    attack_vector:        str = "N"   # N=Network A=Adjacent L=Local P=Physical
    attack_complexity:    str = "L"   # L=Low H=High
    privileges_required:  str = "N"   # N=None L=Low H=High
    user_interaction:     str = "N"   # N=None R=Required
    scope:                str = "U"   # U=Unchanged C=Changed
    confidentiality:      str = "H"   # N=None L=Low H=High
    integrity:            str = "H"
    availability:         str = "H"

    def vector_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}"
            f"/PR:{self.privileges_required}/UI:{self.user_interaction}"
            f"/S:{self.scope}/C:{self.confidentiality}"
            f"/I:{self.integrity}/A:{self.availability}"
        )

    def base_score(self) -> float:
        """Simplified CVSS v3.1 base score calculation."""
        AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[self.attack_vector]
        AC  = {"L": 0.77, "H": 0.44}[self.attack_complexity]
        PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}[self.privileges_required]
        PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}[self.privileges_required]
        UI  = {"N": 0.85, "R": 0.62}[self.user_interaction]
        S   = self.scope
        C   = {"N": 0.00, "L": 0.22, "H": 0.56}[self.confidentiality]
        I   = {"N": 0.00, "L": 0.22, "H": 0.56}[self.integrity]
        A   = {"N": 0.00, "L": 0.22, "H": 0.56}[self.availability]

        PR = PR_C if S == "C" else PR_U
        ISS = 1 - (1 - C) * (1 - I) * (1 - A)
        if ISS == 0:
            return 0.0
        if S == "U":
            Impact = 6.42 * ISS
        else:
            Impact = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02) ** 15

        Exploitability = 8.22 * AV * AC * PR * UI
        if Impact <= 0:
            return 0.0
        if S == "U":
            raw = min(Impact + Exploitability, 10)
        else:
            raw = min(1.08 * (Impact + Exploitability), 10)

        # Round up to one decimal
        return round(raw * 10) / 10


# ---------------------------------------------------------------------------
# Auto-scorer: maps FindingType → CVSSMetrics template
# ---------------------------------------------------------------------------

_CVSS_TEMPLATES: Dict[FindingType, CVSSMetrics] = {
    FindingType.AUTH_BYPASS:    CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="N", user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="H"),
    FindingType.INJECTION:      CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="N", user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="H"),
    FindingType.RACE_CONDITION: CVSSMetrics(attack_vector="N", attack_complexity="H", privileges_required="L", user_interaction="N", scope="U", confidentiality="L", integrity="H", availability="L"),
    FindingType.IDOR:           CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="L", user_interaction="N", scope="U", confidentiality="H", integrity="N", availability="N"),  # noqa
    FindingType.DATA_LEAK:      CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="L", user_interaction="N", scope="U", confidentiality="H", integrity="N", availability="N"),
    FindingType.LOGIC_ERROR:    CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="L", user_interaction="N", scope="U", confidentiality="L", integrity="H", availability="L"),
    FindingType.BUSINESS_LOGIC: CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="L", user_interaction="N", scope="U", confidentiality="L", integrity="H", availability="L"),
    FindingType.CRASH:          CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="N", user_interaction="N", scope="U", confidentiality="N", integrity="N", availability="H"),
    FindingType.PERFORMANCE:    CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="N", user_interaction="N", scope="U", confidentiality="N", integrity="N", availability="L"),
}

_DEFAULT_CVSS = CVSSMetrics()


def score_finding(finding: Finding) -> tuple[float, str]:
    """
    Return (cvss_score, vector_string) for a finding.
    Uses the finding type template as a baseline.
    """
    metrics = _CVSS_TEMPLATES.get(finding.type, _DEFAULT_CVSS)
    score   = metrics.base_score()
    vector  = metrics.vector_string()
    return score, vector


def severity_from_cvss(score: float) -> Severity:
    """Convert CVSS base score to Severity enum."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def enrich_finding_with_cvss(finding: Finding) -> Finding:
    """Add CVSS score to finding evidence. Mutates in place, returns for chaining."""
    score, vector = score_finding(finding)
    finding.evidence["cvss_score"]  = score
    finding.evidence["cvss_vector"] = vector
    return finding


# ---------------------------------------------------------------------------
# Issue auto-opener: GitHub / GitLab
# ---------------------------------------------------------------------------

class GitHubIssueOpener:
    """
    Automatically opens GitHub Issues for critical/high findings.

    Requires: GITHUB_TOKEN env var or explicit token.
    """

    def __init__(self, repo: str, token: Optional[str] = None):
        """repo: "owner/repo" """
        self.repo  = repo
        self.token = token or os.getenv("GITHUB_TOKEN", "")
        self.base  = "https://api.github.com"

    def open_issue(self, finding: Finding, labels: list[str] | None = None) -> Optional[str]:
        """Open a GitHub issue for the given finding. Returns issue URL or None."""
        if not self.token:
            return None
        score, vector = score_finding(finding)
        title = f"[Entropy] {finding.severity.value.upper()}: {finding.title}"
        body  = self._format_body(finding, score, vector)
        default_labels = ["security", f"severity:{finding.severity.value}", "entropy"]
        payload = {
            "title":  title,
            "body":   body,
            "labels": (labels or default_labels),
        }
        try:
            data = json.dumps(payload).encode()
            req  = urllib.request.Request(
                f"{self.base}/repos/{self.repo}/issues",
                data=data,
                headers={
                    "Content-Type":  "application/json",
                    "Authorization": f"Bearer {self.token}",
                    "Accept":        "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read())
            return result.get("html_url")
        except Exception as exc:
            print(f"  [github] Failed to open issue: {exc}")
            return None

    @staticmethod
    def _format_body(finding: Finding, score: float, vector: str) -> str:
        steps = "\n".join(
            f"{s.step_number}. {s.description}" for s in finding.steps
        )
        return f"""## 🌪️ Entropy Security Finding

**Type:** {finding.type.value.replace('_', ' ').title()}  
**Severity:** {finding.severity.value.upper()}  
**CVSS Score:** {score} `{vector}`  
**Endpoint:** `{finding.endpoint}`  
**Persona:** {finding.persona or 'N/A'}  

### Description
{finding.description}

### Reproduction Steps
{steps or '_See full report_'}

### Remediation
{finding.remediation or '_See full report_'}

---
*Auto-generated by [Entropy](https://github.com/entropyproject/entropy)*
"""


class GitLabIssueOpener:
    """
    Automatically opens GitLab Issues for critical/high findings.

    Requires: GITLAB_TOKEN env var and project ID.
    """

    def __init__(self, project_id: str, token: Optional[str] = None, base_url: str = "https://gitlab.com"):
        self.project_id = urllib.parse.quote(project_id, safe="")
        self.token      = token or os.getenv("GITLAB_TOKEN", "")
        self.base       = base_url.rstrip("/")

    def open_issue(self, finding: Finding) -> Optional[str]:
        if not self.token:
            return None
        score, vector = score_finding(finding)
        payload = {
            "title":       f"[Entropy] {finding.severity.value.upper()}: {finding.title}",
            "description": GitHubIssueOpener._format_body(finding, score, vector),
            "labels":      f"security,severity:{finding.severity.value},entropy",
        }
        try:
            data = json.dumps(payload).encode()
            req  = urllib.request.Request(
                f"{self.base}/api/v4/projects/{self.project_id}/issues",
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "PRIVATE-TOKEN": self.token,
                },
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read())
            return result.get("web_url")
        except Exception as exc:
            print(f"  [gitlab] Failed to open issue: {exc}")
            return None
