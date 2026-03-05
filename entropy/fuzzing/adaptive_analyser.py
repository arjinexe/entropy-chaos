"""Adaptive LLM response analyser — reduces false positives by reasoning about findings."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from entropy.core.models import Finding, FindingType, Severity
from entropy.llm.backends import BaseLLM


# ---------------------------------------------------------------------------
# Verdict model
# ---------------------------------------------------------------------------

@dataclass
class AnalysisVerdict:
    finding_id:    str
    confirmed:     bool        # LLM thinks this is a real finding
    confidence:    float       # 0.0 – 1.0
    reasoning:     str
    adjusted_severity: Optional[Severity] = None
    suggested_title:   Optional[str]      = None


# ---------------------------------------------------------------------------
# Analyser
# ---------------------------------------------------------------------------

class AdaptiveResponseAnalyser:
    """
    Uses an LLM to review each (request, response, rule_name) triple and
    decide whether the finding is genuine or a false positive.

    Only runs on findings from the current scan — does not re-test the target.
    Adds a `llm_verdict` key to finding.evidence with the analysis result.

    Works best with a real LLM backend; falls back gracefully with mock.
    """

    # Prompt template
    _SYSTEM = (
        "You are a senior application security engineer reviewing automated API fuzzing results. "
        "Your job is to determine whether a potential finding is a genuine security vulnerability "
        "or a false positive. Be conservative — only confirm findings with clear evidence. "
        "Think about the HTTP context: status codes, response body content, request parameters."
    )

    _PROMPT_TMPL = """
Review this potential security finding from an automated API fuzzer:

## Finding
- Type: {type}
- Rule: {title}
- Endpoint: {endpoint}
- Severity: {severity}

## Request
- Method: {method}
- URL: {url}
- Body: {body}
- Headers: {headers}

## Response
- Status Code: {status_code}
- Body (first 500 chars): {response_body}
- Latency: {latency_ms}ms

## Initial Evidence
{evidence}

## Task
Analyse whether this is a genuine {type} vulnerability.

Consider:
1. Does the response body actually contain the expected indicators?
2. Could this be a false positive (e.g., the server always returns this status)?
3. Is the severity appropriate given the actual evidence?
4. What would an attacker actually be able to do with this?

Return JSON only:
{{
  "confirmed": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "2-3 sentence explanation",
  "adjusted_severity": "critical|high|medium|low|info" or null,
  "suggested_title": "improved title" or null
}}
"""

    def __init__(self, llm: BaseLLM, min_confidence: float = 0.6):
        self.llm             = llm
        self.min_confidence  = min_confidence
        self._cache: Dict[str, AnalysisVerdict] = {}

    # ------------------------------------------------------------------

    def filter_false_positives(
        self,
        findings: List[Finding],
        max_to_analyse: int = 30,
    ) -> Tuple[List[Finding], List[Finding]]:
        """
        Returns (confirmed_findings, rejected_findings).
        Findings without step data are passed through unchanged.
        """
        confirmed:  List[Finding] = []
        rejected:   List[Finding] = []

        # Prioritise critical/high for analysis budget
        sorted_findings = sorted(
            findings,
            key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity.value, 4)
        )

        analysed = 0
        for f in sorted_findings:
            if not f.steps or analysed >= max_to_analyse:
                # No step data or budget exhausted — pass through
                confirmed.append(f)
                continue

            verdict = self._analyse_finding(f)
            analysed += 1

            # Attach verdict to evidence
            f.evidence["llm_verdict"] = {
                "confirmed":  verdict.confirmed,
                "confidence": verdict.confidence,
                "reasoning":  verdict.reasoning,
            }

            if verdict.confirmed and verdict.confidence >= self.min_confidence:
                # Optionally adjust severity
                if verdict.adjusted_severity:
                    f.severity = verdict.adjusted_severity
                if verdict.suggested_title:
                    f.title = verdict.suggested_title
                confirmed.append(f)
            else:
                rejected.append(f)

        return confirmed, rejected

    def enrich_remediations(self, findings: List[Finding]) -> None:
        """Add LLM-generated remediation text to findings that lack it."""
        seen_types: set = set()
        for f in findings:
            if f.remediation or f.type in seen_types:
                continue
            seen_types.add(f.type)
            try:
                data = self.llm.complete_json(
                    f"Provide a concise, actionable remediation (2-4 sentences) for:\n"
                    f"  Type: {f.type.value}\n"
                    f"  Title: {f.title}\n"
                    f"  Description: {f.description}\n"
                    'Return JSON: {"remediation": "..."}'
                )
                f.remediation = data.get("remediation", "")
            except Exception:
                pass

    # ------------------------------------------------------------------

    def _analyse_finding(self, f: Finding) -> AnalysisVerdict:
        cache_key = f"{f.type.value}:{f.title}:{f.endpoint}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        step = f.steps[0] if f.steps else None
        req  = step.request  if step else None
        resp = step.response if step else None

        prompt = self._PROMPT_TMPL.format(
            type          = f.type.value,
            title         = f.title,
            endpoint      = f.endpoint,
            severity      = f.severity.value,
            method        = req.method  if req  else "unknown",
            url           = req.url     if req  else "unknown",
            body          = json.dumps(req.body)[:300] if req and req.body else "{}",
            headers       = json.dumps(dict(list((req.headers or {}).items())[:5]))[:200] if req else "{}",
            status_code   = resp.status_code  if resp else "unknown",
            response_body = str(resp.body or "")[:500] if resp else "{}",
            latency_ms    = f"{resp.latency_ms:.0f}" if resp else "?",
            evidence      = json.dumps(f.evidence, default=str)[:400],
        )

        try:
            data = self.llm.complete_json(prompt, system=self._SYSTEM)
            sev  = None
            if data.get("adjusted_severity"):
                try:
                    sev = Severity(data["adjusted_severity"])
                except ValueError:
                    pass
            verdict = AnalysisVerdict(
                finding_id         = f.id,
                confirmed          = bool(data.get("confirmed", True)),
                confidence         = float(data.get("confidence", 0.7)),
                reasoning          = str(data.get("reasoning", "")),
                adjusted_severity  = sev,
                suggested_title    = data.get("suggested_title"),
            )
        except Exception as exc:
            # On LLM error, default to confirmed to avoid dropping real findings
            verdict = AnalysisVerdict(
                finding_id = f.id,
                confirmed  = True,
                confidence = 0.5,
                reasoning  = f"LLM analysis unavailable: {exc}",
            )

        self._cache[cache_key] = verdict
        return verdict
