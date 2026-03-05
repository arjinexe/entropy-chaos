"""Core orchestrator — schema parsing, LLM attack generation, execution, and reporting."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from entropy.core.models import (
    APISchema, AttackVector, EntropyReport,
    Finding, PersonaType, Severity, TestStatus,
)
from entropy.core.parser import OpenAPIParser
from entropy.core.attack_tree import AttackTreeGenerator
from entropy.core.config import PROFILES, ScanProfile, load_dotenv, load_config_file, build_config_from_yaml
from entropy.fuzzing.executor import HTTPExecutor, EnhancedHTTPExecutor
from entropy.fuzzing.logical import LogicalFuzzer
from entropy.llm.backends import BaseLLM, create_llm
from entropy.personas.engine import (
    BasePersona, PersonaConfig, all_persona_configs, create_persona,
)
from entropy.reporting.reporter import JSONReporter, MarkdownReporter, get_exit_code
from entropy.reporting.html_reporter import HTMLReporter
from entropy.reporting.cvss import enrich_finding_with_cvss


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------

@dataclass
class EntropyConfig:
    # Target
    target_url:  str  = "http://localhost:8000"
    spec_file:   Optional[str] = None
    spec_dict:   Optional[Dict] = None

    # LLM
    llm_backend:  str = "mock"
    llm_model:    str = ""
    llm_api_key:  str = ""
    llm_base_url: str = ""

    # Execution
    dry_run:      bool  = True
    concurrency:  int   = 10
    timeout:      float = 5.0
    max_steps:    int   = 8

    # Personas
    personas: List[PersonaType] = field(default_factory=lambda: [
        p for p in PersonaType if p != PersonaType.CUSTOM
    ])

    # Output
    output_dir:   str  = "entropy-report"
    fail_on:      str  = "high"
    junit_output: Optional[str] = None

    # Behaviour
    verbose:         bool = False
    enrich_with_llm: bool = True
    html_report:     bool = True
    cvss_scoring:    bool = True
    scan_profile:    str  = "standard"

    # GitHub/GitLab issue integration
    github_repo:  Optional[str] = None
    gitlab_project: Optional[str] = None
    open_issues:  bool = False  # Discovery
    auto_discover:    bool = False  # Baseline diff
    baseline_diff:    bool = True  # History / regression
    history_db:       Optional[str] = None
    save_history:     bool = True
    diff_last_run:    bool = True  # Dashboard
    dashboard:        bool = False
    dashboard_port:   int  = 8080  # Watch mode
    watch:            bool = False
    watch_interval:   int  = 300
    watch_files:      List[str] = field(default_factory=list)  # Webhooks
    webhook_url:      Optional[str] = None
    slack_webhook:    Optional[str] = None  # HTTP options
    proxy_url:        Optional[str] = None
    verify_ssl:       bool = True
    max_retries:      int  = 3
    backoff_base:     float = 0.5
    session_cookies:  bool = True  # SARIF
    sarif_output:     Optional[str] = None  # WebSocket
    websocket_url:    Optional[str] = None  # Proxy intercept
    proxy_mode:       bool = False
    proxy_port:       int  = 8888  # Multi-target
    extra_targets:    List[str] = field(default_factory=list)  # Custom persona
    custom_persona:   Optional[str] = None  # Rate limit detection
    rate_limit_check: bool = True
    rate_limit_max_probes: int = 20  # Differential testing (reduced from 50 for speed)
    diff_target:      Optional[str] = None
    diff_auth_header: Optional[str] = None
    # v0.4.0 advanced scanning
    ssrf_check:       bool = True
    ssti_check:       bool = True
    xxe_check:        bool = True
    jwt_check:        bool = True
    smuggling_check:  bool = False   # off by default — timing-based, needs live
    param_mining:     bool = True
    idor_chain:       bool = True
    adaptive_analysis: bool = True   # LLM false-positive filtering
    max_adaptive_budget: int = 20    # max findings to send to LLM for review
    max_scan_minutes:  int   = 45    # hard wall-clock timeout for the full scan (0 = unlimited)

    @classmethod
    def from_yaml(cls, yaml_path: str | None = None) -> "EntropyConfig":
        """Build config from entropy.yml + env vars."""
        load_dotenv()
        raw = load_config_file(yaml_path)
        kwargs = build_config_from_yaml(raw)
        return cls(**{k: v for k, v in kwargs.items() if hasattr(cls, k)})

    @classmethod
    def from_profile(cls, profile: str, **overrides) -> "EntropyConfig":
        """Apply a scan profile then override with explicit kwargs."""
        prof = PROFILES.get(profile, PROFILES["standard"])
        base = cls(
            personas=prof.personas,
            concurrency=prof.concurrency,
            fail_on=prof.fail_on,
            max_steps=prof.max_steps,
            enrich_with_llm=prof.llm_enrichment,
        )
        for k, v in overrides.items():
            if hasattr(base, k):
                setattr(base, k, v)
        return base


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class EntropyRunner:

    def __init__(self, config: EntropyConfig):
        self.config   = config
        self.llm      = self._build_llm()
        self.executor = EnhancedHTTPExecutor(
            dry_run      = config.dry_run,
            timeout      = config.timeout,
            verify_ssl   = config.verify_ssl,
            proxy_url    = config.proxy_url,
            max_retries  = config.max_retries,
            backoff_base = config.backoff_base,
        )
        self.fuzzer   = LogicalFuzzer(self.llm, use_llm=config.enrich_with_llm)
        self._dashboard = None

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def run(self) -> EntropyReport:
        cfg    = self.config
        report = EntropyReport(target=cfg.target_url, status=TestStatus.RUNNING)
        _scan_start = time.time()

        def _scan_timed_out() -> bool:
            if cfg.max_scan_minutes <= 0:
                return False
            return (time.time() - _scan_start) > cfg.max_scan_minutes * 60

        self._print_banner()

        try:
            # 1. Parse schema
            schema = self._parse_schema()
            schema.base_url = cfg.target_url
            self._log(f"✓ Schema: {schema.title} v{schema.version} ({len(schema.endpoints)} endpoints)")

            # 2. Attack tree
            self._log("⚙  Generating attack tree…")
            tree    = AttackTreeGenerator(self.llm).generate(schema)
            vectors = tree.all_vectors()
            self._log(f"✓ Attack tree: {len(vectors)} vectors across {len(tree.root.children)} surfaces")

            self._assign_endpoints(vectors, schema)

            # 3. Personas
            persona_configs = self._build_persona_configs()
            self._log(f"✓ Personas: {[pc.type.value for pc in persona_configs]}")

            # 4. Execute
            self._log("🚀 Chaos simulation starting…\n")
            stats = {
                "requests_sent":     0,
                "personas_used":     len(persona_configs),
                "endpoints_tested":  len(schema.endpoints),
                "vectors_executed":  0,
            }
            all_findings: List[Finding] = []

            for pc in persona_configs:
                if _scan_timed_out():
                    self._log(f"⏱  Scan time limit ({cfg.max_scan_minutes} min) reached — stopping early.")
                    break
                persona = create_persona(pc.type, pc, self.llm, schema)
                self._log(f"  👤 {persona.name}")

                for vi, vector in enumerate(vectors):
                    if _scan_timed_out():
                        self._log(f"  ⏱  Time limit reached mid-persona — stopping.")
                        break
                    if not vector.endpoint:
                        continue
                    vector.persona_type = pc.type

                    # Extra fuzzer payloads
                    for extra in self.fuzzer.generate_payloads(vector.endpoint, max_per_param=2)[:3]:
                        vector.payload.setdefault("extra", []).append(extra)

                    requests = persona.build_request_sequence(vector)
                    if not requests:
                        continue

                    stats["vectors_executed"] += 1

                    if pc.concurrency > 1 and len(requests) > 1:
                        try:
                            loop = asyncio.get_event_loop()
                            if loop.is_running():
                                import concurrent.futures
                                with concurrent.futures.ThreadPoolExecutor() as pool:
                                    futures = [pool.submit(self.executor.execute, req, {}) for req in requests[:pc.concurrency]]
                                    results = [f.result() for f in futures]
                            else:
                                results = loop.run_until_complete(
                                    self.executor.execute_concurrent(requests[:pc.concurrency], {})
                                )
                        except RuntimeError:
                            results = asyncio.run(
                                self.executor.execute_concurrent(requests[:pc.concurrency], {})
                            )
                    else:
                        results = [self.executor.execute(req, {}) for req in requests]

                    stats["requests_sent"] += len(results)

                    for resp, findings in results:
                        for f in findings:
                            f.persona  = persona.name
                            f.endpoint = f"{vector.endpoint.method.value} {vector.endpoint.path}"
                            all_findings.append(f)

                    if cfg.verbose:
                        for req, (resp, _) in zip(requests, results):
                            icon = "✓" if resp.status_code < 400 else "✗"
                            self._log(f"    {icon} {req.method} {req.url[:55]} → {resp.status_code} ({resp.latency_ms:.0f}ms)")  # Rate limit detection
            if cfg.rate_limit_check and schema.endpoints:
                self._log("\n🚦 Rate limit detection…")
                from entropy.fuzzing.ratelimit import RateLimitDetector, MockRateLimitDetector
                from entropy.core.models import Finding, FindingType, Severity
                # Test a sample of endpoints (max 5 to keep it fast)
                sample = schema.endpoints[:5]
                for ep in sample:
                    url = f"{cfg.target_url}{ep.path}"
                    try:
                        DetectorClass = MockRateLimitDetector if cfg.dry_run else RateLimitDetector
                        detector = DetectorClass(url, timeout=cfg.timeout, verify_ssl=cfg.verify_ssl, proxy_url=cfg.proxy_url, max_probes=cfg.rate_limit_max_probes)
                        rl_result = detector.probe()
                        if rl_result.severity in ("critical", "high"):
                            desc = rl_result.summary
                            if not rl_result.has_rate_limit:
                                desc = f"No rate limit on {ep.method.value} {ep.path} — server accepted {len(rl_result.probes)} requests without throttling"
                            elif rl_result.bypass_vectors:
                                desc = f"Rate limit bypassable on {ep.method.value} {ep.path} — vectors: {rl_result.bypass_vectors}"
                            all_findings.append(Finding(
                                type=FindingType.PERFORMANCE,
                                severity=Severity(rl_result.severity),
                                title="Rate Limit Issue: " + ("No limit detected" if not rl_result.has_rate_limit else "Bypass possible"),
                                description=desc,
                                endpoint=f"{ep.method.value} {ep.path}",
                                evidence={
                                    "limit_at": rl_result.limit_at,
                                    "bypass_vectors": rl_result.bypass_vectors,
                                    "limit_window": rl_result.limit_window,
                                },
                            ))
                            self._log(f"  🚦 [{rl_result.severity.upper()}] {ep.method.value} {ep.path}: {rl_result.summary}")
                        else:
                            self._log(f"  ✓ {ep.method.value} {ep.path}: rate limit at #{rl_result.limit_at}")
                    except Exception as exc:
                        if cfg.verbose:
                            self._log(f"  ⚠ Rate limit probe failed: {exc}")  # Differential testing
            if cfg.diff_target:
                self._log(f"\n🔀 Differential testing: {cfg.target_url} vs {cfg.diff_target}")
                from entropy.fuzzing.differential import DifferentialTester
                from entropy.core.models import Finding, FindingType, Severity
                auth_headers = {}
                if cfg.diff_auth_header:
                    k, _, v = cfg.diff_auth_header.partition(":")
                    auth_headers[k.strip()] = v.strip()
                differ = DifferentialTester(
                    target_a=cfg.target_url, target_b=cfg.diff_target,
                    timeout=cfg.timeout, verify_ssl=cfg.verify_ssl,
                    auth_headers=auth_headers,
                )
                diff_report = differ.run(schema)
                self._log(f"  {diff_report.summary()}")
                for div in diff_report.divergences:
                    all_findings.append(Finding(
                        type=FindingType.LOGIC_ERROR,
                        severity=Severity(div.severity),
                        title=f"Differential: {div.kind}",
                        description=div.description,
                        endpoint=div.endpoint,
                        evidence={
                            "kind": div.kind,
                            "target_a": cfg.target_url,
                            "target_b": cfg.diff_target,
                            "status_a": div.snap_a.status_code if div.snap_a else None,
                            "status_b": div.snap_b.status_code if div.snap_b else None,
                        },
                    ))

            # 5. Deduplicate + CVSS + remediation
            report.findings = self._deduplicate(all_findings)

            # 5b. v0.4.0: Advanced per-endpoint testing
            self._run_advanced_tests(report.findings, schema, cfg)

            # Re-deduplicate after advanced tests
            report.findings = self._deduplicate(report.findings)

            if cfg.cvss_scoring:
                for f in report.findings:
                    enrich_finding_with_cvss(f)

            # 5c. Adaptive LLM false-positive filtering
            if cfg.adaptive_analysis and cfg.enrich_with_llm:
                confirmed, rejected = self._run_adaptive_analysis(report.findings)
                if rejected:
                    self._log(f"  🧠 Adaptive analysis: {len(confirmed)} confirmed, {len(rejected)} rejected as false positives")
                report.findings = confirmed
                report.stats["false_positives_filtered"] = len(rejected)

            if cfg.enrich_with_llm:
                self._enrich_remediations(report.findings)

            report.stats      = stats
            report.status     = TestStatus.COMPLETED
            report.finished_at = datetime.utcnow()

            self._print_summary(report)

            # 6. Save reports
            self._save_reports(report)

            # 7. Open issues
            if cfg.open_issues:
                self._open_issues(report)  # History + diff
            if cfg.save_history:
                try:
                    from entropy.history import FindingHistory
                    from pathlib import Path as _Path
                    db_path = _Path(cfg.history_db) if cfg.history_db else None
                    db   = FindingHistory(db_path)
                    diff = db.diff_with_last(report)
                    db.save_run(report)
                    self._log(f"\n📚 History: {diff.summary}")
                    if diff.new_findings:
                        self._log(f"  🚨 {len(diff.new_findings)} NEW regressions!")
                    report.stats["diff"] = {
                        "baseline_run": diff.baseline_run_id,
                        "new":          len(diff.new_findings),
                        "fixed":        len(diff.fixed_findings),
                    }
                    if diff.new_findings:
                        self._send_alerts(report)
                except Exception as _e:
                    self._log(f"  ⚠ History save failed: {_e}")

            self._emit("scan_complete", {"findings": len(report.findings)})

        except Exception as exc:
            report.status     = TestStatus.FAILED
            report.finished_at = datetime.utcnow()
            self._log(f"✗ Run failed: {exc}")
            self._emit("log", {"msg": f"Run failed: {exc}", "cls": "err"})
            raise

        return report

    # ------------------------------------------------------------------

    def _build_llm(self) -> BaseLLM:
        cfg = self.config
        kw: Dict = {}
        if cfg.llm_model:    kw["model"]    = cfg.llm_model
        if cfg.llm_api_key:  kw["api_key"]  = cfg.llm_api_key
        if cfg.llm_base_url: kw["base_url"] = cfg.llm_base_url
        return create_llm(cfg.llm_backend, **kw)

    def _parse_schema(self) -> APISchema:
        cfg = self.config
        if cfg.spec_dict:
            return OpenAPIParser.from_dict(cfg.spec_dict).parse()
        if cfg.spec_file:
            # If spec is a URL, fetch it instead of reading as file
            if cfg.spec_file.startswith("http://") or cfg.spec_file.startswith("https://"):
                self._log(f"🌐 Fetching spec from URL: {cfg.spec_file}")
                import urllib.request as _ur
                try:
                    with _ur.urlopen(cfg.spec_file, timeout=cfg.timeout) as resp:
                        raw = resp.read().decode("utf-8")
                    import json as _json
                    try:
                        spec_data = _json.loads(raw)
                    except _json.JSONDecodeError:
                        import yaml as _yaml
                        spec_data = _yaml.safe_load(raw)
                    return OpenAPIParser.from_dict(spec_data).parse()
                except Exception as e:
                    self._log(f"⚠️  Could not fetch spec from URL ({e}) — falling back to auto-discover")
                    cfg = self.config.__class__(**{**self.config.__dict__, "spec_file": None, "auto_discover": True})
                    self.config = cfg
            else:
                p = Path(cfg.spec_file)
                if p.suffix in (".graphql", ".gql"):
                    from entropy.schemas.graphql import GraphQLParser, graphql_to_api_schema
                    gql = GraphQLParser.from_file(str(p))
                    return graphql_to_api_schema(gql, cfg.target_url)
                return OpenAPIParser.from_file(p).parse()
        if cfg.auto_discover or not cfg.spec_file:
            self._log(f"🔍 No spec provided — auto-discovering endpoints at {cfg.target_url}…")
            from entropy.discovery import ActiveCrawler
            crawler = ActiveCrawler(
                cfg.target_url,
                timeout    = cfg.timeout,
                verify_ssl = cfg.verify_ssl,
                proxy      = cfg.proxy_url,
                verbose    = cfg.verbose,
            )
            result = crawler.crawl()
            if result.schema:
                return result.schema
            # Build minimal schema from discovered endpoints
            from entropy.core.models import APISchema as _AS
            schema = _AS(
                title     = f"Discovered: {cfg.target_url}",
                version   = "auto",
                base_url  = cfg.target_url,
                endpoints = result.endpoints,
            )
            self._log(f"  ✓ Auto-discovered {len(schema.endpoints)} endpoints")
            return schema
        raise ValueError("No API spec provided. Use --spec, or add --discover flag.")

    def _build_persona_configs(self) -> List[PersonaConfig]:
        all_c   = all_persona_configs(self.config.concurrency)
        desired = set(self.config.personas)
        configs = [pc for pc in all_c if pc.type in desired]  # Inject custom persona from YAML
        if self.config.custom_persona:
            try:
                from entropy.personas.custom import CustomPersonaSpec
                spec = CustomPersonaSpec.from_yaml(self.config.custom_persona)
                # Build a PersonaConfig wrapping the custom spec
                custom_pc = PersonaConfig(
                    type        = PersonaType.CUSTOM,
                    name        = spec.name,
                    description = spec.description,
                    concurrency = spec.concurrency,
                    extra       = {
                        "attack_focus":        spec.attack_focus,
                        "payload_overrides":   spec.payload_overrides,
                        "headers":             spec.headers,
                        "endpoints_whitelist": spec.endpoints_whitelist,
                        "endpoints_blacklist": spec.endpoints_blacklist,
                        "delay_ms":            spec.delay_ms,
                    },
                )
                configs.append(custom_pc)
                self._log(f"  ✓ Custom persona loaded: {spec.name}")
            except Exception as exc:
                self._log(f"  ⚠ Custom persona load failed: {exc}")

        return configs

    def _assign_endpoints(self, vectors: List[AttackVector], schema: APISchema) -> None:
        import itertools
        ep_cycle = itertools.cycle(schema.endpoints) if schema.endpoints else iter([])
        for v in vectors:
            if v.endpoint is None and schema.endpoints:
                v.endpoint = next(ep_cycle)

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        seen:   set = set()
        unique: List[Finding] = []
        for f in findings:
            key = (f.title, f.endpoint, f.type.value)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        sev_order = {s: i for i, s in enumerate(Severity)}
        return sorted(unique, key=lambda f: sev_order.get(f.severity, 99))

    def _enrich_remediations(self, findings: List[Finding]) -> None:
        enriched: set = set()
        for f in findings:
            if f.type in enriched:
                continue
            enriched.add(f.type)
            try:
                data = self.llm.complete_json(
                    f"Provide a concise remediation (2-3 sentences) for:\n"
                    f"  Type: {f.type.value}\n  Title: {f.title}\n  Description: {f.description}\n"
                    "Return JSON: {\"remediation\": \"...\"}"
                )
                f.remediation = data.get("remediation", "")
            except Exception:
                pass

    def _save_reports(self, report: EntropyReport) -> None:
        out = Path(self.config.output_dir)
        out.mkdir(parents=True, exist_ok=True)

        md   = MarkdownReporter(self.llm).save(report, out / "report.md")
        js   = JSONReporter().save(report, out / "report.json")
        paths = [f"   Markdown → {md}", f"   JSON     → {js}"]

        if self.config.html_report:
            html = HTMLReporter().save(report, out / "report.html")
            paths.append(f"   HTML     → {html}")

        if self.config.junit_output:
            from entropy.integrations.cicd import GitLabCIIntegration
            junit = GitLabCIIntegration.save_junit(report, self.config.junit_output)
            paths.append(f"   JUnit    → {junit}")

        if self.config.sarif_output:
            from entropy.reporting.sarif import SARIFReporter
            sarif_path = Path(self.config.sarif_output)
            sarif_path.parent.mkdir(parents=True, exist_ok=True)
            sarif = SARIFReporter().save(report, sarif_path)
            paths.append(f"   SARIF    → {sarif}")

        self._log("\n📄 Reports saved:")
        for p in paths:
            self._log(p)

        # CI annotations
        from entropy.integrations.cicd import detect_ci_environment, GitHubActionsIntegration
        if detect_ci_environment() == "github_actions":
            GitHubActionsIntegration.annotate(report)
            GitHubActionsIntegration.set_outputs(report)

    def _open_issues(self, report: EntropyReport) -> None:
        critical_high = [f for f in report.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if not critical_high:
            return
        if self.config.github_repo:
            from entropy.reporting.cvss import GitHubIssueOpener
            opener = GitHubIssueOpener(self.config.github_repo)
            for f in critical_high[:10]:
                url = opener.open_issue(f)
                if url:
                    self._log(f"  🐛 GitHub issue: {url}")
        if self.config.gitlab_project:
            from entropy.reporting.cvss import GitLabIssueOpener
            opener = GitLabIssueOpener(self.config.gitlab_project)
            for f in critical_high[:10]:
                url = opener.open_issue(f)
                if url:
                    self._log(f"  🦊 GitLab issue: {url}")

    def _print_banner(self) -> None:
        cfg = self.config
        print("""
╔══════════════════════════════════════════════════════╗
║  🌪️  ENTROPY — Chaos Engineering Framework          ║
║  AI-Powered Logical Fuzzing & Autonomous Testing     ║
╚══════════════════════════════════════════════════════╝
""")
        print(f"  Target  : {cfg.target_url}")
        print(f"  LLM     : {cfg.llm_backend}" + (f" / {cfg.llm_model}" if cfg.llm_model else ""))
        print(f"  Mode    : {'DRY RUN (simulation)' if cfg.dry_run else 'LIVE (real HTTP)'}")
        print(f"  Profile : {cfg.scan_profile}")
        print(f"  Output  : {cfg.output_dir}/")
        print()

    def _print_summary(self, report: EntropyReport) -> None:
        s = report.summary()
        d = (report.finished_at - report.started_at).total_seconds() if report.finished_at else 0
        print(f"""
╔══════════════════════════════════════════════════════╗
║  📊  RESULTS SUMMARY                                ║
╠══════════════════════════════════════════════════════╣
║  🔴 Critical : {str(s.get('critical',0)).ljust(4)}                               ║
║  🟠 High     : {str(s.get('high',0)).ljust(4)}                               ║
║  🟡 Medium   : {str(s.get('medium',0)).ljust(4)}                               ║
║  🟢 Low      : {str(s.get('low',0)).ljust(4)}                               ║
║                                                      ║
║  Total findings : {str(len(report.findings)).ljust(33)}║
║  Duration       : {(str(round(d,1))+'s').ljust(33)}║
╚══════════════════════════════════════════════════════╝
""")

    def _run_advanced_tests(
        self,
        findings: List[Finding],
        schema: "APISchema",
        cfg: "EntropyConfig",
    ) -> None:
        """Run v0.4.0 advanced security checks and append findings."""
        from entropy.core.models import Finding as _F

        # SSRF detection
        if cfg.ssrf_check and schema.endpoints:
            try:
                from entropy.fuzzing.ssrf import SSRFDetector
                self._log("  🌐 SSRF detection…")
                ssrf = SSRFDetector(
                    cfg.target_url, timeout=cfg.timeout,
                    verify_ssl=cfg.verify_ssl, dry_run=cfg.dry_run,
                )
                for ep in schema.endpoints[:8]:
                    new = ssrf.test_endpoint(ep)
                    findings.extend(new)
                    if new and cfg.verbose:
                        self._log(f"    🔴 SSRF on {ep.path}: {new[0].title}")
            except Exception as exc:
                if cfg.verbose:
                    self._log(f"  ⚠ SSRF scan error: {exc}")

        # SSTI detection
        if cfg.ssti_check and schema.endpoints:
            try:
                from entropy.fuzzing.ssti import SSTIDetector
                self._log("  🧪 SSTI detection…")
                ssti = SSTIDetector(
                    cfg.target_url, timeout=cfg.timeout,
                    verify_ssl=cfg.verify_ssl, dry_run=cfg.dry_run,
                )
                for ep in schema.endpoints[:8]:
                    new = ssti.test_endpoint(ep)
                    findings.extend(new)
            except Exception as exc:
                if cfg.verbose:
                    self._log(f"  ⚠ SSTI scan error: {exc}")

        # XXE detection
        if cfg.xxe_check and schema.endpoints:
            try:
                from entropy.fuzzing.xxe import XXEDetector
                self._log("  📄 XXE detection…")
                xxe = XXEDetector(
                    cfg.target_url, timeout=cfg.timeout,
                    verify_ssl=cfg.verify_ssl, dry_run=cfg.dry_run,
                )
                for ep in schema.endpoints[:8]:
                    new = xxe.test_endpoint(ep)
                    findings.extend(new)
            except Exception as exc:
                if cfg.verbose:
                    self._log(f"  ⚠ XXE scan error: {exc}")

        # Parameter mining
        if cfg.param_mining and schema.endpoints:
            try:
                from entropy.fuzzing.param_miner import ParameterMiner
                self._log("  🔍 Parameter mining…")
                miner = ParameterMiner(
                    cfg.target_url, timeout=cfg.timeout,
                    verify_ssl=cfg.verify_ssl, concurrency=8,
                    dry_run=cfg.dry_run,
                )
                for ep in schema.endpoints[:5]:
                    new = miner.mine_endpoint(ep)
                    findings.extend(new)
                    if new and cfg.verbose:
                        for f in new:
                            self._log(f"    💡 Hidden param: {f.title}")
            except Exception as exc:
                if cfg.verbose:
                    self._log(f"  ⚠ Param mining error: {exc}")

        # IDOR chain testing
        if cfg.idor_chain and schema.endpoints:
            try:
                from entropy.fuzzing.idor_chain import IDORChainTester
                self._log("  🔗 IDOR chain testing…")
                idor = IDORChainTester(
                    cfg.target_url, timeout=cfg.timeout,
                    verify_ssl=cfg.verify_ssl, dry_run=cfg.dry_run,
                )
                new = idor.test_schema(schema)
                findings.extend(new)
            except Exception as exc:
                if cfg.verbose:
                    self._log(f"  ⚠ IDOR chain error: {exc}")

        # HTTP Request Smuggling (live only — timing-based)
        if cfg.smuggling_check and not cfg.dry_run:
            try:
                from entropy.fuzzing.smuggling import RequestSmugglingDetector
                self._log("  🚢 Smuggling detection…")
                smuggler = RequestSmugglingDetector(
                    cfg.target_url, verify_ssl=cfg.verify_ssl,
                )
                new = smuggler.detect()
                findings.extend(new)
            except Exception as exc:
                if cfg.verbose:
                    self._log(f"  ⚠ Smuggling detection error: {exc}")

        # JWT analysis — scan findings for JWT tokens in evidence
        if cfg.jwt_check:
            try:
                from entropy.fuzzing.jwt_tester import JWTAnalyser, extract_jwts
                analyser   = JWTAnalyser()
                jwt_tokens = set()
                for f in list(findings):
                    tokens = extract_jwts(f.evidence)
                    jwt_tokens.update(tokens)
                for token in jwt_tokens:
                    new = analyser.analyse(token, "jwt_response", dry_run=cfg.dry_run)
                    findings.extend(new)
            except Exception as exc:
                if cfg.verbose:
                    self._log(f"  ⚠ JWT analysis error: {exc}")

    def _run_adaptive_analysis(
        self, findings: List[Finding]
    ) -> tuple:
        try:
            from entropy.fuzzing.adaptive_analyser import AdaptiveResponseAnalyser
            analyser = AdaptiveResponseAnalyser(
                self.llm,
                min_confidence=0.55,
            )
            return analyser.filter_false_positives(
                findings, max_to_analyse=self.config.max_adaptive_budget
            )
        except Exception:
            return findings, []

    def _log(self, msg: str) -> None:
        print(msg)
    # ------------------------------------------------------------------  # Helpers
    # ------------------------------------------------------------------

    def _emit(self, event_type: str, data) -> None:
        """Emit event to dashboard if active."""
        if self.config.dashboard:
            try:
                from entropy.web import emit
                emit(event_type, data)
            except Exception:
                pass

    def _send_alerts(self, report: EntropyReport) -> None:
        """Send webhook / Slack alerts on new findings."""
        cfg = self.config
        if cfg.webhook_url:
            try:
                import json, urllib.request
                payload = {
                    "event":     "entropy.regression",
                    "target":    report.target,
                    "run_id":    report.id,
                    "new_count": report.stats.get("diff", {}).get("new", 0),
                }
                req = urllib.request.Request(
                    cfg.webhook_url,
                    data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=10)
            except Exception as exc:
                self._log(f"  ⚠ Webhook failed: {exc}")

        if cfg.slack_webhook:
            try:
                import json, urllib.request
                n   = report.stats.get("diff", {}).get("new", 0)
                msg = f"🚨 *Entropy* — {n} new finding(s) on `{report.target}`"
                req = urllib.request.Request(
                    cfg.slack_webhook,
                    data=json.dumps({"text": msg}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=10)
            except Exception as exc:
                self._log(f"  ⚠ Slack failed: {exc}")
