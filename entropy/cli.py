#!/usr/bin/env python3
"""CLI entry point — run `entropy --help` for usage."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from entropy.core.models import PersonaType
from entropy.core.config import PROFILES, ENTROPY_YML_TEMPLATE, load_dotenv
from entropy.core.orchestrator import EntropyConfig, EntropyRunner
from entropy.llm.backends import list_backends
from entropy.reporting.reporter import get_exit_code


# ---------------------------------------------------------------------------
# Subcommand: run
# ---------------------------------------------------------------------------

def _add_run_parser(sub):
    p = sub.add_parser("run", help="Run chaos engineering tests against an API")

    # Config file shortcut
    p.add_argument("--config",    metavar="FILE",  help="Load entropy.yml config file")
    p.add_argument("--profile",   default="standard", choices=list(PROFILES.keys()),
                   help="Scan profile: quick | standard | full | stealth | ci")

    # Target
    p.add_argument("--spec",      metavar="FILE",  help="OpenAPI/Swagger/GraphQL spec file")
    p.add_argument("--target",    default="http://localhost:8000", help="Target base URL")

    # LLM
    p.add_argument("--llm",       default="mock",
                   choices=list_backends() + ["groq","together","lmstudio","azure"],
                   metavar="BACKEND",
                   help="LLM backend: " + " | ".join(list_backends()))
    p.add_argument("--llm-model",    default="", metavar="MODEL", help="LLM model name")
    p.add_argument("--llm-api-key",  default="", metavar="KEY",   help="LLM API key")
    p.add_argument("--llm-url",      default="", metavar="URL",   help="Custom LLM base URL (for compatible endpoints)")

    # Execution
    p.add_argument("--dry-run",  action="store_true", help="Simulate requests without real HTTP (default)")
    p.add_argument("--live",     action="store_true", help="Send real HTTP requests")
    p.add_argument("--concurrency", type=int, default=None, help="Override concurrent requests per persona")
    p.add_argument("--timeout",  type=float, default=10.0, help="HTTP timeout in seconds")

    # Personas
    p.add_argument("--personas", nargs="+", metavar="PERSONA",
                   choices=[pt.value for pt in PersonaType if pt != PersonaType.CUSTOM],
                   help="Personas to activate (default: profile default)")

    # Output
    p.add_argument("--output",   default="entropy-report", help="Output directory")
    p.add_argument("--fail-on",  default=None,
                   choices=["critical","high","medium","low","any","none"],
                   help="Exit with code 1 if findings at/above this severity")
    p.add_argument("--junit",    default=None, metavar="FILE", help="JUnit XML output path")
    p.add_argument("--no-html",  action="store_true", help="Skip HTML report generation")  # Discovery
    p.add_argument("--discover", action="store_true", help="Auto-discover endpoints (no spec needed)")  # Dashboard
    p.add_argument("--dashboard",      action="store_true", help="Launch browser dashboard on port 8080")
    p.add_argument("--dashboard-port", type=int, default=8080, metavar="PORT", help="Dashboard port (default: 8080)")  # Watch mode
    p.add_argument("--watch",          action="store_true", help="Watch mode: re-run on schedule or file change")
    p.add_argument("--watch-interval", type=int, default=300, metavar="SEC", help="Watch interval in seconds (default: 300)")
    p.add_argument("--watch-file",     nargs="+", metavar="FILE", help="Re-run when these files change")  # HTTP options
    p.add_argument("--proxy",       default=None, metavar="URL",  help="HTTP proxy URL (e.g. http://127.0.0.1:8080 for Burp)")
    p.add_argument("--no-verify-ssl", action="store_true",        help="Disable TLS verification (accept self-signed certs)")
    p.add_argument("--retries",     type=int, default=3, metavar="N", help="Max retries per request (default: 3)")  # SARIF
    p.add_argument("--sarif",       default=None, metavar="FILE", help="SARIF output file (GitHub Code Scanning)")  # Baseline diff
    p.add_argument("--no-baseline", action="store_true",          help="Disable baseline diff filtering")  # History
    p.add_argument("--no-history",  action="store_true",          help="Disable SQLite history / regression tracking")
    p.add_argument("--history-db",  default=None, metavar="FILE", help="Custom history DB path")  # WebSocket
    p.add_argument("--ws",          default=None, metavar="URL",  help="WebSocket endpoint to fuzz (ws:// or wss://)")  # Proxy intercept mode
    p.add_argument("--proxy-mode",  action="store_true",          help="Start HTTP interception proxy")
    p.add_argument("--proxy-port",  type=int, default=8888,       help="Interception proxy port (default: 8888)")  # Rate limit
    p.add_argument("--no-rate-limit-check", action="store_true", help="Skip rate limit detection")
    p.add_argument("--rate-limit-probes",   type=int, default=50, metavar="N", help="Max probes for rate limit detection (default: 50)")  # Differential testing
    p.add_argument("--diff-target",      default=None, metavar="URL", help="Compare --target vs this URL (prod vs staging, v1 vs v2)")
    p.add_argument("--diff-auth-header", default=None, metavar="HEADER", help="Auth header for diff target e.g. 'Authorization: Bearer token'")  # Custom persona
    p.add_argument("--custom-persona",   default=None, metavar="FILE", help="Custom persona YAML file path")  # Webhooks
    p.add_argument("--webhook",      default=None, metavar="URL", help="Webhook URL for new-finding alerts")
    p.add_argument("--slack-webhook",default=None, metavar="URL", help="Slack incoming webhook URL")

    # CI integrations
    p.add_argument("--github-repo",   default=None, metavar="OWNER/REPO", help="Open GitHub issues for critical/high")
    p.add_argument("--gitlab-project",default=None, metavar="PROJECT_ID",  help="Open GitLab issues for critical/high")

    # Misc
    p.add_argument("--verbose",  action="store_true", help="Print every request/response")
    p.add_argument("--no-llm-enrichment", action="store_true", help="Skip LLM remediation enrichment")
    p.add_argument("--env-file", default=".env", help="Path to .env file (default: .env)")
    return p


def cmd_run(args) -> int:
    load_dotenv(args.env_file)

    # Start from profile
    profile  = PROFILES.get(args.profile, PROFILES["standard"])
    dry_run  = not args.live

    # Personas: CLI > profile default
    personas = [PersonaType(p) for p in args.personas] if args.personas else profile.personas

    config = EntropyConfig(
        target_url=args.target,
        spec_file=args.spec,

        llm_backend=args.llm,
        llm_model=args.llm_model,
        llm_api_key=args.llm_api_key,
        llm_base_url=args.llm_url,

        dry_run=dry_run,
        concurrency=args.concurrency if args.concurrency else profile.concurrency,
        timeout=args.timeout,
        max_steps=profile.max_steps,

        personas=personas,

        output_dir=args.output,
        fail_on=args.fail_on or profile.fail_on,
        junit_output=args.junit,
        html_report=not args.no_html,

        scan_profile=args.profile,
        verbose=args.verbose,
        enrich_with_llm=not args.no_llm_enrichment,

        github_repo=args.github_repo,
        gitlab_project=args.gitlab_project,
        open_issues=bool(args.github_repo or args.gitlab_project),  # Auto_discover   = args.discover,
        rate_limit_check = not args.no_rate_limit_check,
        rate_limit_max_probes = args.rate_limit_probes,
        diff_target      = args.diff_target,
        diff_auth_header = args.diff_auth_header,
        custom_persona   = args.custom_persona,
        dashboard       = args.dashboard,
        dashboard_port  = args.dashboard_port,
        watch           = args.watch,
        watch_interval  = args.watch_interval,
        watch_files     = args.watch_file or [],
        proxy_url       = args.proxy,
        verify_ssl      = not args.no_verify_ssl,
        max_retries     = args.retries,
        sarif_output    = args.sarif,
        baseline_diff   = not args.no_baseline,
        save_history    = not args.no_history,
        history_db      = args.history_db,
        websocket_url   = args.ws,
        proxy_mode      = args.proxy_mode,
        proxy_port      = args.proxy_port,
        webhook_url     = args.webhook,
        slack_webhook   = args.slack_webhook,
    )  # Proxy intercept mode
    if args.proxy_mode:
        from entropy.proxy import EntropyProxy
        proxy = EntropyProxy(port=args.proxy_port)
        proxy.start()
        return 0

    runner = EntropyRunner(config)  # Watch mode
    if args.watch:
        from entropy.watch import EntropyWatcher
        watcher = EntropyWatcher(
            config,
            interval_seconds = args.watch_interval,
            watch_files      = args.watch_file or [],
            webhook_url      = args.webhook,
            slack_webhook    = args.slack_webhook,
        )
        watcher.start()
        return 0

    report = runner.run()

    if (args.fail_on or "").lower() == "none":
        return 0  # CI regression check
    diff = report.stats.get("diff", {})
    if diff.get("new", 0) > 0:
        print(f"\n  ⚠  {diff['new']} regression(s) detected vs last run!")

    return get_exit_code(report, fail_on=config.fail_on)


# ---------------------------------------------------------------------------
# Subcommand: report
# ---------------------------------------------------------------------------

def _add_report_parser(sub):
    p  = sub.add_parser("report", help="Report utilities")
    rp = p.add_subparsers(dest="report_cmd")

    s = rp.add_parser("summary", help="Print summary of an existing report")
    s.add_argument("--input", required=True, help="Path to report.json")

    rp.add_parser("ci-templates",    help="Print GitHub Actions / GitLab CI templates")
    rp.add_parser("config-template", help="Print an example entropy.yml")
    return p


def cmd_report(args) -> int:
    if args.report_cmd == "summary":
        p = Path(args.input)
        if not p.exists():
            print(f"Error: {p} not found.", file=sys.stderr)
            return 1
        data = json.loads(p.read_text())
        print(f"\n📄 Entropy Report: {data.get('target','N/A')}")
        print(f"   Status  : {data.get('status','N/A')}")
        print(f"   Findings: {len(data.get('findings',[]))}")
        for sev, count in (data.get("summary") or {}).items():
            if count:
                print(f"   {sev.capitalize():10s}: {count}")
        stats = data.get("stats") or {}
        if stats:
            print(f"   Requests: {stats.get('requests_sent','N/A')}")
        return 0

    if args.report_cmd == "ci-templates":
        from entropy.integrations.cicd import GITHUB_ACTIONS_WORKFLOW, GITLAB_CI_TEMPLATE
        print("=" * 60)
        print("GitHub Actions (.github/workflows/entropy.yml)")
        print("=" * 60)
        print(GITHUB_ACTIONS_WORKFLOW)
        print("=" * 60)
        print("GitLab CI (.gitlab-ci.yml snippet)")
        print("=" * 60)
        print(GITLAB_CI_TEMPLATE)
        return 0

    if args.report_cmd == "config-template":
        print(ENTROPY_YML_TEMPLATE)
        return 0

    print("Use: entropy report summary | ci-templates | config-template")
    return 1


# ---------------------------------------------------------------------------
# Subcommand: backends
# ---------------------------------------------------------------------------

def cmd_backends(_args) -> int:
    from entropy.llm.backends import _BACKEND_MAP, _BACKEND_DEFAULTS
    print("\n🤖 Available LLM Backends\n")
    info = {
        "mock":        ("No API key needed", "Offline deterministic — ideal for CI/development"),
        "openai":      ("OPENAI_API_KEY",     "OpenAI GPT-4o-mini, GPT-4o, etc."),
        "anthropic":   ("ANTHROPIC_API_KEY",  "Claude claude-haiku-4-5-20251001, claude-sonnet-4-5, claude-opus-4-5, etc."),
        "gemini":      ("GEMINI_API_KEY",     "Google Gemini 1.5 Flash/Pro, 2.0 Flash"),
        "mistral":     ("MISTRAL_API_KEY",    "Mistral Small, Mistral Large, Codestral"),
        "cohere":      ("COHERE_API_KEY",     "Command R+, Command R"),
        "huggingface": ("HF_API_KEY",         "Any HF Inference API model (Llama, Phi, Qwen…)"),
        "ollama":      ("No API key needed",  "Local models: llama3, mistral, phi3, gemma2 (run `ollama pull <model>`)"),
        "groq":        ("GROQ_API_KEY",       "OpenAI-compatible, ultra-fast inference (Llama, Mixtral)"),
        "together":    ("TOGETHER_API_KEY",   "Together AI — OpenAI-compatible, many open models"),
        "lmstudio":    ("No API key needed",  "LM Studio local server (OpenAI-compatible, localhost:1234)"),
    }
    for name, (key_info, desc) in info.items():
        print(f"  {name:<14} {key_info:<25} {desc}")
    print()
    return 0


# ---------------------------------------------------------------------------
# Subcommand: profiles
# ---------------------------------------------------------------------------

def cmd_profiles(_args) -> int:
    print("\n🎯 Scan Profiles\n")
    print(f"  {'Name':<12} {'Personas':<6} {'Concurrency':<14} {'Fail-on':<10} Description")
    print("  " + "-" * 75)
    for name, prof in PROFILES.items():
        print(f"  {name:<12} {len(prof.personas):<6} {prof.concurrency:<14} {prof.fail_on:<10} {prof.description}")
    print()
    return 0


# ---------------------------------------------------------------------------
# Subcommand: graphql
# ---------------------------------------------------------------------------

def _add_graphql_parser(sub):
    p  = sub.add_parser("graphql", help="GraphQL-specific utilities")
    gp = p.add_subparsers(dest="gql_cmd")

    a = gp.add_parser("attacks", help="Print built-in GraphQL attack queries")
    a.add_argument("--target", default="http://localhost:4000", help="GraphQL endpoint base URL")

    i = gp.add_parser("introspect", help="Fetch and print schema from a live GraphQL endpoint")
    i.add_argument("--target", required=True, help="GraphQL endpoint URL")
    return p


def cmd_graphql(args) -> int:
    if args.gql_cmd == "attacks":
        from entropy.schemas.graphql import get_graphql_attack_requests
        attacks = get_graphql_attack_requests(args.target)
        print(f"\n🕸️  GraphQL Attack Payloads ({len(attacks)} scenarios)\n")
        for a in attacks:
            print(f"  [{a['severity'].upper():<8}] {a['name']}")
            print(f"             {a['description']}")
            body = json.dumps(a['body'])[:100]
            print(f"             Payload: {body}…\n")
        return 0

    if args.gql_cmd == "introspect":
        from entropy.schemas.graphql import GraphQLParser
        print(f"  Fetching schema from {args.target}…")
        try:
            schema = GraphQLParser.from_endpoint(args.target)
            print(f"  ✓ Query root  : {schema.query_type}")
            print(f"  ✓ Mutation root: {schema.mutation_type}")
            print(f"  ✓ Types        : {len(schema.types)}")
            for name, t in list(schema.types.items())[:10]:
                print(f"     {name} ({t.kind}) — {len(t.fields)} fields")
        except Exception as exc:
            print(f"  ✗ Failed: {exc}")
            return 1
        return 0

    print("Use: entropy graphql attacks | introspect")
    return 1


# ---------------------------------------------------------------------------
# Subcommand: owasp
# ---------------------------------------------------------------------------

def cmd_owasp(_args) -> int:
    from entropy.scenarios.owasp import ALL_SCENARIOS, SCENARIOS_BY_OWASP
    print(f"\n🛡️  OWASP Top 10 Attack Scenarios ({len(ALL_SCENARIOS)} total)\n")
    for owasp_id in sorted(SCENARIOS_BY_OWASP.keys()):
        scenarios = SCENARIOS_BY_OWASP[owasp_id]
        print(f"  {owasp_id} ({scenarios[0].owasp_name})")
        for s in scenarios:
            print(f"    [{s.severity.upper():<8}] {s.id}  {s.name}")
            print(f"              CVSS: {s.cvss_base}  —  {s.description[:70]}…")
        print()
    return 0


# ---------------------------------------------------------------------------
# Subcommand: compare (differential)
# ---------------------------------------------------------------------------

def _add_compare_parser(sub):
    p = sub.add_parser("compare", help="Differential test: compare two API targets")
    p.add_argument("--spec",    required=True,          help="API spec file")
    p.add_argument("--target-a", required=True,         help="First target URL (baseline)")
    p.add_argument("--target-b", required=True,         help="Second target URL (compare against)")
    p.add_argument("--auth-header", default=None,       help="Auth header e.g. 'Authorization: Bearer ...'")
    p.add_argument("--no-verify-ssl", action="store_true")
    p.add_argument("--output",  default=None,           help="Write diff report to JSON file")
    return p


def cmd_compare(args) -> int:
    from entropy.core.orchestrator import EntropyConfig, EntropyRunner
    from entropy.fuzzing.differential import DifferentialTester
    from entropy.core.parser import OpenAPIParser
    import json

    print(f"\n🔀 Differential: {args.target_a}  vs  {args.target_b}\n")

    try:
        schema = OpenAPIParser.from_file(args.spec).parse()
    except Exception as exc:
        print(f"  ✗ Failed to parse spec: {exc}")
        return 1

    auth_headers = {}
    if args.auth_header:
        k, _, v = args.auth_header.partition(":")
        auth_headers[k.strip()] = v.strip()

    differ = DifferentialTester(
        target_a     = args.target_a,
        target_b     = args.target_b,
        verify_ssl   = not args.no_verify_ssl,
        auth_headers = auth_headers,
    )
    report = differ.run(schema)

    print(report.summary())
    print()

    if not report.divergences:
        print("  ✅ No divergences found — targets behave identically")
        return 0

    by_sev = {"critical": [], "high": [], "medium": [], "low": []}
    for d in report.divergences:
        by_sev.setdefault(d.severity, []).append(d)

    for sev in ("critical", "high", "medium", "low"):
        items = by_sev.get(sev, [])
        if not items:
            continue
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[sev]
        print(f"  {emoji} {sev.upper()} ({len(items)})")
        for d in items:
            print(f"     [{d.kind}] {d.endpoint}")
            print(f"       {d.description}")
        print()

    if args.output:
        from pathlib import Path
        out = {
            "target_a": report.target_a,
            "target_b": report.target_b,
            "endpoints_tested": report.endpoints_tested,
            "duration_s": round(report.duration_s, 2),
            "divergences": [
                {
                    "endpoint": d.endpoint,
                    "kind": d.kind,
                    "severity": d.severity,
                    "description": d.description,
                }
                for d in report.divergences
            ],
        }
        Path(args.output).write_text(json.dumps(out, indent=2))
        print(f"  📄 Diff report written to {args.output}")

    return 1 if report.has_breaking_changes else 0


# ---------------------------------------------------------------------------
# Subcommand: persona
# ---------------------------------------------------------------------------

def _add_persona_parser(sub):
    p  = sub.add_parser("persona", help="Custom persona management")
    pp = p.add_subparsers(dest="persona_cmd")

    pp.add_parser("template", help="Print persona YAML template")
    v = pp.add_parser("validate", help="Validate a persona YAML file")
    v.add_argument("file", help="Path to persona YAML")
    return p


def cmd_persona(args) -> int:
    if args.persona_cmd == "template":
        from entropy.personas.custom import PERSONA_YAML_TEMPLATE
        print(PERSONA_YAML_TEMPLATE)
        return 0

    if args.persona_cmd == "validate":
        from entropy.personas.custom import CustomPersonaSpec
        try:
            spec = CustomPersonaSpec.from_yaml(args.file)
            print(f"\n  ✅ Valid persona: {spec.name}")
            print(f"     Auth level   : {spec.auth_level}")
            print(f"     Attack focus : {spec.attack_focus or '(all)'}")
            print(f"     Concurrency  : {spec.concurrency}")
            if spec.endpoints_whitelist:
                print(f"     Whitelist    : {spec.endpoints_whitelist}")
            if spec.payload_overrides:
                print(f"     Overrides    : {spec.payload_overrides}")
            return 0
        except Exception as exc:
            print(f"\n  ✗ Invalid persona: {exc}")
            return 1

    print("Use: entropy persona template | validate <file>")
    return 1


# ---------------------------------------------------------------------------
# Subcommand: ratelimit
# ---------------------------------------------------------------------------

def _add_ratelimit_parser(sub):
    p = sub.add_parser("ratelimit", help="Probe rate limiting on a specific endpoint")
    p.add_argument("--url",         required=True,   help="Full URL to probe")
    p.add_argument("--method",      default="GET",   help="HTTP method (default: GET)")
    p.add_argument("--max-probes",  type=int, default=60, help="Max requests to send (default: 60)")
    p.add_argument("--delay-ms",    type=float, default=50, help="Delay between requests in ms (default: 50)")
    p.add_argument("--no-verify-ssl", action="store_true")
    p.add_argument("--proxy",       default=None)
    return p


def cmd_ratelimit(args) -> int:
    from entropy.fuzzing.ratelimit import RateLimitDetector

    print(f"\n🚦 Rate limit probe: {args.method} {args.url}")
    print(f"   Max probes: {args.max_probes}, delay: {args.delay_ms}ms\n")

    detector = RateLimitDetector(
        url         = args.url,
        method      = args.method,
        max_probes  = args.max_probes,
        delay_ms    = args.delay_ms,
        verify_ssl  = not args.no_verify_ssl,
        proxy_url   = args.proxy,
    )
    result = detector.probe()

    if not result.has_rate_limit:
        print(f"  🔴 NO RATE LIMIT — server accepted all {len(result.probes)} requests")
        return 1

    print(f"  ✅ Rate limit detected at request #{result.limit_at}")
    if result.limit_window:
        print(f"     Window       : {result.limit_window}")
    if result.retry_after_respected is not None:
        respected = "✅ yes" if result.retry_after_respected else "❌ no (Retry-After ignored)"
        print(f"     Retry-After  : {respected}")
    if result.bypass_vectors:
        print(f"\n  🔴 BYPASS VECTORS FOUND:")
        for v in result.bypass_vectors:
            print(f"     • {v}")
        return 1

    print("\n  No bypass vectors found.")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: history
# ---------------------------------------------------------------------------

def _add_history_parser(sub):
    p  = sub.add_parser("history", help="View scan history and regression reports")
    hp = p.add_subparsers(dest="history_cmd")

    ls = hp.add_parser("list", help="List recent runs")
    ls.add_argument("--target", default=None, help="Filter by target URL")
    ls.add_argument("--limit",  type=int, default=10)

    tr = hp.add_parser("trend", help="Show finding trend for a target")
    tr.add_argument("--target", required=True)
    tr.add_argument("--last",   type=int, default=10)

    cm = hp.add_parser("compare", help="Compare two runs by ID")
    cm.add_argument("run_a")
    cm.add_argument("run_b")

    cl = hp.add_parser("clear", help="Delete all history (use with caution)")
    return p


def cmd_history(args) -> int:
    from entropy.history import FindingHistory
    db = FindingHistory()

    if args.history_cmd == "list":
        runs = db.list_runs(target=args.target, limit=args.limit)
        print(f"\n📚 Recent runs ({len(runs)} shown)\n")
        print(f"  {'ID':<12} {'Target':<35} {'Status':<12} {'Findings':<10} {'C/H/M/L'}")
        print("  " + "-" * 85)
        for r in runs:
            print(
                f"  {r.id[:8]:<12} {r.target[:34]:<35} {r.status:<12} "
                f"{r.findings_count:<10} {r.critical}/{r.high}/{r.medium}/{r.low}"
            )
        print()
        return 0

    if args.history_cmd == "trend":
        trend = db.trend(args.target, last_n=args.last)
        print(f"\n📈 Trend for {args.target}\n")
        print(f"  {'Run':<10} {'Date':<22} {'Crit':>5} {'High':>5} {'Med':>5} {'Low':>5}")
        print("  " + "-" * 55)
        for t in trend:
            print(f"  {t['run_id'][:8]:<10} {t['started_at'][:19]:<22} "
                  f"{t['critical']:>5} {t['high']:>5} {t['medium']:>5} {t['low']:>5}")
        print()
        return 0

    if args.history_cmd == "compare":
        diff = db.compare_runs(args.run_a, args.run_b)
        print(f"\n🔍 Compare {args.run_a[:8]} vs {args.run_b[:8]}")
        print(f"   Only in {args.run_a[:8]}: {len(diff['only_in_a'])} finding(s)")
        print(f"   Only in {args.run_b[:8]}: {len(diff['only_in_b'])} finding(s)")
        print(f"   In both           : {len(diff['in_both'])} finding(s)")
        return 0

    print("Use: entropy history list | trend | compare")
    return 1


# ---------------------------------------------------------------------------
# Subcommand: discover
# ---------------------------------------------------------------------------

def cmd_discover(args) -> int:
    from entropy.discovery import ActiveCrawler
    crawler = ActiveCrawler(args.target, timeout=args.timeout, verbose=True)
    result  = crawler.crawl()
    print(f"\n🔍 Discovery results for {args.target}")
    print(f"   Duration    : {result.duration_s:.1f}s")
    print(f"   Spec found  : {result.spec_url or 'None'}")
    print(f"   Endpoints   : {len(result.endpoints)}")
    print(f"   JS hints    : {len(result.js_endpoints)}")
    if result.endpoints:
        print("\n   Endpoints:")
        for ep in result.endpoints[:30]:
            print(f"     [{ep.method.value:<7}] {ep.path}")
    if result.js_endpoints:
        print("\n   JS-extracted:")
        for url in result.js_endpoints[:10]:
            print(f"     {url}")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: shell (interactive REPL)
# ---------------------------------------------------------------------------

def cmd_shell(args) -> int:
    # readline is optional: unavailable on Windows and in CI/non-TTY environments
    try:
        import readline  # noqa: arrow-key history on Unix/macOS
    except ImportError:
        pass

    import sys
    from entropy.core.orchestrator import EntropyConfig, EntropyRunner

    _tty = sys.stdin.isatty()

    BANNER = """
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551  Entropy Shell  --  Interactive REPL                \u2551
\u2551  Type 'help' for commands, 'quit' to exit           \u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d"""

    HELP = """
  run             - run full scan with current config
  target <url>    - set target URL
  spec <file>     - load spec file
  discover        - enable auto-discover (no spec needed)
  live            - toggle live/dry-run mode
  llm <backend>   - switch LLM (mock|anthropic|openai|gemini|groq|ollama)
  status          - show current config
  owasp           - list OWASP Top 10 scenarios
  history         - show last 5 runs for current target
  quit / exit     - leave shell
"""

    print(BANNER)
    if not _tty:
        print("  Non-interactive mode -- reading commands from stdin.\n")

    cfg = EntropyConfig(
        target_url  = getattr(args, "target", None) or "http://localhost:8000",
        spec_file   = getattr(args, "spec",   None),
        llm_backend = getattr(args, "llm",    "mock"),
        dry_run     = not getattr(args, "live", False),
        verbose     = True,
    )
    runner = EntropyRunner(cfg)

    while True:
        try:
            if _tty:
                line = input("entropy> ").strip()
            else:
                raw = sys.stdin.readline()
                if raw == "":
                    break
                line = raw.strip()
                if line:
                    print(f"entropy> {line}")
        except (EOFError, KeyboardInterrupt):
            print("\nBye!")
            break

        if not line:
            continue
        if line in ("quit", "exit", "q"):
            print("Bye!")
            break
        elif line == "help":
            print(HELP)
        elif line == "run":
            try:
                report = runner.run()
                n = len(report.findings)
                t = report.stats.get("duration_s", 0)
                print(f"\n  Done -- {n} finding(s) in {t:.1f}s")
            except Exception as exc:
                print(f"  Error: {exc}")
        elif line.startswith("target "):
            cfg.target_url = line[7:].strip()
            runner = EntropyRunner(cfg)
            print(f"  Target -> {cfg.target_url}")
        elif line.startswith("spec "):
            cfg.spec_file = line[5:].strip()
            runner = EntropyRunner(cfg)
            print(f"  Spec -> {cfg.spec_file}")
        elif line == "discover":
            cfg.auto_discover = True
            cfg.spec_file = None
            runner = EntropyRunner(cfg)
            print("  Auto-discover enabled.")
        elif line.startswith("llm "):
            cfg.llm_backend = line[4:].strip()
            runner = EntropyRunner(cfg)
            print(f"  LLM -> {cfg.llm_backend}")
        elif line == "live":
            cfg.dry_run = not cfg.dry_run
            runner = EntropyRunner(cfg)
            print(f"  Mode -> {'dry-run' if cfg.dry_run else 'LIVE'}")
        elif line == "status":
            mode = "dry-run" if cfg.dry_run else "LIVE"
            print(f"\n  Target  : {cfg.target_url}")
            print(f"  Spec    : {cfg.spec_file or '(auto-discover)'}")
            print(f"  LLM     : {cfg.llm_backend}")
            print(f"  Mode    : {mode}")
            print(f"  Personas: {[p.value for p in cfg.personas]}\n")
        elif line == "history":
            try:
                from entropy.history import FindingHistory
                from pathlib import Path as _P
                db = FindingHistory(_P.home() / ".entropy" / "history.db")
                runs = db.list_runs(target=cfg.target_url, limit=5)
                if not runs:
                    print("  No history for this target.")
                else:
                    for r in runs:
                        print(f"  {r.run_id[:8]}  C:{r.critical} H:{r.high} M:{r.medium}  {r.target}")
            except Exception as exc:
                print(f"  History unavailable: {exc}")
        elif line == "owasp":
            try:
                from entropy.scenarios.owasp import ALL_SCENARIOS
                for s in ALL_SCENARIOS[:10]:
                    print(f"  [{s.severity.upper():<8}] {s.name}")
            except Exception as exc:
                print(f"  Error: {exc}")
        else:
            print(f"  Unknown command: {line!r}  (type 'help')")
    return 0

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    load_dotenv()

    from entropy import __version__
    parser = argparse.ArgumentParser(
        prog="entropy",
        description="🌪️  Entropy — AI-Powered Chaos Engineering & Logical Fuzzing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  entropy run --spec openapi.yaml --target http://localhost:8000 --llm mock
  entropy run --spec api.yaml --llm anthropic --llm-api-key sk-ant-... --live
  entropy run --spec api.yaml --llm gemini --llm-api-key AIza... --profile full
  entropy run --spec api.yaml --llm ollama --llm-model llama3 --live
  entropy run --spec api.yaml --llm groq --llm-api-key gsk_... --profile quick
  entropy report summary --input entropy-report/report.json
  entropy report config-template > entropy.yml
  entropy backends
  entropy profiles
  entropy graphql attacks --target http://localhost:4000
  entropy owasp
""",
    )

    sub = parser.add_subparsers(dest="command")
    _add_run_parser(sub)
    _add_report_parser(sub)
    sub.add_parser("backends", help="List available LLM backends")
    sub.add_parser("profiles", help="List available scan profiles")
    _add_graphql_parser(sub)
    sub.add_parser("owasp", help="List OWASP Top 10 attack scenarios")
    _add_history_parser(sub)
    _add_compare_parser(sub)
    _add_persona_parser(sub)
    _add_ratelimit_parser(sub)  # Subcommands
    dc = sub.add_parser("discover", help="Auto-discover API endpoints without a spec")
    dc.add_argument("--target",  required=True, help="Target base URL")
    dc.add_argument("--timeout", type=float, default=8.0)

    sh = sub.add_parser("shell", help="Interactive REPL for manual testing")
    sh.add_argument("--target", default="http://localhost:8000")
    sh.add_argument("--spec",   default=None)
    sh.add_argument("--llm",    default="mock")
    sh.add_argument("--live",   action="store_true")

    parser.add_argument("--version", action="version", version=f"entropy {__version__}")
    args = parser.parse_args()

    dispatch = {
        "run":      cmd_run,
        "report":   cmd_report,
        "backends": cmd_backends,
        "profiles": cmd_profiles,
        "graphql":  cmd_graphql,
        "owasp":    cmd_owasp,
        "history":   cmd_history,
        "discover":  cmd_discover,
        "shell":     cmd_shell,
        "compare":   cmd_compare,
        "persona":   cmd_persona,
        "ratelimit": cmd_ratelimit,
    }

    fn = dispatch.get(args.command)
    if fn:
        sys.exit(fn(args))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
