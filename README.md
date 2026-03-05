<div align="center">

# entropy

API security testing with LLM-generated attack scenarios

[![PyPI](https://badge.fury.io/py/entropy-chaos.svg)](https://pypi.org/project/entropy-chaos/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-128%20passing-brightgreen)](#)

</div>

Most API scanners work from a fixed list of known attack patterns — SQLi payloads, common headers, OWASP wordlists. They're good at finding what they know to look for. They miss the stuff that's specific to your API: the order flow that lets you check out with a negative total, the admin endpoint that 401s on GET but not POST, the WebSocket handler that crashes on a prototype pollution payload.

Entropy feeds your API schema to an LLM and asks it to think adversarially about your specific endpoints, data models, and business logic. The LLM generates attack sequences tailored to what it sees — then Entropy executes them, compares responses against a clean baseline, and reports only the deviations that look like actual bugs.

It works on OpenAPI specs, GraphQL schemas, or no spec at all (it'll crawl the target and figure out the endpoints itself).

---

## Install

```bash
pip install entropy-chaos
```

Requires Python 3.10+. The only mandatory dependency is PyYAML — everything else is optional.

---

## Basic usage

```bash
# Simulate attacks without sending real requests (safe to run anywhere)
entropy run --spec openapi.yaml --target http://localhost:8000

# Actually send the requests
entropy run --spec openapi.yaml --target http://localhost:8000 --live

# No spec file — let it discover endpoints on its own
entropy run --target https://api.example.com --discover --live

# Use a real LLM for better attack generation
entropy run --spec api.yaml --llm anthropic --live
# ANTHROPIC_API_KEY is picked up from the environment automatically
```

---

## How it works

**Attack generation.** Entropy parses your schema, builds a picture of the API's data model and authentication structure, then prompts an LLM to generate attack sequences. The LLM output isn't just payloads — it's multi-step scenarios ("authenticate as user A, then try to access user B's resource using the session token from step 1").

**Personas.** Five attacker archetypes run in parallel, each with different threat models:

| Persona | What it tests |
|---------|---------------|
| `malicious_insider` | Authenticated abuse — IDOR, mass assignment, privilege escalation |
| `impatient_consumer` | Timing issues — race conditions, double-spend, retry loops |
| `bot_swarm` | Volume-based issues — rate limiting, resource exhaustion |
| `confused_user` | Edge cases — type confusion, state machine bypasses, unexpected inputs |
| `penetration_tester` | Classic vulns — injection, auth bypass, SSRF, XXE |

**Baseline diffing.** Before sending an attack payload, Entropy sends a normal request to the same endpoint and records the response. Findings are only flagged when the attack response meaningfully differs from the baseline — different status code, new fields in the body, significant latency increase. This cuts out most of the noise that comes from endpoints that are already returning errors.

**History.** Every run is saved to `~/.entropy/history.db`. In CI, Entropy will exit non-zero if it finds new issues compared to the previous run for the same target, which makes it usable as a regression gate.

---

## LLM backends

Entropy works with most LLM APIs. Set the relevant env var and pass `--llm <backend>`:

| Backend | Env var |
|---------|---------|
| `anthropic` | `ANTHROPIC_API_KEY` |
| `openai` | `OPENAI_API_KEY` |
| `gemini` | `GEMINI_API_KEY` |
| `mistral` | `MISTRAL_API_KEY` |
| `groq` | `GROQ_API_KEY` |
| `ollama` | *(no key — runs locally)* |
| `huggingface` | `HF_API_KEY` |
| `mock` | *(no key — deterministic, for CI/testing)* |

The `mock` backend generates realistic-looking attack scenarios without any API calls. It's what the test suite uses, and it's good enough to validate your pipeline setup before wiring in a real LLM.

---

## v0.3 features

### Endpoint discovery

If you don't have a spec file (or don't want to maintain one), pass `--discover`:

```bash
entropy run --target https://api.example.com --discover --live
```

It checks `robots.txt`, crawls linked JS files for `fetch()`/`axios` calls, probes 110+ common API paths, and looks for OpenAPI/Swagger specs at the usual locations. What it finds gets fed into the attack generation pipeline the same way a spec would.

```bash
# Just discovery, no fuzzing
entropy discover --target https://api.example.com
```

### Rate limit detection

```bash
# Runs automatically during a scan, or standalone:
entropy ratelimit --url https://api.example.com/login --max-probes 60
```

Sends requests until it hits a 429 (or exhausts the probe budget), then tests common bypass techniques: `X-Forwarded-For` rotation, `X-Real-IP`, path variations with trailing slashes. Missing rate limits are reported as HIGH; bypassable ones as CRITICAL.

### Differential testing

Compare two targets and find where they diverge:

```bash
entropy compare \
  --spec openapi.yaml \
  --target-a https://api.example.com/v1 \
  --target-b https://api.example.com/v2
```

Flags status code changes, removed response fields, and significant latency regressions. Useful for catching breaking changes before a release, or verifying that staging matches prod.

### Custom personas

The built-in personas cover general threat models. If you want to simulate something specific to your app:

```bash
entropy persona template > finance-insider.yaml
# edit it
entropy persona validate finance-insider.yaml
entropy run --spec api.yaml --custom-persona finance-insider.yaml --live
```

```yaml
name: finance-insider
auth_level: read_write
attack_focus:
  - privilege_escalation
  - idor
endpoints_whitelist:
  - /api/reports
  - /api/export
payload_overrides:
  role: admin
  is_admin: true
```

### Dashboard

```bash
entropy run --spec api.yaml --dashboard --live
# http://localhost:8080
```

Real-time findings feed via Server-Sent Events. No external JS dependencies.

### WebSocket fuzzing

```bash
entropy run --spec api.yaml --ws wss://api.example.com/ws --live
```

15 payloads covering injection, prototype pollution, oversized messages, and type confusion. Uses the stdlib `ssl`/`socket` — no `websockets` package required.

### Proxy integration

```bash
# Route through Burp Suite
entropy run --spec api.yaml --proxy http://127.0.0.1:8080 --no-verify-ssl --live

# Entropy as an intercepting proxy (mutates requests in flight)
entropy proxy --port 8888
```

### Watch mode

```bash
entropy run --spec api.yaml --watch --watch-interval 300 --live
entropy run --spec api.yaml --watch --watch-file api.yaml --live  # re-run on spec changes
```

---

## Output formats

```bash
entropy run --spec api.yaml --live                    # Markdown + JSON + HTML (default)
entropy run --spec api.yaml --sarif results.sarif --live  # SARIF for GitHub Code Scanning
```

All runs produce a Markdown summary, a machine-readable JSON report, and an HTML report with severity breakdowns. The JSON output is stable across versions.

---

## Scan profiles

```bash
entropy run --spec api.yaml --profile quick --live   # ~2min, critical only
entropy run --spec api.yaml --profile full  --live   # thorough, all personas
```

| Profile | Personas | Fail threshold | Use case |
|---------|----------|----------------|----------|
| `quick` | 2 | critical | Pre-commit / fast feedback |
| `standard` | 3 | high | PR gate (default) |
| `full` | 5 | high | Nightly / pre-release |
| `stealth` | 2 | critical | Low-noise prod testing |
| `ci` | 3 | high | CI pipelines |

---

## CI integration

### GitHub Actions

```yaml
- name: Install entropy
  run: pip install entropy-chaos

- name: Run scan
  run: |
    entropy run \
      --spec openapi.yaml \
      --target ${{ env.API_URL }} \
      --llm anthropic \
      --profile ci \
      --sarif results.sarif \
      --live
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}

- name: Upload to Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

### GitLab CI

```yaml
entropy:
  image: python:3.11
  script:
    - pip install entropy-chaos
    - entropy run --spec openapi.yaml --target $API_URL --llm groq --profile ci --live
  artifacts:
    reports:
      junit: entropy-report/junit.xml
```

---

## Configuration file

Rather than passing flags every time, drop an `entropy.yml` in your project root:

```bash
entropy run                        # picks up entropy.yml automatically
entropy run --config path/to/entropy.yml
```

```yaml
target: http://localhost:8000
spec: openapi.yaml

llm:
  backend: anthropic

scan:
  live: true
  profile: standard
  baseline_diff: true
  rate_limit_check: true

output:
  dir: entropy-report
  sarif: results.sarif
  fail_on: high

# alerts:
#   slack_webhook: https://hooks.slack.com/...
```

Generate a fully-commented template:

```bash
entropy report config-template > entropy.yml
```

---

## All commands

```
entropy run        Run a scan
entropy compare    Compare two targets (v1 vs v2, prod vs staging)
entropy discover   Probe a target for endpoints without a spec
entropy ratelimit  Test rate limiting on a specific URL
entropy history    Browse previous runs (list / trend / compare)
entropy persona    Manage custom personas (template / validate)
entropy shell      Interactive REPL
entropy proxy      HTTP interception proxy
entropy backends   List available LLM backends
entropy profiles   List scan profiles
entropy owasp      List OWASP Top 10 scenarios
```

Full flag reference: `entropy run --help`

---

## License

MIT — see [LICENSE](LICENSE).

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md)

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).
