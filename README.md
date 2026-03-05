<div align="center">

# entropy

API security testing with LLM-generated attack scenarios

[![PyPI](https://badge.fury.io/py/entropy-chaos.svg)](https://pypi.org/project/entropy-chaos/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-128%20passing-brightgreen)](#)
[![CI](https://github.com/arjinexe/entropy-chaos/actions/workflows/ci.yml/badge.svg)](https://github.com/arjinexe/entropy-chaos/actions)

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

## Quick start

```bash
# Simulate attacks without sending real requests (safe to run anywhere)
entropy run --spec openapi.yaml --target http://localhost:8000

# Actually send the requests
entropy run --spec openapi.yaml --target http://localhost:8000 --live

# No spec file — let it discover endpoints on its own
entropy run --target https://api.example.com --discover --live

# Use a real LLM for smarter attack generation
entropy run --spec api.yaml --llm anthropic --live
# ANTHROPIC_API_KEY is picked up from the environment automatically
```

---

## How it works

**Attack generation.** Entropy parses your schema, builds a picture of the API's data model and authentication structure, then prompts an LLM to generate attack sequences. The LLM output isn't just payloads — it's multi-step scenarios ("authenticate as user A, then try to access user B's resource using the session token from step 1").

**Personas.** Five attacker archetypes run in parallel, each with different threat models:

| Persona | What it tests |
|---------|---------------|
| `malicious_insider` | Authenticated abuse — IDOR, mass assignment, privilege escalation, negative values |
| `impatient_consumer` | Timing issues — race conditions, double-spend, retry loops |
| `bot_swarm` | Volume-based issues — rate limiting, resource exhaustion (capped at 10 concurrent) |
| `confused_user` | Edge cases — type confusion, state machine bypasses, unexpected inputs |
| `penetration_tester` | Classic vulns — SQLi, XSS, SSTI, path traversal, auth bypass |

**Baseline diffing.** Before sending an attack payload, Entropy sends a normal request to the same endpoint and records the response. Findings are only flagged when the attack response meaningfully differs from the baseline — different status code, new fields in the body, significant latency increase. This cuts out most of the noise.

**History.** Every run is saved to `~/.entropy/history.db`. In CI, Entropy will exit non-zero if it finds new issues compared to the previous run for the same target, making it usable as a regression gate.

---

## LLM backends

Entropy works with most LLM APIs. Set the relevant env var and pass `--llm <backend>`:

| Backend | Env var | Notes |
|---------|---------|-------|
| `anthropic` | `ANTHROPIC_API_KEY` | Best results |
| `openai` | `OPENAI_API_KEY` | GPT-4o recommended |
| `gemini` | `GEMINI_API_KEY` | |
| `mistral` | `MISTRAL_API_KEY` | |
| `groq` | `GROQ_API_KEY` | Fast, free tier available |
| `ollama` | *(no key — runs locally)* | `ollama pull llama3` first |
| `huggingface` | `HF_API_KEY` | |
| `mock` | *(no key — deterministic)* | For CI/testing only |

> **Note on `mock` backend:** The mock LLM generates fixed, pre-written attack payloads without understanding your specific API. It's useful for CI pipeline validation and smoke-testing, but will miss business-logic bugs that require contextual understanding. For real security testing, use `--llm anthropic` or `--llm openai`.

---

## Endpoint discovery

If you don't have a spec file, pass `--discover`. The crawler:

- Checks `robots.txt` and `sitemap.xml`
- Probes 200+ common API paths (including PHP-specific paths)
- **Follows HTML links recursively** (depth-limited)
- **Extracts `<form>` actions and `<input>` names** to find POST endpoints
- **Discovers query parameters** from linked URLs (e.g. `?cat=1&page=2`)
- Mines JS files for `fetch()`/`axios` calls
- Looks for OpenAPI/Swagger specs at standard locations

```bash
entropy run --target https://api.example.com --discover --live

# Just discovery, no fuzzing
entropy discover --target https://api.example.com
```

For PHP/legacy sites with HTML forms, discovery works best with `--verbose` to see what's found:

```bash
entropy run --target http://testphp.vulnweb.com --discover --live --verbose
```

---

## Testing against practice targets

These are publicly available sites intended for security tool testing:

```bash
# Acunetix test PHP app (deliberately vulnerable)
entropy run --target http://testphp.vulnweb.com --discover --llm mock --live --no-rate-limit-check

# IBM demo banking app
entropy run --target http://demo.testfire.net --discover --llm mock --live --no-rate-limit-check

# Local: OWASP Juice Shop (Docker)
docker run -d -p 3000:3000 bkimminich/juice-shop
entropy run --target http://localhost:3000 --discover --llm mock --live --profile full
```

> **Legal reminder:** Only test targets you own or have explicit written permission to test. Unauthorised testing is illegal regardless of the target's apparent vulnerability.

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

## Output formats

```bash
entropy run --spec api.yaml --live                        # Markdown + JSON + HTML (default)
entropy run --spec api.yaml --sarif results.sarif --live  # SARIF for GitHub Code Scanning
entropy run --spec api.yaml --junit junit.xml --live      # JUnit XML for CI systems
```

Reports are saved to the `entropy-report/` directory by default. Change with `--output`.

---

## Useful flags

| Flag | Default | Description |
|------|---------|-------------|
| `--live` | off | Send real HTTP requests (default is dry-run simulation) |
| `--discover` | off | Auto-discover endpoints instead of using a spec file |
| `--profile` | standard | Scan profile: quick / standard / full / stealth / ci |
| `--llm` | mock | LLM backend to use for attack generation |
| `--fail-on` | high | Exit 1 if findings at this severity or above: critical/high/medium/low/none |
| `--no-history` | off | Skip saving run to history DB (useful for one-off tests) |
| `--no-rate-limit-check` | off | Skip rate limit detection (faster, less noise) |
| `--no-baseline` | off | Skip baseline diffing |
| `--concurrency` | 10 | Max concurrent requests |
| `--timeout` | 10.0 | Request timeout in seconds |
| `--retries` | 3 | Retry failed requests with backoff |
| `--proxy` | — | Route through a proxy (e.g. `http://127.0.0.1:8080` for Burp) |
| `--no-verify-ssl` | off | Disable TLS verification |
| `--verbose` | off | Print every request/response |
| `--output` | entropy-report | Output directory for reports |
| `--sarif` | — | Also write SARIF report to this path |
| `--junit` | — | Also write JUnit XML to this path |

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
      --no-history \
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
    - entropy run --spec openapi.yaml --target $API_URL --llm groq --profile ci --no-history --live
  artifacts:
    reports:
      junit: entropy-report/junit.xml
```

---

## Configuration file

Rather than passing flags every time, drop an `entropy.yml` in your project root:

```bash
entropy run                          # picks up entropy.yml automatically
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

## v0.3 features

### Rate limit detection

```bash
entropy ratelimit --url https://api.example.com/login --max-probes 60
```

Sends requests until it hits a 429, then tests common bypass techniques: `X-Forwarded-For` rotation, `X-Real-IP`, path variations. Missing rate limits are reported as HIGH; bypassable ones as CRITICAL.

### Differential testing

```bash
entropy compare \
  --spec openapi.yaml \
  --target-a https://api.example.com/v1 \
  --target-b https://api.example.com/v2
```

Flags status code changes, removed fields, and latency regressions. Useful for staging vs prod verification.

### Custom personas

```bash
entropy persona template > finance-insider.yaml
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

Real-time findings feed via Server-Sent Events.

### WebSocket fuzzing

```bash
entropy run --spec api.yaml --ws wss://api.example.com/ws --live
```

15 payloads covering injection, prototype pollution, oversized messages, type confusion.

### Proxy integration

```bash
# Route through Burp Suite
entropy run --spec api.yaml --proxy http://127.0.0.1:8080 --no-verify-ssl --live

# Entropy as an intercepting proxy
entropy proxy --port 8888
```

### Watch mode

```bash
entropy run --spec api.yaml --watch --watch-interval 300 --live
entropy run --spec api.yaml --watch --watch-file api.yaml --live
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

## Troubleshooting

**Scan takes too long**
Add `--no-rate-limit-check` and reduce `--concurrency 3`. The `quick` profile is also faster.

**Too many false positives**
Use `--fail-on critical` or `--profile stealth` to reduce noise.

**Only 2 endpoints discovered**
Use `--verbose` to see what the crawler finds. For JS-heavy SPAs, consider providing an OpenAPI spec directly. For PHP sites, discovery should find form-based endpoints automatically.

**History regression warnings on every run**
Add `--no-history` for ad-hoc testing. History tracking is designed for CI where the same target is scanned repeatedly.

**SSL errors**
Add `--no-verify-ssl` for self-signed certificates.

---

## License

MIT — see [LICENSE](LICENSE).

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md)

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).
