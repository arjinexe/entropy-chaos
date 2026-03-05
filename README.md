<div align="center">

# entropy

API security testing with LLM-generated attack scenarios

[![PyPI](https://badge.fury.io/py/entropy-chaos.svg)](https://pypi.org/project/entropy-chaos/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-177%20passing-brightgreen)](#)

</div>

Most API scanners run through a fixed list of known patterns — SQLi payloads, OWASP wordlists, common headers. They're decent at catching what they already know about. What they miss is the logic that's specific to your API: the checkout flow that accepts a negative quantity, the admin endpoint that blocks GET but not POST, the WebSocket handler that falls over on a prototype pollution payload.

Entropy hands your API schema to an LLM and asks it to think like an attacker. It generates multi-step attack sequences based on your actual endpoints and data models, runs them, diffs the responses against a clean baseline, and only surfaces the ones that look like real issues.

Works with OpenAPI specs, GraphQL schemas, or nothing at all — it can crawl the target and figure out the endpoints itself.

---

## Install

```bash
pip install entropy-chaos
```

Python 3.10+ required. Only hard dependency is PyYAML.

---

> ### ⚠️ `--live` flag — read this first
>
> **By default, entropy runs in dry-run / simulation mode. No HTTP requests are sent to your target. All findings are simulated.**
>
> To actually scan something, you need `--live`:
>
> ```bash
> # This does nothing real — simulated output only
> entropy run --target https://api.example.com --discover
>
> # This actually scans
> entropy run --target https://api.example.com --discover --live
> ```
>
> The terminal output says `Mode : DRY RUN (simulation)` when live is off. If you see that line, your target has not been touched.

---

## Basic usage

```bash
# Dry run — safe to run anywhere, no requests sent
entropy run --spec openapi.yaml --target http://localhost:8000

# Live scan — actually sends requests
entropy run --spec openapi.yaml --target http://localhost:8000 --live

# No spec — discover endpoints automatically, then scan
entropy run --target https://api.example.com --discover --live

# Full scan with a real LLM backend
entropy run --spec api.yaml --llm anthropic --profile full --live
# ANTHROPIC_API_KEY is read from the environment
```

---

## How it works

**Attack generation.** Entropy parses your schema, maps out the data model and auth structure, then sends it to an LLM with the instruction to think adversarially. The output isn't just a list of payloads — it's multi-step attack chains like "authenticate as user A, grab the session token, then try to pull user B's data with it."

**Personas.** Five attacker archetypes run in parallel:

| Persona | What it tests |
|---------|---------------|
| `malicious_insider` | Authenticated abuse — IDOR, mass assignment, privilege escalation |
| `impatient_consumer` | Timing issues — race conditions, double-spend, retry loops |
| `bot_swarm` | Volume-based issues — rate limiting, resource exhaustion |
| `confused_user` | Edge cases — type confusion, state machine bypasses, unexpected inputs |
| `penetration_tester` | Classic vulns — injection, auth bypass, SSRF, XXE |

**Baseline diffing.** Before each attack, entropy sends a normal request to the same endpoint and records the response. A finding only gets flagged if the attack response meaningfully differs — different status code, new fields, latency spike. This cuts the noise from endpoints that were already broken before you touched them.

**History.** Every run writes to `~/.entropy/history.db`. In CI, entropy exits non-zero when it finds issues that weren't there in the last run — useful as a regression gate.

---

## LLM backends

Set the relevant env var, pass `--llm <backend>`:

| Backend | Env var |
|---------|---------|
| `anthropic` | `ANTHROPIC_API_KEY` |
| `openai` | `OPENAI_API_KEY` |
| `gemini` | `GEMINI_API_KEY` |
| `mistral` | `MISTRAL_API_KEY` |
| `groq` | `GROQ_API_KEY` |
| `ollama` | *(runs locally, no key)* |
| `huggingface` | `HF_API_KEY` |
| `mock` | *(no key — deterministic output, good for CI/pipeline testing)* |

`mock` generates plausible-looking attack scenarios without hitting any API. The test suite uses it. It's enough to verify your pipeline works before plugging in a real backend.

> **Note on `--llm mock`:** Mock still sends real HTTP requests when `--live` is set — it just uses pre-generated attack payloads instead of LLM-generated ones. Results are less targeted but the scan is real.

---

## v0.4 features

### SSRF detection

Looks for parameters that take URLs (`url`, `callback`, `redirect`, `webhook`, `src`, etc.) and injects internal addresses — AWS EC2 metadata endpoint (`169.254.169.254`), GCP metadata, Azure IMDS, RFC1918 gateway ranges. Confirms when the server actually returns cloud metadata in the response.

### SSTI detection

Tests string parameters with arithmetic probes across nine template engine dialects. `{{7*7}}` returning `49` confirms Jinja2 or Twig. `${7*7}` confirms FreeMarker or Spring EL. FreeMarker RCE chains get escalated to CRITICAL automatically.

### XXE detection

Sends `<!ENTITY xxe SYSTEM "file:///etc/passwd">` payloads to any endpoint taking POST/PUT/PATCH. Covers standard XML bodies, SVG upload vectors, and parameter entity variants. Detects file content leaking into responses.

### JWT security testing

Pulls JWT tokens out of scan responses and throws a few things at them: `alg:none` bypass, weak HMAC secret brute-force (30 common secrets), claim tampering for privilege escalation, expired token acceptance, missing `exp` checks. If a secret cracks, it shows up verbatim in the finding.

### HTTP Request Smuggling

Timing-based CL.TE and TE.CL detection. Sends ambiguous requests and watches for latency delta vs a clean baseline. A gap over 4 seconds suggests the backend is stalling on a smuggled prefix. Needs `--live` and `--smuggling`:

```bash
entropy run --target https://api.example.com --smuggling --live
```

### Parameter mining

Probes 80+ undocumented parameter names concurrently and flags anything that changes the response status, body size, or adds new fields. High-value targets get priority: `admin`, `debug`, `is_admin`, `bypass`, `role`, `eval`.

### Multi-step IDOR chain testing

Finds endpoints with numeric path segments and walks sequential ID ranges. Flags responses that return sensitive fields (email, balance, token, medical records) for IDs the caller shouldn't be able to access.

### Adaptive LLM false-positive filtering

After the scan finishes, each finding goes back to the LLM with the full request/response context. The LLM decides whether the evidence actually supports the finding or not. Filtered count shows up in the summary. Turn it off with `--no-adaptive`.

---

## v0.3 features

### Endpoint discovery

No spec file? Pass `--discover`:

```bash
entropy run --target https://api.example.com --discover --live
```

Checks `robots.txt`, crawls linked JS for `fetch()` and `axios` calls, probes 180+ common API paths (PHP apps, Spring Boot actuators, Django debug views), and sniffs for OpenAPI/Swagger specs at the usual locations. Runs concurrently.

```bash
# Discovery only, no fuzzing
entropy discover --target https://api.example.com
```

### Rate limit detection

```bash
entropy ratelimit --url https://api.example.com/login --max-probes 60
```

Fires requests until it hits a 429 or runs out of budget, then tests bypass techniques: `X-Forwarded-For` rotation, `X-Real-IP`, trailing slash path variants. Missing rate limits come out as HIGH; bypassable ones as CRITICAL. Also runs automatically during a full scan.

### Differential testing

```bash
entropy compare \
  --spec openapi.yaml \
  --target-a https://api.example.com/v1 \
  --target-b https://api.example.com/v2
```

Finds where two targets diverge — status code changes, dropped response fields, latency regressions. Good for checking staging against prod or catching breaking changes before a release.

### Custom personas

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

Live findings feed over Server-Sent Events. No external JS dependencies.

### WebSocket fuzzing

```bash
entropy run --spec api.yaml --ws wss://api.example.com/ws --live
```

15 payloads across injection, prototype pollution, oversized messages, and type confusion. Uses stdlib `ssl`/`socket` — no extra packages needed.

### Proxy integration

```bash
# Send traffic through Burp Suite
entropy run --spec api.yaml --proxy http://127.0.0.1:8080 --no-verify-ssl --live

# Run entropy itself as an intercepting proxy
entropy proxy --port 8888
```

### Watch mode

```bash
entropy run --spec api.yaml --watch --watch-interval 300 --live
entropy run --spec api.yaml --watch --watch-file api.yaml --live
```

---

## Output formats

```bash
entropy run --spec api.yaml --live                        # Markdown + JSON + HTML
entropy run --spec api.yaml --sarif results.sarif --live  # SARIF for GitHub Code Scanning
```

Every run writes a Markdown summary, a JSON report, and an HTML report with severity breakdowns. JSON schema is stable across versions.

---

## Scan profiles

```bash
entropy run --spec api.yaml --profile quick --live   # ~2min, critical findings only
entropy run --spec api.yaml --profile full  --live   # everything, all personas
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

Drop an `entropy.yml` in your project root instead of passing flags every time:

```bash
entropy run                         # picks up entropy.yml automatically
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

Generate a commented template:

```bash
entropy report config-template > entropy.yml
```

---

## Commands

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
