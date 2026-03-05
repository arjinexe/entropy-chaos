# Changelog

---

## 0.4.3

Patch release: CI stability, HTML report correctness, and scan performance.

### Bug fixes

**CI: Python 3.11 test job blocked by SARIF action resolution** — The `github/codeql-action/upload-sarif` step was inside the `test` matrix job. When GitHub's action-download service returned `503 Service Unavailable` during job setup, the entire Python 3.11 job failed—even the actual tests. The SARIF upload now runs in a separate `sarif-upload` job (`continue-on-error: true`) that downloads the `.sarif` artifact produced by the test job. The test matrix no longer references CodeQL and is unaffected by transient GitHub infrastructure issues.

**HTML report: findings hidden when payloads contain HTML special characters** — Finding titles, descriptions, endpoints, and HTTP bodies were inserted into the HTML template as raw strings. Payloads such as `<script>alert(1)</script>` or SQL strings containing `<`, `>`, and `"` broke the document structure, causing most finding cards to be invisible and detail expansion to silently fail. All user-supplied strings are now escaped with `html.escape()` before insertion.

### Performance

**Scan wall-clock timeout** — A new `max_scan_minutes` config option (default `45`, CLI flag `--max-scan-minutes`) stops the scan loop after the configured number of minutes and proceeds directly to reporting. Previously a large target like OWASP Juice Shop could run for 49+ minutes without bound.

**Rate-limit probe count halved** — `rate_limit_max_probes` default reduced from `50` to `20`. The detection threshold is reliably hit within 20 requests for every common implementation; the extra 30 probes only added latency.

---


Maintenance release. Bug fixes, test hardening, and packaging improvements.

### Bug fixes

**CI release notes extraction** — The GitHub Actions workflow used `## [VERSION]` bracket syntax in the `awk` pattern but the CHANGELOG uses plain `## VERSION` headings. The pattern now matches the actual file format so release notes are correctly extracted on tag pushes.

**Version consistency** — All version strings (`pyproject.toml`, `entropy/__init__.py`) are now kept in sync as part of the release checklist. The `--version` flag output matches the published PyPI version.

### Developer experience

- `python tests/test_entropy.py` continues to be the zero-dependency test runner; all 177 tests pass on Python 3.10, 3.11, and 3.12.
- `twine check dist/*` passes cleanly; long-description renders correctly on PyPI.

---

## 0.4.1

Packaging and metadata fixes.

Corrected `pyproject.toml` classifier list and added missing `py.typed` marker to ensure the package is recognised as typed by mypy and pyright. Optional dependency group `full` now pins `websockets>=12.0` correctly. No functional changes.

---

## 0.4.0

Major detection expansion. Seven new attack modules, adaptive LLM false-positive filtering, parameter mining, and multi-step IDOR chain testing.

### New attack modules

**SSRF detection** (`entropy/fuzzing/ssrf.py`) — Identifies URL-like parameters (`url`, `callback`, `redirect`, `webhook`, etc.) and injects internal/cloud-metadata targets (AWS IMDSv2, GCP metadata, Azure IMDS, RFC1918 ranges). Confirms exploitation when response contains metadata markers.

**SSTI detection** (`entropy/fuzzing/ssti.py`) — Probes string parameters with arithmetic payloads across nine template engine dialects: Jinja2, Twig, FreeMarker, Velocity, Smarty, Thymeleaf, ERB, Pebble, Spring EL. Confirms when the engine evaluates `{{7*7}}` → `49`. FreeMarker RCE chains escalate to CRITICAL.

**XXE detection** (`entropy/fuzzing/xxe.py`) — Sends XML payloads with external entity declarations to POST/PUT/PATCH endpoints. Covers classic LFI, SVG upload vectors, and parameter entity variants. Detects `/etc/passwd` and `win.ini` content in responses.

**JWT security testing** (`entropy/fuzzing/jwt_tester.py`) — Analyses JWT tokens extracted from scan responses and tests: `alg:none` bypass, weak HMAC secret brute-force (30 common secrets), claim tampering, expired-token acceptance, and missing `exp` claim. Reports cracked secrets verbatim.

**HTTP Request Smuggling** (`entropy/fuzzing/smuggling.py`) — CL.TE and TE.CL timing-based detection. Compares request latency against a baseline; a delta >4 seconds indicates the back-end is waiting for a smuggled request. Off by default (timing-sensitive), enable with `--smuggling`.

**Parameter mining** (`entropy/fuzzing/param_miner.py`) — Probes 80+ undocumented parameter names in batches (concurrent) and flags any that change the response status, body length, or introduce new response fields. Prioritises high-value targets: `admin`, `debug`, `bypass`, `role`, `is_admin`.

**Multi-step IDOR chain testing** (`entropy/fuzzing/idor_chain.py`) — Finds resource endpoints with numeric path parameters and probes sequential IDs. Flags when a response contains sensitive fields (email, balance, token, etc.) for IDs the requester doesn't own.

### Adaptive LLM false-positive filtering

A new post-processing step (`entropy/fuzzing/adaptive_analyser.py`) sends each finding — along with its full request/response context — to the configured LLM and asks whether the evidence actually supports the finding. False positives are filtered out before the report is written. The number of rejected findings is logged and included in `report.stats`. Budget defaults to 20 findings per run (`--adaptive-budget`). Disable with `--no-adaptive`.

### Other improvements

New CLI flags: `--ssrf`, `--ssti`, `--xxe`, `--jwt`, `--smuggling`, `--no-param-mining`, `--no-idor-chain`, `--no-adaptive`.

MockLLM now handles adaptive analysis prompts with context-aware verdicts (confirms SQL error responses, rejects 400 responses).

Three new `FindingType` values: `SSTI`, `SMUGGLING`, `PARAMETER_POLLUTION`.

SARIF OWASP tag mapping extended to cover all new finding types.

177 tests, all passing.

---

## 0.3.4

Bug fixes and detection improvements.

The `--discover` flag was silently ignored due to a comment-out typo in the CLI argument handler — auto-discovery now works correctly when passed on the command line.

Shell `history` command crashed with an `AttributeError` because it accessed `run.run_id` instead of the correct `run.id` field. Fixed.

`asyncio.run()` was called inside a synchronous for-loop, which raises `RuntimeError` when an event loop is already running (e.g. Jupyter, async test runners). Replaced with a safe loop-detection pattern that falls back to a thread pool.

Rate limit detector now respects the `--rate-limit-probes` value passed by the user instead of always defaulting to 60.

Seven new anomaly detection rules:
- **SQL Injection** — recognises MySQL, PostgreSQL, and Oracle error strings in responses
- **XSS Reflection** — flags injected script tags echoed verbatim without encoding
- **Path Traversal / LFI** — detects `/etc/passwd` and Windows file content in responses
- **Information Disclosure** — catches PHP fatal errors, Java stack traces, and framework debug output
- **Command Injection** — identifies OS command output (`uid=`, `drwxr`, etc.) in responses
- **Open Redirect** — flags `Location` headers pointing to external domains after URL injection
- **Auth Bypass via HTTP Method** — detects endpoints that 401 on GET but accept POST

Active discovery wordlist expanded from ~50 to 100+ paths, including PHP application patterns, Spring Boot, Django, and debug leak locations. Path probing is now concurrent (up to 20 threads) so large sites are scanned significantly faster.

SARIF tool version updated to match package version.

---

## 0.3.0

Spec-free scanning. You can now point entropy at a target with no OpenAPI file and it'll figure out what endpoints exist on its own — crawls robots.txt, mines JS files for fetch/axios calls, probes common paths, checks the usual swagger locations.

Baseline diffing is on by default. Before sending a fuzz payload, entropy records a normal response to the same endpoint. Only reports something as a finding if the attack response actually differs. Cuts out most of the noise.

Run history is now persisted to `~/.entropy/history.db`. In CI this means entropy can tell you whether a finding is new or was already known from the last run. Useful for keeping a regression gate from crying wolf.

Rate limit detection got added as a dedicated step — probes each endpoint until it hits a 429 or runs out of budget, then tests common bypass headers (X-Forwarded-For, X-Real-IP, etc). Missing limits are HIGH; bypassable ones are CRITICAL.

Differential testing: `entropy compare --target-a ... --target-b ...` sends identical requests to two targets and flags divergences. Mostly useful for v1 vs v2 or prod vs staging before a deploy.

Other additions: live dashboard (`--dashboard`), watch mode (`--watch`), WebSocket fuzzing (`--ws`), SARIF output (`--sarif`), Burp proxy support (`--proxy`), interception proxy mode (`entropy proxy`), custom persona YAML (`--custom-persona`), interactive shell (`entropy shell`), `--no-verify-ssl`.

Config file support was updated to handle all of the above. `entropy.yml` now covers everything you can pass on the command line.

---

## 0.2.0

Added 8 LLM backends (Anthropic, OpenAI, Gemini, Mistral, Groq, Ollama, HuggingFace, mock). GraphQL SDL and introspection JSON support alongside OpenAPI. Five attacker personas: malicious insider, impatient consumer, bot swarm, confused user, penetration tester. OWASP Top 10 scenario library, CVSS v3.1 scoring. HTML/Markdown/JSON/JUnit report formats. Docker sandbox for isolated live testing. GitHub Actions and GitLab CI integration templates. Auth manager handling JWT, API keys, and credential pools. 56 tests.

---

## 0.1.0

Initial release. OpenAPI 3 parsing, mock LLM, single persona, Markdown report.
