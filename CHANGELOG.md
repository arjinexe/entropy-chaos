# Changelog

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
