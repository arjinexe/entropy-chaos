# Contributing

## Setup

```bash
git clone https://github.com/yourusername/entropy-chaos
cd entropy-chaos
pip install -e ".[dev]"
python tests/test_entropy.py
```

Tests don't need a running API or any API keys — the mock LLM backend handles everything.

## Where things live

```
entropy/core/          models, config, orchestrator, attack tree, parser
entropy/llm/           LLM backends
entropy/personas/      attacker archetypes
entropy/fuzzing/       HTTP executor, logical fuzzer, baseline diff, rate limit, differential
entropy/reporting/     Markdown, HTML, JSON, SARIF, CVSS
entropy/discovery/     endpoint crawler
entropy/history/       SQLite run persistence
entropy/web/           live dashboard
entropy/proxy/         interception proxy
entropy/websocket/     WebSocket fuzzer
entropy/scenarios/     OWASP attack library
```

## Adding a new LLM backend

Subclass `BaseLLM` in `entropy/llm/backends.py`, implement `complete(prompt, system="") -> str`, add it to `_BACKEND_MAP` and `_BACKEND_DEFAULTS`. Add an alias test in `test_create_llm_aliases`.

## Adding a new persona

Subclass `BasePersona` in `entropy/personas/engine.py`, implement `build_request_sequence(vector)`, add a `PersonaType` enum value in `entropy/core/models.py`, register it in `_PERSONA_MAP`. The persona gets picked up automatically by the orchestrator.

## Adding anomaly rules

Add a class to `entropy/fuzzing/executor.py` extending `AnomalyRule`, implement `check(req, resp, context) -> bool`.

## Tests

All new code needs a test. The test runner is standalone — no pytest required, though it works with pytest too:

```bash
python tests/test_entropy.py
# or
pytest tests/ -v
```

New modules should get unit tests covering the main paths and at least one integration test through the orchestrator if applicable.

## PRs

Fork, branch off main, open a PR. Tests must pass. If the change affects CLI behaviour or config file syntax, update the README.
