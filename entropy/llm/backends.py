""""LLM backend abstraction — mock, Anthropic, OpenAI, Gemini, Ollama, and more."""
from __future__ import annotations

import json
import random
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class BaseLLM(ABC):

    @abstractmethod
    def complete(self, prompt: str, system: str = "") -> str:
        pass

    def complete_json(self, prompt: str, system: str = "") -> Any:
        raw   = self.complete(prompt, system)
        clean = re.sub(r"^```(?:json)?\s*", "", raw.strip())
        clean = re.sub(r"\s*```$", "", clean.strip())
        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            match = re.search(r"(\{.*\}|\[.*\])", clean, re.DOTALL)
            if match:
                return json.loads(match.group(1))
            raise ValueError(f"LLM did not return valid JSON:\n{raw[:500]}")

    @staticmethod
    def _post_json(url: str, payload: dict, headers: dict, timeout: int = 120) -> dict:
        import urllib.request, urllib.error
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            raise RuntimeError(f"HTTP {exc.code} from {url}: {body[:400]}") from exc


# ---------------------------------------------------------------------------
# 1. Mock LLM
# ---------------------------------------------------------------------------

class MockLLM(BaseLLM):
    """Offline deterministic mock — ideal for CI and development."""

    _LOGIC_ATTACKS = [
        {"name": "Double-spend coupon",         "description": "Apply the same discount coupon twice before server validates.",             "payload_hints": ["coupon_code","discount_id"],           "anomaly": "Discount applied multiple times."},
        {"name": "Negative quantity order",     "description": "Submit order with quantity=-1 to attempt credit injection.",              "payload_hints": ["quantity","amount","count"],            "anomaly": "Server credits account instead of charging."},
        {"name": "Price tampering",             "description": "Modify unit_price in request body to an arbitrary low value.",            "payload_hints": ["price","unit_price","total"],           "anomaly": "Server accepts client-supplied price."},
        {"name": "Unauthorized resource access","description": "Replace own user_id with another user's ID in path/query.",              "payload_hints": ["user_id","account_id","order_id","id"], "anomaly": "IDOR: response contains another user's data."},
        {"name": "JWT algorithm confusion",     "description": "Change JWT header alg to 'none' and remove signature.",                  "payload_hints": ["Authorization","token","jwt"],          "anomaly": "Server accepts unsigned token."},
        {"name": "Mass assignment injection",   "description": "Add privileged fields (is_admin, role) to request body.",                "payload_hints": ["role","is_admin","permissions"],        "anomaly": "Server persists privileged fields."},
        {"name": "Race condition voucher",      "description": "Send 50 concurrent requests to claim a one-time-use voucher.",           "payload_hints": ["voucher","promo_code"],                 "anomaly": "Resource claimed multiple times."},
        {"name": "State machine bypass",        "description": "Skip intermediate steps by calling the final endpoint directly.",        "payload_hints": ["status","state","step"],                "anomaly": "Invalid state transition accepted."},
        {"name": "Insecure deserialization",    "description": "Send crafted serialized object to trigger server-side issues.",          "payload_hints": ["data","payload","object"],              "anomaly": "Server deserializes untrusted input."},
        {"name": "GraphQL introspection leak",  "description": "Query __schema to enumerate all types and mutations.",                   "payload_hints": ["query","__schema","__type"],            "anomaly": "Full schema exposed."},
    ]

    _FUZZ_PAYLOADS: Dict[str, List[Any]] = {
        "string":  ["", " "*10000, "' OR '1'='1", "<script>alert(1)</script>", "../../../../etc/passwd", "\x00\x00", "A"*65536, "${7*7}", "{{7*7}}", "; ls -la", "UNION SELECT NULL--"],
        "integer": [0, -1, -9999999, 2**31-1, 2**31, 2**63, 0.1, "NaN", "Infinity"],
        "boolean": [True, False, 0, 1, "true", "false", "yes", "no", None],
        "object":  [None, [], "", 0, {"$gt":""}, {"__proto__":{"admin":True}}],
        "array":   [None, {}, "", [None]*100, [{"$where":"1==1"}]],
    }

    _REMEDIATION = {
        "logic_error":    "Implement server-side validation. Never trust client-supplied pricing, quantities, or authorization decisions.",
        "race_condition": "Use database-level locking (SELECT FOR UPDATE) or idempotency keys.",
        "auth_bypass":    "Validate JWT signatures server-side with a fixed algorithm. Never accept 'alg: none'.",
        "injection":      "Use parameterized queries. Apply strict input validation with allowlists.",
        "crash":          "Add global exception handlers. Implement rate limiting and request-size limits.",
        "data_leak":      "Enforce object-level authorization on every data retrieval endpoint.",
        "business_logic": "Model all valid state transitions explicitly. Reject invalid states.",
        "performance":    "Add rate limiting, request timeouts, and circuit breakers.",
    }

    def __init__(self, seed: int = 42):
        random.seed(seed)

    def complete(self, prompt: str, system: str = "") -> str:
        p = prompt.lower()
        if "attack tree" in p or "attack node" in p:
            return self._mock_attack_tree(prompt)
        if "fuzz payload" in p or "payload" in p:
            return self._mock_fuzz_payloads(prompt)
        if "remediation" in p or "fix" in p or "mitigat" in p:
            return self._mock_remediation(prompt)
        if "persona" in p or "behavior" in p or "behaviour" in p:
            return self._mock_persona_strategy(prompt)
        if "report" in p or "summary" in p or "executive" in p:
            return self._mock_report_summary(prompt)
        if "cvss" in p or "score" in p:
            return json.dumps({"cvss_score": round(random.uniform(4.0, 9.9), 1), "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
        return json.dumps({"message": "Mock LLM response", "prompt_received": prompt[:120]})

    def _mock_attack_tree(self, prompt: str) -> str:
        endpoints = re.findall(r'(GET|POST|PUT|PATCH|DELETE)\s+(/[\w/{}/]+)', prompt.upper())
        attacks   = random.sample(self._LOGIC_ATTACKS, min(4, len(self._LOGIC_ATTACKS)))
        nodes = []
        for i, attack in enumerate(attacks):
            ep = endpoints[i % len(endpoints)] if endpoints else ("POST", "/api/resource")
            nodes.append({
                "id": f"node_{i}", "name": attack["name"], "goal": attack["description"],
                "severity": random.choice(["critical","high","medium"]),
                "endpoint": f"{ep[0]} {ep[1]}",
                "vectors": [{"description": attack["description"], "payload_hints": attack["payload_hints"], "expected_anomaly": attack["anomaly"]}],
            })
        return json.dumps({"attack_nodes": nodes})

    def _mock_fuzz_payloads(self, prompt: str) -> str:
        ptype = "string"
        for t in ("integer","boolean","object","array"):
            if t in prompt.lower():
                ptype = t
                break
        pool = self._FUZZ_PAYLOADS.get(ptype, self._FUZZ_PAYLOADS["string"])
        return json.dumps({"payloads": random.sample(pool, min(5, len(pool))), "type": ptype})

    def _mock_remediation(self, prompt: str) -> str:
        for key, text in self._REMEDIATION.items():
            if key in prompt.lower():
                return json.dumps({"remediation": text})
        return json.dumps({"remediation": "Apply defense-in-depth: validate all inputs server-side, enforce least-privilege, and add comprehensive audit logging."})

    def _mock_persona_strategy(self, prompt: str) -> str:
        strategies = {
            "malicious_insider":  {"behavior": "Uses valid credentials but attempts to access resources beyond their role.", "concurrency": 1,   "delay_ms": 500},
            "impatient_consumer": {"behavior": "Rapidly retries, double-submits forms, ignores rate limits.",               "concurrency": 10,  "delay_ms": 50},
            "bot_swarm":          {"behavior": "Hundreds of concurrent requests targeting limited resources.",               "concurrency": 100, "delay_ms": 10},
            "confused_user":      {"behavior": "Sends malformed, out-of-order requests.",                                   "concurrency": 1,   "delay_ms": 200},
        }
        for persona, strategy in strategies.items():
            if persona in prompt.lower():
                return json.dumps(strategy)
        return json.dumps(list(strategies.values())[0])

    def _mock_report_summary(self, prompt: str) -> str:
        return json.dumps({
            "executive_summary": "Entropy identified multiple high-severity logic vulnerabilities. Critical findings include race conditions and IDOR vulnerabilities. Immediate remediation is recommended.",
            "risk_rating": "HIGH",
        })


# ---------------------------------------------------------------------------
# 2. OpenAI-compatible  (OpenAI, Azure, Groq, Together, LM Studio, vLLM)
# ---------------------------------------------------------------------------

class OpenAILLM(BaseLLM):
    """OpenAI-compatible /v1/chat/completions. Works with Groq, Together, Azure, etc."""

    def __init__(self, api_key: str, model: str = "gpt-4o-mini", base_url: str = "https://api.openai.com/v1"):
        self.api_key  = api_key
        self.model    = model
        self.base_url = base_url.rstrip("/")

    def complete(self, prompt: str, system: str = "") -> str:
        messages: List[Dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        data = self._post_json(
            f"{self.base_url}/chat/completions",
            payload={"model": self.model, "messages": messages, "max_tokens": 2048},
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
        )
        return data["choices"][0]["message"]["content"]


# ---------------------------------------------------------------------------
# 3. Anthropic Claude
# ---------------------------------------------------------------------------

class AnthropicLLM(BaseLLM):
    """
    Anthropic Claude via Messages API.
    Models: claude-opus-4-5, claude-sonnet-4-5, claude-haiku-4-5-20251001, etc.
    """

    API_URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, api_key: str, model: str = "claude-haiku-4-5-20251001", max_tokens: int = 2048):
        self.api_key    = api_key
        self.model      = model
        self.max_tokens = max_tokens

    def complete(self, prompt: str, system: str = "") -> str:
        payload: Dict[str, Any] = {
            "model":      self.model,
            "max_tokens": self.max_tokens,
            "messages":   [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system
        data = self._post_json(
            self.API_URL,
            payload=payload,
            headers={
                "Content-Type":      "application/json",
                "x-api-key":         self.api_key,
                "anthropic-version": "2023-06-01",
            },
        )
        return data["content"][0]["text"]


# ---------------------------------------------------------------------------
# 4. Google Gemini
# ---------------------------------------------------------------------------

class GeminiLLM(BaseLLM):
    """
    Google Gemini via Generative Language REST API.
    Models: gemini-1.5-pro, gemini-1.5-flash, gemini-2.0-flash, gemini-pro, etc.
    """

    BASE = "https://generativelanguage.googleapis.com/v1beta/models"

    def __init__(self, api_key: str, model: str = "gemini-1.5-flash"):
        self.api_key = api_key
        self.model   = model

    def complete(self, prompt: str, system: str = "") -> str:
        full = f"{system}\n\n{prompt}" if system else prompt
        url  = f"{self.BASE}/{self.model}:generateContent?key={self.api_key}"
        data = self._post_json(
            url,
            payload={
                "contents": [{"parts": [{"text": full}]}],
                "generationConfig": {"maxOutputTokens": 2048, "temperature": 0.7},
            },
            headers={"Content-Type": "application/json"},
        )
        return data["candidates"][0]["content"]["parts"][0]["text"]


# ---------------------------------------------------------------------------
# 5. Mistral AI
# ---------------------------------------------------------------------------

class MistralLLM(BaseLLM):
    """
    Mistral AI chat completions.
    Models: mistral-large-latest, mistral-small-latest, open-mixtral-8x22b, codestral-latest, etc.
    """

    API_URL = "https://api.mistral.ai/v1/chat/completions"

    def __init__(self, api_key: str, model: str = "mistral-small-latest"):
        self.api_key = api_key
        self.model   = model

    def complete(self, prompt: str, system: str = "") -> str:
        messages: List[Dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        data = self._post_json(
            self.API_URL,
            payload={"model": self.model, "messages": messages, "max_tokens": 2048},
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
        )
        return data["choices"][0]["message"]["content"]


# ---------------------------------------------------------------------------
# 6. Cohere
# ---------------------------------------------------------------------------

class CohereLLM(BaseLLM):
    """
    Cohere Chat v2 API.
    Models: command-r-plus, command-r, command-light, etc.
    """

    API_URL = "https://api.cohere.ai/v2/chat"

    def __init__(self, api_key: str, model: str = "command-r-plus"):
        self.api_key = api_key
        self.model   = model

    def complete(self, prompt: str, system: str = "") -> str:
        messages: List[Dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        data = self._post_json(
            self.API_URL,
            payload={"model": self.model, "messages": messages},
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}", "X-Client-Name": "entropy-chaos"},
        )
        content = data.get("message", {}).get("content", [])
        if isinstance(content, list) and content:
            return content[0].get("text", "")
        return str(content)


# ---------------------------------------------------------------------------
# 7. Hugging Face Inference API
# ---------------------------------------------------------------------------

class HuggingFaceLLM(BaseLLM):
    """
    Hugging Face Inference API — works with any hosted text-generation model.
    Models: meta-llama/Meta-Llama-3-8B-Instruct, mistralai/Mistral-7B-Instruct-v0.3, etc.
    """

    BASE = "https://api-inference.huggingface.co/models"

    def __init__(self, api_key: str, model: str = "meta-llama/Meta-Llama-3-8B-Instruct", max_new_tokens: int = 1024):
        self.api_key        = api_key
        self.model          = model
        self.max_new_tokens = max_new_tokens

    def complete(self, prompt: str, system: str = "") -> str:
        full = f"<|system|>\n{system}\n<|user|>\n{prompt}\n<|assistant|>" if system else prompt
        data = self._post_json(
            f"{self.BASE}/{self.model}",
            payload={"inputs": full, "parameters": {"max_new_tokens": self.max_new_tokens, "return_full_text": False}},
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
        )
        if isinstance(data, list) and data:
            return data[0].get("generated_text", "")
        return str(data.get("generated_text", data))


# ---------------------------------------------------------------------------
# 8. Ollama  (local, privacy-first)
# ---------------------------------------------------------------------------

class OllamaLLM(BaseLLM):
    """
    Local models via Ollama REST API.
    Install: https://ollama.com — then: ollama pull llama3
    Models: llama3, mistral, phi3, gemma2, qwen2, deepseek-coder, codellama, etc.
    """

    def __init__(self, model: str = "llama3", base_url: str = "http://localhost:11434"):
        self.model    = model
        self.base_url = base_url.rstrip("/")

    def complete(self, prompt: str, system: str = "") -> str:
        data = self._post_json(
            f"{self.base_url}/api/generate",
            payload={"model": self.model, "prompt": prompt, "system": system, "stream": False},
            headers={"Content-Type": "application/json"},
        )
        return data.get("response", "")

    def list_models(self) -> List[str]:
        import urllib.request
        with urllib.request.urlopen(f"{self.base_url}/api/tags", timeout=5) as resp:
            data = json.loads(resp.read())
        return [m["name"] for m in data.get("models", [])]


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_BACKEND_MAP: Dict[str, type] = {
    "mock":        MockLLM,
    "openai":      OpenAILLM,
    "anthropic":   AnthropicLLM,
    "claude":      AnthropicLLM,
    "gemini":      GeminiLLM,
    "google":      GeminiLLM,
    "mistral":     MistralLLM,
    "cohere":      CohereLLM,
    "huggingface": HuggingFaceLLM,
    "hf":          HuggingFaceLLM,
    "ollama":      OllamaLLM,
    "groq":        OpenAILLM,
    "together":    OpenAILLM,
    "lmstudio":    OpenAILLM,
    "azure":       OpenAILLM,
}

_BACKEND_DEFAULTS: Dict[str, Dict[str, str]] = {
    "groq":     {"base_url": "https://api.groq.com/openai/v1",   "model": "llama-3.1-70b-versatile"},
    "together": {"base_url": "https://api.together.xyz/v1",       "model": "meta-llama/Llama-3-70b-chat-hf"},
    "lmstudio": {"base_url": "http://localhost:1234/v1",          "model": "local-model"},
}


def create_llm(backend: str = "mock", **kwargs: Any) -> BaseLLM:
    """Instantiate an LLM backend by name. Pass api_key / model / base_url as needed."""  
    key = backend.lower()
    cls = _BACKEND_MAP.get(key)
    if cls is None:
        canonical = sorted({k for k in _BACKEND_MAP if k not in ("claude","google","hf")})
        raise ValueError(f"Unknown LLM backend: {backend!r}. Choose: {', '.join(canonical)}")
    for k, v in _BACKEND_DEFAULTS.get(key, {}).items():
        kwargs.setdefault(k, v)
    return cls(**kwargs)


def list_backends() -> List[str]:
    """Return canonical list of supported backend names."""
    return sorted({k for k in _BACKEND_MAP if k not in ("claude","google","hf","groq","together","lmstudio","azure")})
