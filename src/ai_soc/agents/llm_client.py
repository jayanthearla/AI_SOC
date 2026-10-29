"""Provider-agnostic LLM client.  `complete(system, user) -> str`.

  mock           deterministic offline template analyst (also the 'no-LLM' baseline in the paper). No network.
  anthropic      Messages API over HTTPS (env ANTHROPIC_API_KEY; model e.g. claude-sonnet-5-5)       [untested here]
  openai_compat  any OpenAI-compatible /chat/completions endpoint, e.g. OpenAI, Groq, vLLM, Ollama    [untested here]
                 env OPENAI_API_KEY (or GROQ_API_KEY), OPENAI_BASE_URL (default https://api.openai.com/v1)

Use temperature 0, record `model` and the date, and repeat runs (experiments E8/E9) - LLM outputs are not deterministic
even at temperature 0.
"""
from __future__ import annotations

import json
import os
import re

import requests

DEFAULT_MODELS = {"anthropic": "claude-sonnet-5-5", "openai_compat": "llama-3.3-70b-versatile", "mock": "template-v1"}


class LLMClient:
    provider = "base"

    def __init__(self, model=None, temperature=0.0, max_tokens=2500):
        self.model = model or DEFAULT_MODELS.get(self.provider, "")
        self.temperature, self.max_tokens = temperature, max_tokens

    def complete(self, system: str, user: str) -> str:
        raise NotImplementedError


class AnthropicClient(LLMClient):
    provider = "anthropic"

    def complete(self, system, user):
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        r = requests.post("https://api.anthropic.com/v1/messages",
                          headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                          json={"model": self.model, "max_tokens": self.max_tokens, "temperature": self.temperature,
                                "system": system, "messages": [{"role": "user", "content": user}]}, timeout=120)
        r.raise_for_status()
        return "".join(b.get("text", "") for b in r.json()["content"] if b.get("type") == "text")


class OpenAICompatClient(LLMClient):
    provider = "openai_compat"

    def complete(self, system, user):
        key = os.environ.get("OPENAI_API_KEY") or os.environ.get("GROQ_API_KEY")
        if not key:
            raise RuntimeError("OPENAI_API_KEY / GROQ_API_KEY not set")
        base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        r = requests.post(f"{base}/chat/completions", headers={"Authorization": f"Bearer {key}"},
                          json={"model": self.model, "temperature": self.temperature, "max_tokens": self.max_tokens,
                                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}, timeout=120)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


class MockClient(LLMClient):
    """Deterministic template analyst: reads the CONTEXT json block from the prompt and writes a schema-valid report.
    It is the 'no LLM' baseline (E8) and lets the whole stack be tested offline.  It ignores instructions in log text
    by construction, so it also serves as the injection-test control."""
    provider = "mock"

    def complete(self, system, user):
        from ai_soc.agents.template import template_report
        m = re.search(r"<context>\s*(\{.*\})\s*</context>", user, re.S)
        return json.dumps(template_report(json.loads(m.group(1))))


def make_client(provider="mock", model=None, **kw) -> LLMClient:
    return {"mock": MockClient, "anthropic": AnthropicClient, "openai_compat": OpenAICompatClient}[provider](model, **kw)
