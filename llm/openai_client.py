"""
openai_client.py
----------------
Optional OpenAI-backed LLM client.
Falls back is handled by llm_factory in llm/__init__.py.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from llm.llm_client import LLMClient


class OpenAIClient(LLMClient):
    model_id = "gpt-4o"

    def __init__(self, api_key: str):
        from openai import OpenAI  # imported lazily to keep mock-only mode lightweight

        self.client = OpenAI(api_key=api_key)

    def generate_text(self, prompt: str, *, temperature: float = 0.0) -> str:
        completion = self.client.chat.completions.create(
            model=self.model_id,
            temperature=temperature,
            messages=[
                {"role": "system", "content": "You are a concise SOC copilot."},
                {"role": "user", "content": prompt},
            ],
        )
        return completion.choices[0].message.content or ""

    def generate_json(self, prompt: str, schema_hint: Dict[str, Any]) -> Dict[str, Any]:
        full_prompt = (
            f"{prompt}\n\nReturn JSON matching keys: {sorted(schema_hint.keys())}."
        )
        text = self.generate_text(full_prompt, temperature=0.0)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {
                "provider": "openai",
                "model_id": self.model_id,
                "raw_text": text,
                "parse_error": "non-json response",
            }
