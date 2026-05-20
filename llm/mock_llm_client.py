"""
mock_llm_client.py
------------------
Deterministic mock LLM for offline prototype runs.
"""

from __future__ import annotations

from typing import Any, Dict

from llm.llm_client import LLMClient


class MockLLMClient(LLMClient):
    model_id = "mock-llm-deterministic-v1"

    def generate_text(self, prompt: str, *, temperature: float = 0.0) -> str:
        del temperature
        seed = sum(ord(ch) for ch in prompt) % 1000
        return (
            "MOCK_RESPONSE: Deterministic synthesis generated for prototype context. "
            f"signal_seed={seed}."
        )

    def generate_json(self, prompt: str, schema_hint: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "provider": "mock",
            "model_id": self.model_id,
            "summary": self.generate_text(prompt),
            "schema_hint_keys": sorted(schema_hint.keys()),
        }
