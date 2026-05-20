"""
llm package
-----------
Provider selector with safe fallback to deterministic mock.
"""

from __future__ import annotations

import os
import warnings

from llm.llm_client import LLMClient
from llm.mock_llm_client import MockLLMClient


def build_llm_client() -> LLMClient:
    provider = os.getenv("LLM_PROVIDER", "mock").strip().lower()
    if provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            warnings.warn(
                "LLM_PROVIDER=openai but OPENAI_API_KEY not set; falling back to mock.",
                RuntimeWarning,
            )
            return MockLLMClient()
        try:
            from llm.openai_client import OpenAIClient

            return OpenAIClient(api_key=api_key)
        except Exception as exc:  # pragma: no cover - runtime safety fallback
            warnings.warn(
                f"OpenAI client unavailable ({exc}); falling back to mock.",
                RuntimeWarning,
            )
            return MockLLMClient()
    return MockLLMClient()

