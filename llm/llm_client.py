"""
llm_client.py
-------------
Abstract LLM client interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict


class LLMClient(ABC):
    @abstractmethod
    def generate_text(self, prompt: str, *, temperature: float = 0.0) -> str:
        raise NotImplementedError

    @abstractmethod
    def generate_json(self, prompt: str, schema_hint: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError
