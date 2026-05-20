"""
runner.py
---------
Unified execution entrypoint supporting python and langgraph modes.
"""

from __future__ import annotations

from typing import Literal

from orchestration.orchestrator import Orchestrator
from schemas.input_schema import RawAlert
from schemas.output_schema import OrchestratorResult


def resolve_default_mode() -> str:
    try:
        import langgraph  # noqa: F401

        return "langgraph"
    except Exception:
        return "python"


def run_alert(alert: RawAlert, mode: Literal["python", "langgraph"] | str = "auto") -> OrchestratorResult:
    selected = resolve_default_mode() if mode == "auto" else mode
    if selected == "langgraph":
        try:
            from orchestration.langgraph_graph import run_graph

            return run_graph(alert)
        except Exception:
            # safe fallback if graph stack is unavailable
            pass
    return Orchestrator().process_alert(alert)
