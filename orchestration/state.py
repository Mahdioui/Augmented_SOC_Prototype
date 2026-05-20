"""
state.py
--------
State container for LangGraph workflow execution.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, TypedDict

from schemas.input_schema import RawAlert
from schemas.output_schema import OrchestratorResult


class SOCGraphState(TypedDict, total=False):
    mode: str
    request_id: str
    alert: RawAlert
    result: OrchestratorResult
    artifacts: Dict[str, str]
    route: str
    error: Optional[str]
    context: Dict[str, Any]
