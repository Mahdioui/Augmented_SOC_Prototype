"""
audit_schema.py
---------------
Audit entry schema required by chapter 6.
"""

from __future__ import annotations

from datetime import datetime
from typing import List

from pydantic import BaseModel, Field


class AuditRecord(BaseModel):
    request_id: str
    case_id: str
    timestamp_utc: datetime = Field(default_factory=datetime.utcnow)
    agent: str
    model_id: str
    prompt_version: str
    sources: List[str] = Field(default_factory=list)
    tools_called: List[str] = Field(default_factory=list)
    proposed_action: str = ""
    confidence: float = 0.0
    policy_decision: str = ""
    human_validation: str = ""
    final_outcome: str = ""
