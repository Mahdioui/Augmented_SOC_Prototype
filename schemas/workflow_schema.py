"""
workflow_schema.py
------------------
Workflow-level state and simulation schemas.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class WorkflowExecutionRecord(BaseModel):
    workflow: str
    alert_id: str
    status: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    ended_at: Optional[datetime] = None
    policy_decision: Optional[str] = None
    output_path: Optional[str] = None
