"""
feedback_schema.py
------------------
Schemas for human-in-the-loop analyst review capture.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from schemas.output_schema import TriageClassification, TriagePriority


class AnalystFeedback(BaseModel):
    alert_id: str
    scenario_name: Optional[str] = None
    reviewer_role: str
    final_review_decision: str = Field(
        ...,
        description="confirm_triage | override_triage | escalate | deescalate | pending",
    )
    analyst_final_classification: Optional[TriageClassification] = None
    analyst_final_priority: Optional[TriagePriority] = None
    triage_agreement: bool
    false_positive_agreement: bool
    summary_quality_agreement: bool
    next_action_agreement: bool
    analyst_comments: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
