"""
scenario_schema.py
------------------
Schemas for scenario metadata used in thesis-grade demonstrations.
"""

from __future__ import annotations

from pydantic import BaseModel

from schemas.input_schema import RawAlert


class ScenarioMetadata(BaseModel):
    scenario_category: str
    expected_difficulty: str
    expected_triage_direction: str
    expected_policy_behavior: str
    expected_false_positive_profile: str
    expected_escalation_tendency: str
    notes: str = ""


class ScenarioDefinition(BaseModel):
    name: str
    alert: RawAlert
    metadata: ScenarioMetadata
