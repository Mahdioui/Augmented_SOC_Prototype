"""
policy_engine.py
----------------
Declarative governance policy engine driven by YAML action registry.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import yaml


class GovernancePolicyEngine:
    def __init__(self, registry_path: str | Path | None = None):
        if registry_path is None:
            registry_path = Path(__file__).with_name("action_registry.yaml")
        self.registry_path = Path(registry_path)
        self.registry = self._load_registry()

    def _load_registry(self) -> Dict[str, Dict]:
        if not self.registry_path.exists():
            return {"actions": {}}
        with self.registry_path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {"actions": {}}

    def evaluate(
        self,
        action_name: str,
        confidence: float,
        *,
        confidence_threshold: float = 0.65,
    ) -> Dict[str, object]:
        actions = self.registry.get("actions", {})
        action_def = actions.get(action_name)
        triggered_rules: List[str] = []
        rationale: List[str] = []

        if action_def is None:
            return {
                "decision": "BLOCK",
                "triggered_rules": ["GOV-000:UNKNOWN_ACTION"],
                "decision_rationale": f"Action '{action_name}' is not registered.",
                "approval_role_required": "security_manager",
                "confidence_threshold_applied": confidence_threshold,
            }

        if confidence < confidence_threshold:
            triggered_rules.append("GOV-010:LOW_CONFIDENCE")
            rationale.append(
                f"Confidence {confidence:.2f} below threshold {confidence_threshold:.2f}."
            )

        if not action_def.get("allowed_in_prototype", False):
            triggered_rules.append("GOV-020:NOT_ALLOWED_IN_PROTOTYPE")
            rationale.append("Action is not executable in this prototype.")
            decision = "BLOCK"
        elif action_def.get("requires_human_approval", False):
            triggered_rules.append("GOV-030:HUMAN_APPROVAL_REQUIRED")
            rationale.append("Action requires explicit human approval.")
            decision = "REQUIRE_APPROVAL"
        else:
            decision = "ALLOW"

        if action_def.get("risk_level") == "high" and decision == "ALLOW":
            triggered_rules.append("GOV-040:HIGH_RISK_ESCALATE")
            rationale.append("High-risk action should be escalated.")
            decision = "ESCALATE"

        return {
            "decision": decision,
            "triggered_rules": triggered_rules,
            "decision_rationale": " | ".join(rationale) if rationale else "No blocking condition.",
            "approval_role_required": action_def.get("required_role", "analyst"),
            "confidence_threshold_applied": confidence_threshold,
        }
