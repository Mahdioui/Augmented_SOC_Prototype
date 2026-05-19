"""
false_positive_prediction_agent.py
----------------------------------
Bounded agent that estimates false-positive likelihood.

This agent does not dismiss or close alerts. It only provides structured,
explainable probability support for analyst decision-making.
"""

from __future__ import annotations

from datetime import datetime
from typing import List

from schemas.input_schema import EnrichedAlert
from schemas.output_schema import FalsePositivePredictionResult, TriageResult


class FalsePositivePredictionAgent:
    VERSION = "1.0.0"

    def predict(
        self, enriched: EnrichedAlert, triage: TriageResult
    ) -> FalsePositivePredictionResult:
        score = 0.50
        confidence = 0.50
        reasons: List[str] = []
        risk_notes: List[str] = []

        related = enriched.related_cases
        if related:
            fp_count = sum(1 for case in related if case.false_positive)
            fp_ratio = fp_count / len(related)
            score += (fp_ratio - 0.5) * 0.40
            confidence += 0.15
            reasons.append(
                f"Historical similar cases: {fp_count}/{len(related)} were false positives."
            )

        if not enriched.ioc_matched:
            score += 0.18
            reasons.append("No confirmed IOC match increases false-positive likelihood.")
        else:
            score -= 0.25
            confidence += 0.10
            reasons.append("Strong IOC evidence reduces false-positive likelihood.")

        severity = enriched.original_alert.severity
        if severity in ("low", "medium"):
            score += 0.10
        else:
            score -= 0.12

        if enriched.asset_context and enriched.asset_context.criticality in ("critical", "high"):
            score -= 0.12
            risk_notes.append("High/critical asset context suppresses auto-dismiss confidence.")
        if enriched.user_is_privileged:
            score -= 0.10
            risk_notes.append("Privileged account involvement suppresses false-positive handling.")

        if triage.classification in ("false_positive", "likely_false_positive"):
            score += 0.15
        if triage.classification in ("true_positive", "likely_true_positive"):
            score -= 0.15

        if triage.confidence >= 0.75:
            confidence += 0.10
        else:
            confidence -= 0.05

        governance_guardrail_applied = False
        if enriched.asset_is_critical or enriched.user_is_privileged or enriched.ioc_matched:
            governance_guardrail_applied = True
            if score > 0.70:
                score = 0.70
            risk_notes.append(
                "Governance guardrail: high-risk context prevents aggressive false-positive handling."
            )

        score = max(0.0, min(1.0, score))
        confidence = max(0.0, min(1.0, confidence))

        if score >= 0.70:
            handling = (
                "Likely false positive; keep case open for analyst confirmation and rule tuning review."
            )
            priority_adjustment = "Consider downgrading one level after human validation."
        elif score >= 0.45:
            handling = "Uncertain signal quality; keep current priority and request targeted validation."
            priority_adjustment = "No automatic adjustment suggested."
        else:
            handling = "Likely true signal; prioritize investigation and maintain current escalation path."
            priority_adjustment = "Avoid downgrading priority."

        explanation = " | ".join(reasons) if reasons else "Limited indicators available."
        reasoning_summary = (
            "False-positive estimate is computed from historical case patterns, IOC quality, "
            "severity context, and governance constraints."
        )

        return FalsePositivePredictionResult(
            alert_id=enriched.alert_id,
            false_positive_probability=round(score, 2),
            prediction_confidence=round(confidence, 2),
            explanation=explanation,
            reasoning_summary=reasoning_summary,
            recommended_handling=handling,
            priority_adjustment_suggestion=priority_adjustment,
            risk_notes=risk_notes,
            governance_guardrail_applied=governance_guardrail_applied,
            prediction_timestamp=datetime.utcnow(),
            agent_version=self.VERSION,
        )
