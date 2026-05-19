"""
next_best_action_agent.py
-------------------------
Bounded recommendation agent for prioritized next investigation steps.
"""

from __future__ import annotations

from datetime import datetime
from typing import List

from schemas.input_schema import AlertType, EnrichedAlert
from schemas.output_schema import (
    ActionCategory,
    FalsePositivePredictionResult,
    NextBestActionItem,
    NextBestActionResult,
    TriageResult,
)


class NextBestActionAgent:
    VERSION = "1.0.0"

    def recommend(
        self,
        enriched: EnrichedAlert,
        triage: TriageResult,
        fp_prediction: FalsePositivePredictionResult | None = None,
    ) -> NextBestActionResult:
        alert_type = AlertType(enriched.original_alert.type)
        items: List[NextBestActionItem] = []

        items.append(
            NextBestActionItem(
                action_id="NBA-001",
                action="Validate core alert evidence against source telemetry.",
                rationale="Always start with evidence validation before escalation.",
                action_category=ActionCategory.INVESTIGATIVE,
                investigative_only=True,
                requires_analyst_review=True,
                sensitive=False,
                confidence=0.95,
            )
        )

        if alert_type in (AlertType.MALWARE, AlertType.RANSOMWARE):
            items.extend(
                [
                    NextBestActionItem(
                        action_id="NBA-020",
                        action="Query EDR process lineage and parent-child execution timeline.",
                        rationale="Confirms malicious execution chain and potential persistence.",
                        action_category=ActionCategory.INVESTIGATIVE,
                        confidence=0.90,
                    ),
                    NextBestActionItem(
                        action_id="NBA-021",
                        action="Inspect lateral movement indicators (SMB/RDP/PsExec traces).",
                        rationale="Critical to determine spread risk in banking infrastructure.",
                        action_category=ActionCategory.INVESTIGATIVE,
                        confidence=0.86,
                    ),
                    NextBestActionItem(
                        action_id="NBA-022",
                        action="Recommend host isolation to incident response lead (recommendation only).",
                        rationale="Potential containment option for confirmed malware activity.",
                        action_category=ActionCategory.CONTAINMENT_RECOMMENDATION,
                        investigative_only=False,
                        requires_analyst_review=True,
                        sensitive=True,
                        confidence=0.80,
                    ),
                ]
            )
        elif alert_type == AlertType.PHISHING:
            items.extend(
                [
                    NextBestActionItem(
                        action_id="NBA-030",
                        action="Correlate email headers with threat-intel sender infrastructure.",
                        rationale="Improves confidence in campaign attribution.",
                        action_category=ActionCategory.ENRICHMENT,
                        confidence=0.87,
                    ),
                    NextBestActionItem(
                        action_id="NBA-031",
                        action="Verify recent privileged activity for potentially compromised users.",
                        rationale="Detects post-phishing account misuse.",
                        action_category=ActionCategory.INVESTIGATIVE,
                        confidence=0.84,
                    ),
                ]
            )
        elif alert_type == AlertType.SUSPICIOUS_LOGIN:
            items.extend(
                [
                    NextBestActionItem(
                        action_id="NBA-040",
                        action="Check IAM anomalies: impossible travel, token reuse, MFA challenge logs.",
                        rationale="Distinguishes account compromise from legitimate travel noise.",
                        action_category=ActionCategory.INVESTIGATIVE,
                        confidence=0.88,
                    ),
                    NextBestActionItem(
                        action_id="NBA-041",
                        action="Cross-check recent privileged changes linked to this identity.",
                        rationale="Prioritizes impact assessment for elevated access accounts.",
                        action_category=ActionCategory.INVESTIGATIVE,
                        confidence=0.82,
                    ),
                ]
            )
        else:
            items.append(
                NextBestActionItem(
                    action_id="NBA-050",
                    action="Expand contextual enrichment with additional host/user timeline data.",
                    rationale="Insufficient signal specificity; needs broader context.",
                    action_category=ActionCategory.ENRICHMENT,
                    confidence=0.75,
                )
            )

        if fp_prediction and fp_prediction.false_positive_probability >= 0.65:
            items.append(
                NextBestActionItem(
                    action_id="NBA-090",
                    action="Review detection rule fidelity and known-noise signatures for this pattern.",
                    rationale="High FP estimate indicates potential tuning opportunity.",
                    action_category=ActionCategory.INVESTIGATIVE,
                    confidence=0.80,
                )
            )

        if triage.priority in ("P1_CRITICAL", "P2_HIGH"):
            items.append(
                NextBestActionItem(
                    action_id="NBA-099",
                    action="Open escalation briefing to Tier 2 / Incident Response coordinator.",
                    rationale="Priority/severity level requires rapid coordinated review.",
                    action_category=ActionCategory.ESCALATION,
                    investigative_only=False,
                    requires_analyst_review=True,
                    sensitive=True,
                    confidence=0.88,
                )
            )

        reasoning_summary = (
            "Next-best-actions are selected from a bounded action vocabulary using "
            "alert type, triage signals, and optional false-positive context."
        )
        explanation = (
            "Actions are investigative/recommendation-only and include governance-sensitive "
            "flags for policy review."
        )
        avg_conf = sum(item.confidence for item in items) / len(items)

        return NextBestActionResult(
            alert_id=enriched.alert_id,
            actions=items,
            reasoning_summary=reasoning_summary,
            confidence=round(avg_conf, 2),
            explanation=explanation,
            generated_timestamp=datetime.utcnow(),
            agent_version=self.VERSION,
        )
