"""
triage_agent.py
---------------
The Alert Triage Agent — Stage 2 of the SOC pipeline.

Responsibilities (bounded):
- Accept a fully enriched alert
- Apply deterministic business rules and a confidence scoring model
- Return a structured TriageResult with classification, priority, and recommendations

This agent NEVER executes actions. It ONLY recommends.
If confidence falls below the threshold, it mandates a human review.
"""

from __future__ import annotations

import logging
from datetime import datetime

from schemas.input_schema import (
    AlertType,
    AssetCriticality,
    EnrichedAlert,
    PrivilegeLevel,
)
from schemas.output_schema import (
    RecommendedAction,
    SuspicionLevel,
    TriageClassification,
    TriagePriority,
    TriageResult,
)

logger = logging.getLogger(__name__)

# Confidence threshold below which human review is automatically required
HUMAN_REVIEW_CONFIDENCE_THRESHOLD = 0.65


class TriageAgent:
    """
    Alert Triage Agent — Stage 2 of the SOC pipeline.

    Uses a hybrid approach:
    1. Deterministic rules (fast, explainable, fully auditable)
    2. Confidence scoring (weighted signals → float 0.0 – 1.0)

    Output is always a fully validated TriageResult object.
    """

    VERSION = "1.0.0"

    # Priority upgrade table: alert type → base priority
    _BASE_PRIORITY = {
        AlertType.MALWARE: TriagePriority.P1_CRITICAL,
        AlertType.RANSOMWARE: TriagePriority.P1_CRITICAL,
        AlertType.BRUTE_FORCE: TriagePriority.P2_HIGH,
        AlertType.DATA_EXFILTRATION: TriagePriority.P2_HIGH,
        AlertType.PHISHING: TriagePriority.P3_MEDIUM,
        AlertType.SUSPICIOUS_LOGIN: TriagePriority.P3_MEDIUM,
        AlertType.INSIDER_THREAT: TriagePriority.P2_HIGH,
        AlertType.UNKNOWN: TriagePriority.P3_MEDIUM,
    }

    def evaluate_alert(self, enriched: EnrichedAlert) -> TriageResult:
        """
        Main triage evaluation method.

        Args:
            enriched: A fully populated EnrichedAlert from the enrichment agent.

        Returns:
            A structured and validated TriageResult.
        """
        logger.info(f"[TriageAgent] Evaluating alert {enriched.alert_id}")

        risk_factors = []
        suspicion_score = 0.0   # accumulates signal weights
        confidence_score = 0.0  # reflects data quality and signal strength

        alert = enriched.original_alert
        alert_type = AlertType(alert.type)

        # ------------------------------------------------------------------
        # Signal 1: Source IP reputation
        # ------------------------------------------------------------------
        if enriched.source_ip_is_known_malicious:
            suspicion_score += 0.35
            confidence_score += 0.25
            risk_factors.append("Source IP is listed in threat intelligence as malicious")

        # ------------------------------------------------------------------
        # Signal 2: IOC match (domain or file hash)
        # ------------------------------------------------------------------
        if enriched.ioc_matched:
            suspicion_score += 0.30
            confidence_score += 0.20
            matched_actors = {
                m.threat_actor for m in enriched.threat_intel_matches if m.threat_actor
            }
            if matched_actors:
                risk_factors.append(
                    f"IOC matched known threat actor(s): {', '.join(matched_actors)}"
                )
            else:
                risk_factors.append("IOC matched threat intelligence database")

        # ------------------------------------------------------------------
        # Signal 3: Asset criticality
        # ------------------------------------------------------------------
        if enriched.asset_context:
            crit = AssetCriticality(enriched.asset_context.criticality)
            if crit == AssetCriticality.CRITICAL:
                suspicion_score += 0.20
                confidence_score += 0.15
                risk_factors.append(
                    f"Target asset '{enriched.asset_context.hostname}' is classified CRITICAL"
                )
            elif crit == AssetCriticality.HIGH:
                suspicion_score += 0.10
                confidence_score += 0.10
                risk_factors.append(
                    f"Target asset '{enriched.asset_context.hostname}' is classified HIGH criticality"
                )
        else:
            # Unknown asset reduces confidence
            confidence_score -= 0.10
            risk_factors.append("Asset context unavailable — criticality unknown")

        # ------------------------------------------------------------------
        # Signal 4: Privileged account involvement
        # ------------------------------------------------------------------
        if enriched.user_is_privileged and enriched.user_context:
            priv = PrivilegeLevel(enriched.user_context.privilege_level)
            if priv == PrivilegeLevel.ADMIN:
                suspicion_score += 0.20
                confidence_score += 0.15
                risk_factors.append(
                    f"Involved user '{enriched.user_context.username}' holds ADMIN privileges"
                )
            else:
                suspicion_score += 0.12
                confidence_score += 0.10
                risk_factors.append(
                    f"Involved user '{enriched.user_context.username}' holds elevated privileges"
                )

        # ------------------------------------------------------------------
        # Signal 5: User's historical incidents
        # ------------------------------------------------------------------
        if enriched.user_has_recent_incidents and enriched.user_context:
            incident_count = len(enriched.user_context.recent_incidents)
            suspicion_score += min(0.15, 0.07 * incident_count)
            confidence_score += 0.05
            risk_factors.append(
                f"User has {incident_count} prior security incident(s): "
                f"{', '.join(enriched.user_context.recent_incidents)}"
            )

        # ------------------------------------------------------------------
        # Signal 6: User risk score
        # ------------------------------------------------------------------
        if enriched.user_context:
            risk_s = enriched.user_context.risk_score
            if risk_s >= 50:
                suspicion_score += 0.10
                confidence_score += 0.05
                risk_factors.append(f"User risk score is elevated ({risk_s}/100)")
            elif risk_s >= 30:
                suspicion_score += 0.05
                risk_factors.append(f"User risk score is moderate ({risk_s}/100)")
        else:
            confidence_score -= 0.10
            risk_factors.append("User context unavailable — risk score unknown")

        # ------------------------------------------------------------------
        # Signal 7: Alert severity escalation (from raw SIEM)
        # ------------------------------------------------------------------
        if alert.severity in ("critical", "high"):
            suspicion_score += 0.05
            confidence_score += 0.05

        # ------------------------------------------------------------------
        # Signal 8: Open asset vulnerabilities
        # ------------------------------------------------------------------
        if enriched.asset_context and enriched.asset_context.open_vulnerabilities > 3:
            suspicion_score += 0.08
            risk_factors.append(
                f"Asset has {enriched.asset_context.open_vulnerabilities} open vulnerabilities"
            )

        # ------------------------------------------------------------------
        # Signal 9: MFA status
        # ------------------------------------------------------------------
        if enriched.user_context and not enriched.user_context.mfa_enabled:
            suspicion_score += 0.07
            risk_factors.append("User does not have MFA enabled — credential theft risk elevated")

        # ------------------------------------------------------------------
        # Bonus: enrichment confidence feeds into overall confidence
        # ------------------------------------------------------------------
        confidence_score += enriched.enrichment_confidence * 0.20

        # Clamp both scores to [0, 1]
        suspicion_score = min(1.0, max(0.0, suspicion_score))
        confidence_score = min(1.0, max(0.0, confidence_score))

        # ------------------------------------------------------------------
        # Derive classification, priority, and suspicion level
        # ------------------------------------------------------------------
        classification = self._derive_classification(suspicion_score, confidence_score)
        priority = self._derive_priority(alert_type, enriched, suspicion_score)
        suspicion_level = self._derive_suspicion_level(suspicion_score)
        requires_human = (
            confidence_score < HUMAN_REVIEW_CONFIDENCE_THRESHOLD
            or classification == TriageClassification.UNCERTAIN
        )

        actions = self._build_recommended_actions(
            alert_type, classification, priority, enriched, requires_human
        )

        explanation = self._build_explanation(
            classification, priority, suspicion_level, confidence_score,
            risk_factors, requires_human
        )
        reasoning_summary = (
            "Triage uses weighted deterministic signals (IOC quality, asset criticality, "
            "user privilege, and context confidence) to produce classification, priority, "
            "and analyst review requirements."
        )

        result = TriageResult(
            alert_id=enriched.alert_id,
            classification=classification,
            priority=priority,
            suspicion_level=suspicion_level,
            recommended_actions=actions,
            confidence=round(confidence_score, 2),
            explanation=explanation,
            reasoning_summary=reasoning_summary,
            triage_timestamp=datetime.utcnow(),
            agent_version=self.VERSION,
            requires_human_review=requires_human,
            risk_factors=risk_factors,
        )

        logger.info(
            f"[TriageAgent] Alert {enriched.alert_id} → "
            f"classification={classification} | priority={priority} | "
            f"confidence={confidence_score:.2f} | human_review={requires_human}"
        )
        return result

    # ------------------------------------------------------------------
    # Decision helpers
    # ------------------------------------------------------------------

    def _derive_classification(
        self, suspicion: float, confidence: float
    ) -> TriageClassification:
        """Map suspicion and confidence scores to a classification label."""
        if confidence < 0.40:
            return TriageClassification.UNCERTAIN

        if suspicion >= 0.75:
            return TriageClassification.TRUE_POSITIVE
        elif suspicion >= 0.50:
            return TriageClassification.LIKELY_TRUE_POSITIVE
        elif suspicion >= 0.30:
            return TriageClassification.UNCERTAIN
        elif suspicion >= 0.15:
            return TriageClassification.LIKELY_FALSE_POSITIVE
        else:
            return TriageClassification.FALSE_POSITIVE

    def _derive_priority(
        self,
        alert_type: AlertType,
        enriched: EnrichedAlert,
        suspicion: float,
    ) -> TriagePriority:
        """Determine priority using the base priority table with contextual upgrades."""
        priority = self._BASE_PRIORITY.get(alert_type, TriagePriority.P3_MEDIUM)

        priority_order = [
            TriagePriority.P4_LOW,
            TriagePriority.P3_MEDIUM,
            TriagePriority.P2_HIGH,
            TriagePriority.P1_CRITICAL,
        ]

        def upgrade(p: TriagePriority) -> TriagePriority:
            idx = priority_order.index(p)
            return priority_order[min(idx + 1, len(priority_order) - 1)]

        # Critical asset → upgrade priority
        if enriched.asset_is_critical:
            priority = upgrade(priority)

        # Admin user + confirmed IOC → upgrade priority
        if (
            enriched.user_is_privileged
            and enriched.ioc_matched
            and suspicion >= 0.60
        ):
            priority = upgrade(priority)

        return priority

    def _derive_suspicion_level(self, suspicion_score: float) -> SuspicionLevel:
        """Convert a numeric suspicion score to a labeled level."""
        if suspicion_score >= 0.80:
            return SuspicionLevel.VERY_HIGH
        elif suspicion_score >= 0.60:
            return SuspicionLevel.HIGH
        elif suspicion_score >= 0.40:
            return SuspicionLevel.MEDIUM
        elif suspicion_score >= 0.20:
            return SuspicionLevel.LOW
        else:
            return SuspicionLevel.NEGLIGIBLE

    def _build_recommended_actions(
        self,
        alert_type: AlertType,
        classification: TriageClassification,
        priority: TriagePriority,
        enriched: EnrichedAlert,
        requires_human: bool,
    ) -> list[RecommendedAction]:
        """Generate a contextual list of recommended actions based on the triage outcome."""
        actions = []

        # Always recommend: document findings
        actions.append(RecommendedAction(
            action_id="ACT-001",
            description="Document initial findings and open a formal incident case",
            urgency="immediate",
            requires_human=True,
            reversible=True,
        ))

        if classification in (
            TriageClassification.TRUE_POSITIVE,
            TriageClassification.LIKELY_TRUE_POSITIVE
        ):
            if alert_type == AlertType.BRUTE_FORCE:
                actions.append(RecommendedAction(
                    action_id="ACT-010",
                    description="Block source IP at perimeter firewall (requires approval)",
                    urgency="immediate",
                    requires_human=True,
                    reversible=True,
                ))
                actions.append(RecommendedAction(
                    action_id="ACT-011",
                    description="Force password reset and MFA re-enrollment for targeted account",
                    urgency="immediate",
                    requires_human=True,
                    reversible=True,
                ))

            elif alert_type in (AlertType.MALWARE, AlertType.RANSOMWARE):
                actions.append(RecommendedAction(
                    action_id="ACT-020",
                    description="Isolate affected endpoint from network (requires senior analyst approval)",
                    urgency="immediate",
                    requires_human=True,
                    reversible=True,
                ))
                actions.append(RecommendedAction(
                    action_id="ACT-021",
                    description="Collect forensic image of affected system before remediation",
                    urgency="immediate",
                    requires_human=True,
                    reversible=True,
                ))
                actions.append(RecommendedAction(
                    action_id="ACT-022",
                    description="Block C2 domains/IPs at DNS and firewall level",
                    urgency="immediate",
                    requires_human=True,
                    reversible=True,
                ))

            elif alert_type == AlertType.PHISHING:
                actions.append(RecommendedAction(
                    action_id="ACT-030",
                    description="Block malicious sender domain at email gateway",
                    urgency="immediate",
                    requires_human=True,
                    reversible=True,
                ))
                actions.append(RecommendedAction(
                    action_id="ACT-031",
                    description="Alert all users who received the phishing email",
                    urgency="short_term",
                    requires_human=True,
                    reversible=True,
                ))

            elif alert_type == AlertType.DATA_EXFILTRATION:
                actions.append(RecommendedAction(
                    action_id="ACT-040",
                    description="Block outbound connection to suspicious external IP via DLP/firewall",
                    urgency="immediate",
                    requires_human=True,
                    reversible=True,
                ))
                actions.append(RecommendedAction(
                    action_id="ACT-041",
                    description="Preserve DLP logs and identify all transferred files",
                    urgency="immediate",
                    requires_human=True,
                    reversible=True,
                ))

            elif alert_type == AlertType.SUSPICIOUS_LOGIN:
                actions.append(RecommendedAction(
                    action_id="ACT-050",
                    description="Verify with user whether the login was legitimate (call/email)",
                    urgency="immediate",
                    requires_human=True,
                    reversible=True,
                ))
                actions.append(RecommendedAction(
                    action_id="ACT-051",
                    description="Temporarily disable session tokens from suspicious geolocation",
                    urgency="short_term",
                    requires_human=True,
                    reversible=True,
                ))

        # If low confidence → mandatory escalation
        if requires_human:
            actions.append(RecommendedAction(
                action_id="ACT-099",
                description="Escalate to Tier 2 analyst for human review — confidence below threshold",
                urgency="short_term",
                requires_human=True,
                reversible=True,
            ))

        return actions

    def _build_explanation(
        self,
        classification: TriageClassification,
        priority: TriagePriority,
        suspicion_level: SuspicionLevel,
        confidence: float,
        risk_factors: list[str],
        requires_human: bool,
    ) -> str:
        """Compose a human-readable explanation of the triage decision."""
        parts = [
            f"Classification: {classification} | Priority: {priority} | "
            f"Suspicion: {suspicion_level} | Confidence: {confidence:.0%}.",
            "",
            "Risk factors identified:",
        ]
        for i, factor in enumerate(risk_factors, 1):
            parts.append(f"  {i}. {factor}")

        if requires_human:
            parts.append(
                "\nNOTE: Confidence is below the automated decision threshold "
                f"({HUMAN_REVIEW_CONFIDENCE_THRESHOLD:.0%}). Human analyst review is required."
            )
        return "\n".join(parts)
