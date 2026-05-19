"""
policy_engine.py
----------------
The Policy Engine — a mandatory governance gate in the SOC pipeline.

Responsibilities:
- Evaluate all proposed actions against a set of configurable policy rules
- Block, allow, or flag for human review based on:
    * Asset criticality
    * User privilege level
    * Agent confidence level
    * Action sensitivity classification
    * Compliance scope requirements

Every action that could affect a system, user, or data asset MUST pass
through the policy engine before being presented as a recommendation.

Returns a PolicyCheckResult — never modifies systems directly.
This enforces the "human-in-the-loop" principle for sensitive decisions.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Optional

from schemas.input_schema import AssetCriticality, EnrichedAlert, PrivilegeLevel
from schemas.output_schema import (
    FalsePositivePredictionResult,
    NextBestActionResult,
    PhishingAnalysisResult,
    PolicyCheckResult,
    PolicyDecision,
    PolicyDecisionSeverity,
    TriageResult,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Policy configuration — modify thresholds here to tune governance
# ---------------------------------------------------------------------------

# Confidence below this → always require human review
MIN_CONFIDENCE_FOR_AUTONOMOUS = 0.75

# Actions classified as "sensitive" always require human approval
SENSITIVE_ACTIONS = {
    "isolate_endpoint",
    "block_user_account",
    "reset_password",
    "delete_files",
    "block_ip",
    "disable_service",
    "escalate_to_ciso",
    "legal_hold",
    "revoke_access",
    "network_quarantine",
}

# Compliance requirements that mandate human review for any action
STRICT_COMPLIANCE_SCOPES = {"PCI-DSS", "DORA", "BCBS239"}


class PolicyEngine:
    """
    Policy Engine — governance gate for all SOC agent recommendations.

    Rules are evaluated in priority order. The most restrictive applicable
    rule wins. All triggered rules are recorded in the result for auditability.
    """

    VERSION = "1.0.0"

    def check(
        self,
        enriched: EnrichedAlert,
        triage: TriageResult,
        action_requested: str,
        confidence: float,
        phishing_result: Optional[PhishingAnalysisResult] = None,
        false_positive_result: Optional[FalsePositivePredictionResult] = None,
        next_best_action: Optional[NextBestActionResult] = None,
    ) -> PolicyCheckResult:
        """
        Evaluate whether a proposed action should be allowed, reviewed, or denied.

        Args:
            enriched:         The enriched alert providing asset/user context.
            triage:           The triage result containing the confidence score.
            action_requested: A string description of the proposed action.
            confidence:       The agent's confidence in this specific action.

        Returns:
            A PolicyCheckResult with decision, triggered rules, and reviewer info.
        """
        logger.info(
            f"[PolicyEngine] Checking action '{action_requested}' "
            f"for alert {enriched.alert_id} | confidence={confidence:.2f}"
        )

        triggered_rules: List[str] = []
        triggered_conditions: List[str] = []
        decision = PolicyDecision.ALLOWED
        reason_parts: List[str] = []
        review_notes: List[str] = []
        approval_role_required: Optional[str] = None
        decision_severity = PolicyDecisionSeverity.LOW

        # ------------------------------------------------------------------
        # Rule P-01: Critical asset — any action requires review
        # ------------------------------------------------------------------
        if (
            enriched.asset_context
            and enriched.asset_context.criticality == AssetCriticality.CRITICAL
        ):
            triggered_rules.append("P-01: CRITICAL_ASSET_PROTECTION")
            triggered_conditions.append("asset.criticality == critical")
            decision = PolicyDecision.REVIEW_REQUIRED
            decision_severity = PolicyDecisionSeverity.HIGH
            approval_role_required = "senior_analyst"
            reason_parts.append(
                f"Asset '{enriched.asset_context.hostname}' is classified CRITICAL — "
                "any action requires senior analyst approval"
            )

        # ------------------------------------------------------------------
        # Rule P-02: Privileged / Admin account involved — review required
        # ------------------------------------------------------------------
        if enriched.user_context and enriched.user_is_privileged:
            priv = PrivilegeLevel(enriched.user_context.privilege_level)
            if priv == PrivilegeLevel.ADMIN:
                triggered_rules.append("P-02A: ADMIN_ACCOUNT_INVOLVED")
                triggered_conditions.append("user.privilege_level == admin")
                decision = max_decision(decision, PolicyDecision.REVIEW_REQUIRED)
                decision_severity = max_severity(decision_severity, PolicyDecisionSeverity.HIGH)
                approval_role_required = approval_role_required or "security_manager"
                reason_parts.append(
                    f"Involved account '{enriched.user_context.username}' has ADMIN privileges — "
                    "requires security manager approval"
                )
            else:
                triggered_rules.append("P-02B: PRIVILEGED_ACCOUNT_INVOLVED")
                triggered_conditions.append("user.privilege_level in [privileged,elevated]")
                decision = max_decision(decision, PolicyDecision.REVIEW_REQUIRED)
                decision_severity = max_severity(decision_severity, PolicyDecisionSeverity.MEDIUM)
                approval_role_required = approval_role_required or "senior_analyst"
                reason_parts.append(
                    f"Involved account '{enriched.user_context.username}' has elevated privileges"
                )

        # ------------------------------------------------------------------
        # Rule P-03: Low confidence → always flag for review
        # ------------------------------------------------------------------
        if confidence < MIN_CONFIDENCE_FOR_AUTONOMOUS:
            triggered_rules.append(
                f"P-03: LOW_CONFIDENCE (threshold={MIN_CONFIDENCE_FOR_AUTONOMOUS:.0%})"
            )
            triggered_conditions.append(f"confidence({confidence:.2f}) < {MIN_CONFIDENCE_FOR_AUTONOMOUS:.2f}")
            decision = max_decision(decision, PolicyDecision.REVIEW_REQUIRED)
            decision_severity = max_severity(decision_severity, PolicyDecisionSeverity.MEDIUM)
            approval_role_required = approval_role_required or "analyst"
            reason_parts.append(
                f"Agent confidence ({confidence:.0%}) is below minimum threshold "
                f"({MIN_CONFIDENCE_FOR_AUTONOMOUS:.0%}) for autonomous action"
            )

        # ------------------------------------------------------------------
        # Rule P-04: Sensitive action classification
        # ------------------------------------------------------------------
        action_key = self._normalize_action_key(action_requested)
        if action_key in SENSITIVE_ACTIONS:
            triggered_rules.append(f"P-04: SENSITIVE_ACTION ({action_key})")
            triggered_conditions.append(f"action_key({action_key}) in SENSITIVE_ACTIONS")
            decision = max_decision(decision, PolicyDecision.REVIEW_REQUIRED)
            decision_severity = max_severity(decision_severity, PolicyDecisionSeverity.HIGH)
            approval_role_required = approval_role_required or "senior_analyst"
            reason_parts.append(
                f"Requested action '{action_requested}' is classified as sensitive "
                "and requires explicit human approval"
            )

        # ------------------------------------------------------------------
        # Rule P-05: Strict compliance scope on the affected asset
        # ------------------------------------------------------------------
        if enriched.asset_context:
            asset_scopes = set(enriched.asset_context.compliance_scope)
            triggered_scopes = asset_scopes & STRICT_COMPLIANCE_SCOPES
            if triggered_scopes:
                triggered_rules.append(
                    f"P-05: COMPLIANCE_SCOPE ({', '.join(triggered_scopes)})"
                )
                triggered_conditions.append(
                    f"asset.compliance_scope intersects {','.join(sorted(STRICT_COMPLIANCE_SCOPES))}"
                )
                decision = max_decision(decision, PolicyDecision.REVIEW_REQUIRED)
                decision_severity = max_severity(decision_severity, PolicyDecisionSeverity.HIGH)
                approval_role_required = approval_role_required or "compliance_officer"
                reason_parts.append(
                    f"Asset is in compliance scope {triggered_scopes} — "
                    "actions require compliance officer awareness"
                )

        # ------------------------------------------------------------------
        # Rule P-06: Destructive / irreversible actions are DENIED
        # ------------------------------------------------------------------
        irreversible_keywords = ["delete", "wipe", "format", "destroy", "permanent"]
        if any(kw in action_requested.lower() for kw in irreversible_keywords):
            triggered_rules.append("P-06: IRREVERSIBLE_ACTION_DENIED")
            triggered_conditions.append("action contains irreversible keyword")
            decision = PolicyDecision.DENIED
            decision_severity = PolicyDecisionSeverity.CRITICAL
            reason_parts.append(
                "Action appears to be irreversible/destructive — automatically denied. "
                "Escalate to CISO for manual authorization if required."
            )

        if triage.priority in ("P1_CRITICAL", "P2_HIGH"):
            triggered_rules.append("P-07: HIGH_PRIORITY_CASE_REVIEW")
            triggered_conditions.append(f"triage.priority={triage.priority}")
            decision = max_decision(decision, PolicyDecision.REVIEW_REQUIRED)
            decision_severity = max_severity(decision_severity, PolicyDecisionSeverity.HIGH)
            approval_role_required = approval_role_required or "senior_analyst"
            review_notes.append("High-priority case should be reviewed before downstream action.")

        if phishing_result and phishing_result.verdict in ("confirmed_phishing", "likely_phishing"):
            triggered_rules.append("P-08: PHISHING_VERDICT_REVIEW")
            triggered_conditions.append(f"phishing.verdict={phishing_result.verdict}")
            decision = max_decision(decision, PolicyDecision.REVIEW_REQUIRED)
            decision_severity = max_severity(decision_severity, PolicyDecisionSeverity.MEDIUM)
            review_notes.append("Phishing verdict requires analyst sign-off on response recommendations.")

        if false_positive_result:
            fp_prob = false_positive_result.false_positive_probability
            if fp_prob >= 0.75 and (
                enriched.asset_is_critical or enriched.user_is_privileged or enriched.ioc_matched
            ):
                triggered_rules.append("P-09: FP_GUARDRAIL_HIGH_RISK_CONTEXT")
                triggered_conditions.append(
                    "false_positive_probability>=0.75 with critical/privileged/IOC context"
                )
                decision = max_decision(decision, PolicyDecision.REVIEW_REQUIRED)
                decision_severity = max_severity(decision_severity, PolicyDecisionSeverity.HIGH)
                review_notes.append(
                    "High FP estimate cannot auto-dismiss in high-risk context."
                )

        if next_best_action:
            sensitive_count = sum(1 for item in next_best_action.actions if item.sensitive)
            if sensitive_count > 0:
                triggered_rules.append("P-10: SENSITIVE_NEXT_ACTIONS_PRESENT")
                triggered_conditions.append(f"next_best_action.sensitive_count={sensitive_count}")
                decision = max_decision(decision, PolicyDecision.REVIEW_REQUIRED)
                decision_severity = max_severity(decision_severity, PolicyDecisionSeverity.MEDIUM)
                review_notes.append(
                    f"{sensitive_count} sensitive recommended action(s) require review."
                )

        # ------------------------------------------------------------------
        # Build final reason string
        # ------------------------------------------------------------------
        decision_rationale = (
            "No policy rules triggered — action is permitted."
            if not reason_parts
            else " | ".join(reason_parts)
        )
        policy_reasoning_summary = (
            "Policy decision combines contextual risk (asset/user), confidence thresholds, "
            "action sensitivity, compliance constraints, and guardrails against unsafe automation."
        )

        result = PolicyCheckResult(
            alert_id=enriched.alert_id,
            action_requested=action_requested,
            decision=decision,
            decision_severity=decision_severity,
            triggered_rules=triggered_rules,
            triggered_conditions=triggered_conditions,
            decision_rationale=decision_rationale,
            approval_role_required=approval_role_required,
            review_notes=review_notes,
            policy_reasoning_summary=policy_reasoning_summary,
            check_timestamp=datetime.utcnow(),
        )

        logger.info(
            f"[PolicyEngine] Decision for alert {enriched.alert_id}: "
            f"{decision} | rules triggered: {triggered_rules}"
        )
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _normalize_action_key(self, action: str) -> str:
        """Normalize an action description to a policy key for rule matching."""
        action_lower = action.lower()
        keyword_map = {
            "isolate": "isolate_endpoint",
            "block user": "block_user_account",
            "reset password": "reset_password",
            "password reset": "reset_password",
            "delete": "delete_files",
            "block ip": "block_ip",
            "block source ip": "block_ip",
            "disable": "disable_service",
            "revoke": "revoke_access",
            "quarantine": "network_quarantine",
            "legal hold": "legal_hold",
            "escalate to ciso": "escalate_to_ciso",
        }
        for keyword, key in keyword_map.items():
            if keyword in action_lower:
                return key
        return action_lower.replace(" ", "_")[:40]


def max_decision(
    current: PolicyDecision, new: PolicyDecision
) -> PolicyDecision:
    """
    Return the more restrictive of two policy decisions.
    Order: ALLOWED < REVIEW_REQUIRED < DENIED
    """
    order = {
        PolicyDecision.ALLOWED: 0,
        PolicyDecision.REVIEW_REQUIRED: 1,
        PolicyDecision.DENIED: 2,
    }
    if order[new] > order[current]:
        return new
    return current


def max_severity(
    current: PolicyDecisionSeverity, new: PolicyDecisionSeverity
) -> PolicyDecisionSeverity:
    order = {
        PolicyDecisionSeverity.LOW: 0,
        PolicyDecisionSeverity.MEDIUM: 1,
        PolicyDecisionSeverity.HIGH: 2,
        PolicyDecisionSeverity.CRITICAL: 3,
    }
    if order[new] > order[current]:
        return new
    return current
