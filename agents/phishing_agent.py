"""
phishing_agent.py
-----------------
The Phishing Analysis Agent — specialized sub-agent for phishing alerts.

Responsibilities (bounded):
- Accept a raw or enriched alert of type 'phishing'
- Apply domain-specific phishing detection rules
- Return a structured PhishingAnalysisResult with verdict, score, and indicators

This agent focuses on signals specific to phishing:
  - Domain spoofing / lookalike domains
  - Known phishing infrastructure in threat intel
  - Sender impersonation patterns
  - Credential harvesting indicators
  - Target profile (privileged user, finance department, etc.)

This agent NEVER executes actions. It ONLY produces an analysis verdict.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import List, Optional

from schemas.input_schema import EnrichedAlert, PrivilegeLevel
from schemas.output_schema import (
    PhishingAnalysisResult,
    PhishingIndicator,
    PhishingVerdict,
)

logger = logging.getLogger(__name__)

# Domains known to be associated with internal IT or trusted brands (mock list)
LEGITIMATE_INTERNAL_DOMAINS = {
    "bank.internal",
    "bank.dz",
    "microsoft.com",
    "google.com",
    "office365.com",
}

# Keywords that suggest impersonation of IT/support
IMPERSONATION_KEYWORDS = [
    "password reset", "account suspended", "urgent", "verify your account",
    "click here", "login required", "security alert", "it support",
    "helpdesk", "credential", "confirm your identity",
]

# Top-level domains frequently abused for phishing
SUSPICIOUS_TLDS = {".xyz", ".ru", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw"}


class PhishingAgent:
    """
    Phishing Analysis Agent — specialized analysis for phishing-type alerts.

    Applies a weighted indicator model to produce a phishing score and verdict.
    All indicators and their weights are documented and explainable.
    """

    VERSION = "1.0.0"
    VERDICT_THRESHOLD_CONFIRMED = 0.75
    VERDICT_THRESHOLD_LIKELY = 0.50
    VERDICT_THRESHOLD_SUSPICIOUS = 0.30

    def analyze(self, enriched: EnrichedAlert) -> PhishingAnalysisResult:
        """
        Perform phishing analysis on an enriched alert.

        Args:
            enriched: A fully enriched alert (should be type 'phishing').

        Returns:
            A structured PhishingAnalysisResult.
        """
        logger.info(f"[PhishingAgent] Analyzing alert {enriched.alert_id}")

        alert = enriched.original_alert
        indicators: List[PhishingIndicator] = []
        total_weight = 0.0
        confidence_score = 0.5  # baseline confidence

        # ------------------------------------------------------------------
        # Check 1: Threat intel match on domains
        # ------------------------------------------------------------------
        for match in enriched.threat_intel_matches:
            if match.indicator_type == "domain":
                indicators.append(PhishingIndicator(
                    indicator_type="threat_intel_domain",
                    value=match.indicator_value,
                    description=(
                        f"Domain '{match.indicator_value}' is listed in threat intelligence "
                        f"as {match.category} (actor: {match.threat_actor or 'unknown'}, "
                        f"confidence: {match.confidence:.0%})"
                    ),
                    weight=0.40,
                ))
                total_weight += 0.40
                confidence_score = min(1.0, confidence_score + match.confidence * 0.2)

        # ------------------------------------------------------------------
        # Check 2: Threat intel match on source IP
        # ------------------------------------------------------------------
        if enriched.source_ip_is_known_malicious:
            indicators.append(PhishingIndicator(
                indicator_type="malicious_ip",
                value=alert.source_ip,
                description=(
                    f"Source IP {alert.source_ip} is known phishing/malicious infrastructure"
                ),
                weight=0.30,
            ))
            total_weight += 0.30
            confidence_score = min(1.0, confidence_score + 0.15)

        # ------------------------------------------------------------------
        # Check 3: Suspicious TLD in IOC domains
        # ------------------------------------------------------------------
        for domain in alert.ioc_domains:
            domain_lower = domain.lower()
            for tld in SUSPICIOUS_TLDS:
                if domain_lower.endswith(tld):
                    indicators.append(PhishingIndicator(
                        indicator_type="suspicious_tld",
                        value=domain,
                        description=(
                            f"Domain '{domain}' uses a TLD frequently abused for phishing ('{tld}')"
                        ),
                        weight=0.20,
                    ))
                    total_weight += 0.20
                    confidence_score = min(1.0, confidence_score + 0.05)
                    break

        # ------------------------------------------------------------------
        # Check 4: Lookalike domain detection
        # ------------------------------------------------------------------
        impersonated = self._detect_impersonated_entity(alert.ioc_domains, alert.raw_log)
        if impersonated:
            indicators.append(PhishingIndicator(
                indicator_type="lookalike_domain",
                value=impersonated["domain"],
                description=(
                    f"Domain '{impersonated['domain']}' appears to impersonate "
                    f"'{impersonated['target']}' (brand impersonation)"
                ),
                weight=0.35,
            ))
            total_weight += 0.35
            confidence_score = min(1.0, confidence_score + 0.10)

        # ------------------------------------------------------------------
        # Check 5: Impersonation keywords in raw log / description
        # ------------------------------------------------------------------
        text_to_check = (alert.raw_log + " " + alert.description).lower()
        matched_keywords = [
            kw for kw in IMPERSONATION_KEYWORDS if kw in text_to_check
        ]
        if matched_keywords:
            indicators.append(PhishingIndicator(
                indicator_type="impersonation_keywords",
                value=", ".join(matched_keywords[:5]),
                description=(
                    f"Email content contains social engineering keywords: "
                    f"{', '.join(matched_keywords[:5])}"
                ),
                weight=0.25,
            ))
            total_weight += 0.25
            confidence_score = min(1.0, confidence_score + 0.05)

        # ------------------------------------------------------------------
        # Check 6: Targeted high-value user (privileged or finance)
        # ------------------------------------------------------------------
        credential_risk = False
        if enriched.user_context:
            is_privileged = enriched.user_context.privilege_level in (
                PrivilegeLevel.PRIVILEGED, PrivilegeLevel.ADMIN, PrivilegeLevel.ELEVATED
            )
            is_finance = "finance" in enriched.user_context.department.lower()
            if is_privileged:
                indicators.append(PhishingIndicator(
                    indicator_type="high_value_target",
                    value=enriched.user_context.username,
                    description=(
                        f"Target is a privileged user ({enriched.user_context.privilege_level}) "
                        f"— credential theft would grant elevated access"
                    ),
                    weight=0.25,
                ))
                total_weight += 0.25
                credential_risk = True
                confidence_score = min(1.0, confidence_score + 0.10)
            elif is_finance:
                indicators.append(PhishingIndicator(
                    indicator_type="finance_department_target",
                    value=enriched.user_context.username,
                    description="Target is in Finance department — BEC or fraud risk elevated",
                    weight=0.15,
                ))
                total_weight += 0.15
                confidence_score = min(1.0, confidence_score + 0.05)

        # ------------------------------------------------------------------
        # Check 7: No MFA on targeted account
        # ------------------------------------------------------------------
        if enriched.user_context and not enriched.user_context.mfa_enabled:
            indicators.append(PhishingIndicator(
                indicator_type="no_mfa",
                value=enriched.user_context.username,
                description=(
                    f"Target account has no MFA — credential theft would give immediate access"
                ),
                weight=0.20,
            ))
            total_weight += 0.20
            credential_risk = True

        # ------------------------------------------------------------------
        # Compute phishing score and derive verdict
        # ------------------------------------------------------------------
        phishing_score = min(1.0, total_weight)
        verdict = self._derive_verdict(phishing_score)

        recommended_actions = self._build_recommendations(
            verdict, enriched, indicators, credential_risk
        )

        explanation = self._build_explanation(
            verdict, phishing_score, indicators, confidence_score
        )
        reasoning_summary = (
            "Phishing verdict is derived from explicit indicator weights "
            "(TI matches, impersonation patterns, target profile, and MFA posture)."
        )

        result = PhishingAnalysisResult(
            alert_id=enriched.alert_id,
            verdict=verdict,
            phishing_score=round(phishing_score, 2),
            indicators_found=indicators,
            impersonated_entity=(
                impersonated["target"] if impersonated else None
            ),
            credential_harvesting_risk=credential_risk,
            recommended_actions=recommended_actions,
            confidence=round(confidence_score, 2),
            explanation=explanation,
            reasoning_summary=reasoning_summary,
            analysis_timestamp=datetime.utcnow(),
        )

        logger.info(
            f"[PhishingAgent] Alert {enriched.alert_id} → verdict={verdict} | "
            f"score={phishing_score:.2f} | confidence={confidence_score:.2f}"
        )
        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _detect_impersonated_entity(
        self, domains: List[str], raw_log: str
    ) -> Optional[dict]:
        """
        Detect if any of the alert domains appear to be lookalike/typosquat
        versions of legitimate internal or brand domains.
        """
        legitimate_brands = {
            "bank": "bank.internal",
            "microsoft": "microsoft.com",
            "office365": "office365.com",
            "helpdesk": "bank.internal IT helpdesk",
            "it-support": "bank.internal IT department",
        }

        for domain in domains:
            domain_lower = domain.lower()
            for brand_keyword, legitimate_name in legitimate_brands.items():
                # Lookalike: contains the brand keyword but is not the legit domain
                if (
                    brand_keyword in domain_lower
                    and domain_lower not in LEGITIMATE_INTERNAL_DOMAINS
                ):
                    return {"domain": domain, "target": legitimate_name}

        # Also check the raw log for explicit impersonation mentions
        for brand_keyword, legitimate_name in legitimate_brands.items():
            if brand_keyword in raw_log.lower():
                return {"domain": "email_sender", "target": legitimate_name}

        return None

    def _derive_verdict(self, phishing_score: float) -> PhishingVerdict:
        """Map a phishing score to a categorical verdict."""
        if phishing_score >= self.VERDICT_THRESHOLD_CONFIRMED:
            return PhishingVerdict.CONFIRMED_PHISHING
        elif phishing_score >= self.VERDICT_THRESHOLD_LIKELY:
            return PhishingVerdict.LIKELY_PHISHING
        elif phishing_score >= self.VERDICT_THRESHOLD_SUSPICIOUS:
            return PhishingVerdict.SUSPICIOUS
        else:
            return PhishingVerdict.BENIGN

    def _build_recommendations(
        self,
        verdict: PhishingVerdict,
        enriched: EnrichedAlert,
        indicators: List[PhishingIndicator],
        credential_risk: bool,
    ) -> List[str]:
        """Build a prioritized list of recommended actions based on the verdict."""
        actions = []

        if verdict in (PhishingVerdict.CONFIRMED_PHISHING, PhishingVerdict.LIKELY_PHISHING):
            actions.append("Quarantine the phishing email from all recipient mailboxes")
            actions.append("Block all identified malicious domains at email gateway and DNS")
            if credential_risk:
                actions.append(
                    "Force password reset for targeted user(s) — credential theft risk confirmed"
                )
                actions.append("Audit recent logins for compromised account(s)")
            actions.append("Send phishing awareness notification to all employees")
            actions.append("Update email gateway block lists with new indicators")

        elif verdict == PhishingVerdict.SUSPICIOUS:
            actions.append("Flag email for manual analyst review before delivery")
            actions.append("Notify targeted user to verify sender authenticity")
            actions.append("Monitor for further phishing attempts from same source")

        else:
            actions.append("Log event and monitor — verdict is likely benign")

        actions.append("Document all IOCs for threat intelligence sharing")
        return actions

    def _build_explanation(
        self,
        verdict: PhishingVerdict,
        score: float,
        indicators: List[PhishingIndicator],
        confidence: float,
    ) -> str:
        parts = [
            f"Phishing verdict: {verdict} | Score: {score:.0%} | Confidence: {confidence:.0%}",
            "",
            "Indicators detected:",
        ]
        for i, ind in enumerate(indicators, 1):
            parts.append(f"  {i}. [{ind.indicator_type}] {ind.description} (weight: {ind.weight:.0%})")

        if not indicators:
            parts.append("  No phishing indicators detected.")

        return "\n".join(parts)
