"""
summarization_agent.py
----------------------
The Case Summarization Agent — Stage 3 of the SOC pipeline.

Responsibilities (bounded):
- Accept an enriched alert and the triage result
- Produce a concise, structured, analyst-ready case summary
- Generate both an executive summary (for management) and a technical summary
- List key findings, impacted entities, and recommended next steps

This agent NEVER executes actions. It ONLY produces structured text summaries.
No external LLM calls are made — summaries are assembled from structured data
using template-driven logic, keeping the prototype fully deterministic.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List

from schemas.input_schema import EnrichedAlert
from schemas.output_schema import CaseSummary, TriageResult

logger = logging.getLogger(__name__)

# Mapping from alert type to human-readable label for summaries
ALERT_TYPE_LABELS = {
    "brute_force": "Brute Force / Credential Attack",
    "phishing": "Phishing Campaign",
    "malware": "Malware / Endpoint Compromise",
    "ransomware": "Ransomware Incident",
    "data_exfiltration": "Data Exfiltration Attempt",
    "suspicious_login": "Suspicious Authentication Event",
    "insider_threat": "Insider Threat Indicator",
    "unknown": "Unknown Threat",
}

PRIORITY_LABELS = {
    "P1_CRITICAL": "P1 — Critical (Immediate Response Required)",
    "P2_HIGH": "P2 — High (Response within 1 hour)",
    "P3_MEDIUM": "P3 — Medium (Response within 4 hours)",
    "P4_LOW": "P4 — Low (Response within 24 hours)",
}


class SummarizationAgent:
    """
    Case Summarization Agent — Stage 3 of the SOC pipeline.

    Assembles a complete, structured case summary from enrichment and triage data.
    The output is designed to be directly usable in a SOC case management system.
    """

    VERSION = "1.0.0"

    def summarize(
        self, enriched: EnrichedAlert, triage: TriageResult
    ) -> CaseSummary:
        """
        Generate a complete case summary from enriched alert and triage result.

        Args:
            enriched: The output of the EnrichmentAgent.
            triage:   The output of the TriageAgent.

        Returns:
            A structured CaseSummary ready for case management.
        """
        logger.info(f"[SummarizationAgent] Summarizing alert {enriched.alert_id}")

        alert = enriched.original_alert
        alert_type_label = ALERT_TYPE_LABELS.get(alert.type, "Unknown Threat")
        priority_label = PRIORITY_LABELS.get(triage.priority, triage.priority)

        title = self._build_title(enriched, alert_type_label)
        exec_summary = self._build_executive_summary(enriched, triage, alert_type_label)
        tech_summary = self._build_technical_summary(enriched, triage)
        key_findings = self._extract_key_findings(enriched, triage)
        timeline = self._build_timeline(enriched, triage)
        impacted = self._identify_impacted_entities(enriched)
        next_steps = self._extract_next_steps(triage)
        risk_assessment = self._assess_risk(enriched, triage)
        estimated_impact = self._estimate_impact(enriched, triage)
        requires_escalation = (
            triage.priority in ("P1_CRITICAL", "P2_HIGH")
            or triage.requires_human_review
        )

        summary = CaseSummary(
            alert_id=enriched.alert_id,
            summary_title=title,
            executive_summary=exec_summary,
            technical_summary=tech_summary,
            key_findings=key_findings,
            timeline=timeline,
            impacted_entities=impacted,
            recommended_next_steps=next_steps,
            risk_assessment=risk_assessment,
            estimated_impact=estimated_impact,
            requires_escalation=requires_escalation,
            reasoning_summary=(
                "Summary is generated deterministically from enriched alert context, "
                "triage evidence, and governance-relevant indicators."
            ),
            summary_timestamp=datetime.utcnow(),
            agent_version=self.VERSION,
        )

        logger.info(
            f"[SummarizationAgent] Summary generated for {enriched.alert_id} "
            f"| escalation_required={requires_escalation}"
        )
        return summary

    # ------------------------------------------------------------------
    # Private builders
    # ------------------------------------------------------------------

    def _build_title(self, enriched: EnrichedAlert, alert_type_label: str) -> str:
        alert = enriched.original_alert
        asset_name = (
            enriched.asset_context.hostname if enriched.asset_context else alert.destination_ip
        )
        user_name = (
            enriched.user_context.username if enriched.user_context else "Unknown User"
        )
        return f"[{alert.alert_id}] {alert_type_label} — {asset_name} / {user_name}"

    def _build_executive_summary(
        self,
        enriched: EnrichedAlert,
        triage: TriageResult,
        alert_type_label: str,
    ) -> str:
        alert = enriched.original_alert
        asset_info = (
            f"asset '{enriched.asset_context.hostname}' "
            f"(criticality: {enriched.asset_context.criticality})"
            if enriched.asset_context
            else f"IP {alert.destination_ip}"
        )
        user_info = (
            f"user '{enriched.user_context.full_name}' "
            f"({enriched.user_context.department}, {enriched.user_context.privilege_level} privileges)"
            if enriched.user_context
            else "an unknown user"
        )
        ti_note = ""
        if enriched.ioc_matched:
            actors = {
                m.threat_actor for m in enriched.threat_intel_matches if m.threat_actor
            }
            ti_note = (
                f" Threat intelligence links this event to known actor(s): "
                f"{', '.join(actors)}." if actors else
                " Indicators match known threat intelligence entries."
            )
        human_note = (
            " Human analyst review is required before any action is taken."
            if triage.requires_human_review else ""
        )
        return (
            f"A {alert_type_label} event (classification: {triage.classification}, "
            f"priority: {triage.priority}) was detected on {asset_info}, "
            f"involving {user_info}.{ti_note} "
            f"The automated triage assigned confidence {triage.confidence:.0%}.{human_note}"
        )

    def _build_technical_summary(
        self, enriched: EnrichedAlert, triage: TriageResult
    ) -> str:
        alert = enriched.original_alert
        lines = [
            f"Alert ID: {alert.alert_id}",
            f"Source: {alert.source}",
            f"Type: {alert.type} | Severity: {alert.severity}",
            f"Source IP: {alert.source_ip} (known malicious: {enriched.source_ip_is_known_malicious})",
            f"Destination IP: {alert.destination_ip}",
            f"Timestamp: {alert.timestamp}",
            "",
            f"Description: {alert.description}",
            "",
        ]

        if enriched.user_context:
            u = enriched.user_context
            lines += [
                f"User: {u.full_name} ({u.username}) — {u.department}, {u.role}",
                f"  Privilege level: {u.privilege_level} | MFA: {'enabled' if u.mfa_enabled else 'DISABLED'}",
                f"  Risk score: {u.risk_score}/100",
                f"  Prior incidents: {', '.join(u.recent_incidents) if u.recent_incidents else 'None'}",
                "",
            ]

        if enriched.asset_context:
            a = enriched.asset_context
            lines += [
                f"Asset: {a.hostname} ({a.ip_address}) — {a.business_function}",
                f"  Criticality: {a.criticality} | Network zone: {a.network_zone}",
                f"  Data classification: {a.data_classification}",
                f"  Open vulnerabilities: {a.open_vulnerabilities}",
                "",
            ]

        if enriched.threat_intel_matches:
            lines.append("Threat Intelligence Matches:")
            for m in enriched.threat_intel_matches:
                lines.append(
                    f"  [{m.indicator_type.upper()}] {m.indicator_value} — "
                    f"{m.category} | Actor: {m.threat_actor or 'Unknown'} | "
                    f"Confidence: {m.confidence:.0%}"
                )
            lines.append("")

        lines += [
            f"Triage Result: {triage.classification} | {triage.priority} | "
            f"Suspicion: {triage.suspicion_level}",
            f"Agent confidence: {triage.confidence:.0%}",
        ]
        return "\n".join(lines)

    def _extract_key_findings(
        self, enriched: EnrichedAlert, triage: TriageResult
    ) -> List[str]:
        findings = list(triage.risk_factors)

        if enriched.related_cases:
            fp_cases = [c for c in enriched.related_cases if c.false_positive]
            tp_cases = [c for c in enriched.related_cases if not c.false_positive]
            if tp_cases:
                findings.append(
                    f"{len(tp_cases)} confirmed true-positive case(s) with similar pattern in history"
                )
            if fp_cases:
                findings.append(
                    f"{len(fp_cases)} historical case(s) with same pattern were false positives"
                )

        if not findings:
            findings.append("No high-risk signals identified — likely benign or low-risk event")

        return findings

    def _build_timeline(
        self, enriched: EnrichedAlert, triage: TriageResult
    ) -> List[Dict[str, str]]:
        alert = enriched.original_alert
        timeline = [
            {
                "time": str(alert.timestamp),
                "event": f"Alert generated by {alert.source}",
                "detail": alert.description,
            },
            {
                "time": str(enriched.enrichment_timestamp),
                "event": "Enrichment completed by EnrichmentAgent",
                "detail": (
                    f"User context: {'found' if enriched.user_context else 'not found'} | "
                    f"Asset context: {'found' if enriched.asset_context else 'not found'} | "
                    f"TI matches: {len(enriched.threat_intel_matches)} | "
                    f"Related cases: {len(enriched.related_cases)}"
                ),
            },
            {
                "time": str(triage.triage_timestamp),
                "event": "Triage completed by TriageAgent",
                "detail": (
                    f"Classification: {triage.classification} | "
                    f"Priority: {triage.priority} | "
                    f"Confidence: {triage.confidence:.0%}"
                ),
            },
        ]
        return timeline

    def _identify_impacted_entities(
        self, enriched: EnrichedAlert
    ) -> Dict[str, List[str]]:
        alert = enriched.original_alert
        entities: Dict[str, List[str]] = {
            "users": [],
            "assets": [],
            "ips": [alert.source_ip, alert.destination_ip],
            "domains": list(alert.ioc_domains),
        }
        if enriched.user_context:
            entities["users"].append(
                f"{enriched.user_context.full_name} ({enriched.user_context.user_id})"
            )
        if enriched.asset_context:
            entities["assets"].append(
                f"{enriched.asset_context.hostname} ({enriched.asset_context.asset_id})"
            )
        return entities

    def _extract_next_steps(self, triage: TriageResult) -> List[str]:
        return [action.description for action in triage.recommended_actions]

    def _assess_risk(self, enriched: EnrichedAlert, triage: TriageResult) -> str:
        if triage.priority == "P1_CRITICAL":
            return (
                "CRITICAL — Immediate containment required. "
                "Potential for significant business disruption or data loss."
            )
        elif triage.priority == "P2_HIGH":
            return (
                "HIGH — Prompt investigation required. "
                "Asset or data confidentiality may be at risk."
            )
        elif triage.priority == "P3_MEDIUM":
            return (
                "MEDIUM — Scheduled investigation recommended. "
                "Monitor for escalation indicators."
            )
        else:
            return "LOW — Routine monitoring. Investigate during normal business hours."

    def _estimate_impact(self, enriched: EnrichedAlert, triage: TriageResult) -> str:
        if not enriched.asset_context:
            return "Impact unknown — asset context unavailable."
        a = enriched.asset_context
        scopes = ", ".join(a.compliance_scope) if a.compliance_scope else "none"
        return (
            f"Potentially impacts: {a.business_function}. "
            f"Data classification: {a.data_classification}. "
            f"Compliance scope: {scopes}."
        )
