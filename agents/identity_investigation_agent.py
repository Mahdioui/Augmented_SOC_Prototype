"""
identity_investigation_agent.py
-------------------------------
Specialized identity/suspicious-login investigation agent.
Recommendation-only, no account actions executed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List

from connectors.iam_stub import IAMStub
from rag.retriever import retrieve_documents
from schemas.input_schema import EnrichedAlert


class IdentityInvestigationAgent:
    VERSION = "1.0.0"

    def __init__(self):
        self.iam = IAMStub()

    def investigate(self, enriched: EnrichedAlert) -> Dict[str, object]:
        user_info = self.iam.get_user_context(enriched.user_context)
        risk_score = 0.0
        anomalies: List[str] = []

        if user_info.get("user_found"):
            if not user_info.get("mfa_enabled", True):
                risk_score += 0.20
                anomalies.append("MFA disabled")
            if user_info.get("privilege_level") in ("admin", "privileged", "elevated"):
                risk_score += 0.25
                anomalies.append("Privileged account involved")
            if user_info.get("risk_score", 0) >= 50:
                risk_score += 0.20
                anomalies.append("High identity risk score")
            if user_info.get("recent_incidents"):
                risk_score += 0.15
                anomalies.append("User linked to prior incidents")

        if enriched.original_alert.type in ("suspicious_login", "identity"):
            risk_score += 0.10
        if enriched.source_ip_is_known_malicious:
            risk_score += 0.15
            anomalies.append("Known malicious source IP")

        risk_score = round(min(1.0, risk_score), 2)
        if risk_score >= 0.7:
            recommendation = "Escalate to Tier 2 for focused identity compromise investigation."
        elif risk_score >= 0.4:
            recommendation = "Require analyst validation and session/activity review."
        else:
            recommendation = "Monitor and validate context; likely low to medium identity risk."

        sources = [doc["id"] for doc in retrieve_documents("suspicious login mfa privileged investigation")]
        return {
            "alert_id": enriched.alert_id,
            "identity_risk_score": risk_score,
            "user_context": user_info,
            "anomalies": anomalies,
            "recommendation": recommendation,
            "reasoning_summary": (
                "Identity risk estimated from MFA posture, privilege level, incident history, "
                "source reputation, and suspicious login context."
            ),
            "sources_consulted": sources,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "agent_version": self.VERSION,
        }
