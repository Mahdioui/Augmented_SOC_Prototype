"""
knowledge_base.py
-----------------
Synthetic internal knowledge base for prototype RAG-like retrieval.
"""

from __future__ import annotations

from typing import Dict, List


def load_knowledge_base() -> List[Dict[str, str]]:
    return [
        {
            "id": "kb-playbook-alert-triage",
            "title": "SOC Alert Triage Playbook",
            "content": "Prioritize by asset criticality, user privilege, IOC quality, and business impact.",
        },
        {
            "id": "kb-runbook-phishing",
            "title": "Phishing Runbook",
            "content": "Validate sender infrastructure, inspect links/domains, assess credential theft risk, notify users.",
        },
        {
            "id": "kb-runbook-suspicious-login",
            "title": "Suspicious Login Runbook",
            "content": "Check impossible travel, MFA challenge outcomes, session token anomalies, and privileged activity.",
        },
        {
            "id": "kb-mitre-mapping",
            "title": "MITRE ATT&CK Simplified Mapping",
            "content": "Credential Access, Initial Access, Lateral Movement, Exfiltration, Command and Control.",
        },
        {
            "id": "kb-escalation-policy",
            "title": "Escalation Procedure",
            "content": "P1/P2 and regulated assets require Tier 2 or security management review before sensitive actions.",
        },
    ]
