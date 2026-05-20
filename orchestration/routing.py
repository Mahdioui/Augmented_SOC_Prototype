"""
routing.py
----------
Conditional route helpers for the LangGraph state machine.
"""

from __future__ import annotations

from schemas.input_schema import AlertType


def route_specialized_agent(state: dict) -> str:
    alert = state.get("alert")
    if not alert:
        return "skip_specialized"
    alert_type = AlertType(alert.type)
    if alert_type == AlertType.PHISHING:
        return "phishing"
    if alert_type in (AlertType.SUSPICIOUS_LOGIN, AlertType.UNKNOWN):
        return "identity"
    return "skip_specialized"
