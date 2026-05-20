"""
langgraph_graph.py
------------------
LangGraph state-machine orchestration for chapter-6 alignment.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict

from agents.alert_triage_agent import AlertTriageAgent
from agents.case_summary_agent import CaseSummaryAgent
from agents.enrichment_agent import EnrichmentAgent
from agents.false_positive_prediction_agent import FalsePositivePredictionAgent
from agents.identity_investigation_agent import IdentityInvestigationAgent
from agents.next_best_action_agent import NextBestActionAgent
from agents.phishing_triage_agent import PhishingTriageAgent
from governance.audit_logger import GovernanceAuditLogger
from governance.policy_engine import GovernancePolicyEngine
from orchestration.routing import route_specialized_agent
from orchestration.state import SOCGraphState
from persistence.result_store import ResultStore
from persistence.sqlite_store import SQLiteStore
from schemas.input_schema import RawAlert
from schemas.output_schema import OrchestratorResult, PolicyCheckResult


class GraphRuntime:
    def __init__(self):
        self.enrichment = EnrichmentAgent()
        self.triage = AlertTriageAgent()
        self.summary = CaseSummaryAgent()
        self.phishing = PhishingTriageAgent()
        self.identity = IdentityInvestigationAgent()
        self.fp = FalsePositivePredictionAgent()
        self.nba = NextBestActionAgent()
        self.policy = GovernancePolicyEngine()
        self.audit = GovernanceAuditLogger("audit_trail.jsonl")
        self.result_store = ResultStore()
        self.sqlite = SQLiteStore()


def _ingest_alert(state: SOCGraphState) -> SOCGraphState:
    alert = state["alert"]
    state["result"] = OrchestratorResult(
        alert_id=alert.alert_id,
        raw_alert=alert,
        pipeline_status="in_progress",
    )
    state["request_id"] = state.get("request_id") or str(uuid.uuid4())
    return state


def _enrich_alert(state: SOCGraphState, rt: GraphRuntime) -> SOCGraphState:
    enriched = rt.enrichment.enrich(state["alert"])
    state["result"].enriched_alert = enriched
    return state


def _triage_alert(state: SOCGraphState, rt: GraphRuntime) -> SOCGraphState:
    enriched = state["result"].enriched_alert
    triage = rt.triage.evaluate_alert(enriched)
    state["result"].triage_result = triage
    state["result"].false_positive_prediction = rt.fp.predict(enriched, triage)
    state["result"].next_best_action = rt.nba.recommend(
        enriched, triage, state["result"].false_positive_prediction
    )
    return state


def _route_specialized(state: SOCGraphState) -> SOCGraphState:
    state["route"] = route_specialized_agent(state)
    return state


def _phishing_triage(state: SOCGraphState, rt: GraphRuntime) -> SOCGraphState:
    state["result"].phishing_result = rt.phishing.analyze(state["result"].enriched_alert)
    return state


def _identity_investigation(state: SOCGraphState, rt: GraphRuntime) -> SOCGraphState:
    context = dict(state.get("context") or {})
    context["identity_investigation"] = rt.identity.investigate(state["result"].enriched_alert)
    state["context"] = context
    return state


def _summarize_case(state: SOCGraphState, rt: GraphRuntime) -> SOCGraphState:
    result = state["result"]
    result.case_summary = rt.summary.summarize(result.enriched_alert, result.triage_result)
    return state


def _policy_check(state: SOCGraphState, rt: GraphRuntime) -> SOCGraphState:
    triage = state["result"].triage_result
    action_name = "recommend_priority"
    if triage and triage.recommended_actions:
        first = triage.recommended_actions[0].description.lower()
        if "ticket" in first:
            action_name = "create_ticket_draft"
        elif "summary" in first or "document" in first:
            action_name = "summarize_case"
        elif "block" in first:
            action_name = "block_ip"
        elif "isolate" in first:
            action_name = "isolate_endpoint"
        elif "disable" in first:
            action_name = "disable_user_account"
        elif "tier 2" in first or "escalate" in first:
            action_name = "escalate_to_t2"
    decision = rt.policy.evaluate(action_name=action_name, confidence=triage.confidence if triage else 0.0)
    mapping = {
        "ALLOW": "allowed",
        "REQUIRE_APPROVAL": "review_required",
        "BLOCK": "denied",
        "ESCALATE": "review_required",
    }
    state["result"].policy_check = PolicyCheckResult(
        alert_id=state["result"].alert_id,
        action_requested=action_name,
        decision=mapping.get(decision["decision"], "review_required"),
        triggered_rules=decision["triggered_rules"],
        triggered_conditions=[f"confidence={triage.confidence if triage else 0.0:.2f}"],
        decision_rationale=decision["decision_rationale"],
        approval_role_required=decision["approval_role_required"],
        policy_reasoning_summary="YAML policy evaluation applied in governed prototype mode.",
    )
    return state


def _human_validation_stub(state: SOCGraphState) -> SOCGraphState:
    result = state["result"]
    if result.policy_check and result.policy_check.decision in ("review_required", "denied"):
        result.final_consolidated_explanation += (
            "\nHuman-in-the-loop validation required before sensitive/blocked action."
        )
    return state


def _audit_and_persist(state: SOCGraphState, rt: GraphRuntime) -> SOCGraphState:
    result = state["result"]
    result.pipeline_status = "completed"
    result.final_consolidated_explanation = (
        result.final_consolidated_explanation
        or "LangGraph workflow completed with governed AI-assisted processing."
    )

    record = rt.audit.log_event(
        request_id=state["request_id"],
        case_id=result.alert_id,
        agent="langgraph_orchestrator",
        model_id="mock-llm-deterministic-v1",
        prompt_version="v1",
        sources=["synthetic_data", "internal_kb"],
        tools_called=["enrichment", "triage", "policy", "persistence"],
        proposed_action=(result.policy_check.action_requested if result.policy_check else ""),
        confidence=(result.triage_result.confidence if result.triage_result else 0.0),
        policy_decision=(result.policy_check.decision if result.policy_check else "review_required"),
        human_validation=(
            "required" if result.policy_check and result.policy_check.decision != "allowed" else "not_required"
        ),
        final_outcome=result.pipeline_status,
    )
    artifacts = rt.result_store.save(result)
    result.output_artifacts = artifacts
    rt.sqlite.insert_run(
        alert_id=result.alert_id,
        workflow="langgraph",
        status=result.pipeline_status,
        final_decision=(result.triage_result.classification if result.triage_result else None),
        policy_decision=(result.policy_check.decision if result.policy_check else None),
        output_path=artifacts.get("orchestrator_json"),
    )
    result.audit_reference_ids = [record.request_id]
    state["artifacts"] = artifacts
    return state


def build_soc_graph():
    from langgraph.graph import END, StateGraph

    graph = StateGraph(SOCGraphState)
    graph.add_node("ingest_alert", lambda s: _ingest_alert(s))
    graph.add_node("enrich_alert", lambda s: _enrich_alert(s, _RUNTIME))
    graph.add_node("triage_alert", lambda s: _triage_alert(s, _RUNTIME))
    graph.add_node("route_specialized_agent", lambda s: _route_specialized(s))
    graph.add_node("phishing_triage", lambda s: _phishing_triage(s, _RUNTIME))
    graph.add_node("identity_investigation", lambda s: _identity_investigation(s, _RUNTIME))
    graph.add_node("summarize_case", lambda s: _summarize_case(s, _RUNTIME))
    graph.add_node("policy_check", lambda s: _policy_check(s, _RUNTIME))
    graph.add_node("human_validation_stub", lambda s: _human_validation_stub(s))
    graph.add_node("audit_and_persist", lambda s: _audit_and_persist(s, _RUNTIME))

    graph.set_entry_point("ingest_alert")
    graph.add_edge("ingest_alert", "enrich_alert")
    graph.add_edge("enrich_alert", "triage_alert")
    graph.add_edge("triage_alert", "route_specialized_agent")
    graph.add_conditional_edges(
        "route_specialized_agent",
        lambda state: state.get("route", "skip_specialized"),
        {
            "phishing": "phishing_triage",
            "identity": "identity_investigation",
            "skip_specialized": "summarize_case",
        },
    )
    graph.add_edge("phishing_triage", "summarize_case")
    graph.add_edge("identity_investigation", "summarize_case")
    graph.add_edge("summarize_case", "policy_check")
    graph.add_edge("policy_check", "human_validation_stub")
    graph.add_edge("human_validation_stub", "audit_and_persist")
    graph.add_edge("audit_and_persist", END)
    return graph.compile()


_RUNTIME = GraphRuntime()


def run_graph(alert: RawAlert) -> OrchestratorResult:
    app = build_soc_graph()
    state: SOCGraphState = {"mode": "langgraph", "alert": alert}
    out = app.invoke(state)
    return out["result"]
