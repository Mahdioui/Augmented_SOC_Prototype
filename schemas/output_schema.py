"""
output_schema.py
----------------
Structured output schemas for the governed, AI-assisted SOC prototype.
All outputs are explicit, typed, and audit-friendly.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from schemas.input_schema import EnrichedAlert, RawAlert


class TriageClassification(str, Enum):
    TRUE_POSITIVE = "true_positive"
    LIKELY_TRUE_POSITIVE = "likely_true_positive"
    UNCERTAIN = "uncertain"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    FALSE_POSITIVE = "false_positive"


class TriagePriority(str, Enum):
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"


class SuspicionLevel(str, Enum):
    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class PolicyDecision(str, Enum):
    ALLOWED = "allowed"
    REVIEW_REQUIRED = "review_required"
    DENIED = "denied"


class PolicyDecisionSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PhishingVerdict(str, Enum):
    CONFIRMED_PHISHING = "confirmed_phishing"
    LIKELY_PHISHING = "likely_phishing"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class ActionCategory(str, Enum):
    INVESTIGATIVE = "investigative"
    ENRICHMENT = "enrichment"
    COMMUNICATION = "communication"
    ESCALATION = "escalation"
    CONTAINMENT_RECOMMENDATION = "containment_recommendation"


class RecommendedAction(BaseModel):
    action_id: str
    description: str
    urgency: str = Field(..., description="immediate | short_term | long_term")
    requires_human: bool = True
    reversible: bool = True


class TriageResult(BaseModel):
    alert_id: str
    classification: TriageClassification
    priority: TriagePriority
    suspicion_level: SuspicionLevel
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0)
    explanation: str
    reasoning_summary: str = ""
    triage_timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent_version: str = "1.0.0"
    requires_human_review: bool = False
    risk_factors: List[str] = Field(default_factory=list)

    model_config = {"use_enum_values": True}


class PhishingIndicator(BaseModel):
    indicator_type: str
    value: str
    description: str
    weight: float = Field(..., ge=0.0, le=1.0)


class PhishingAnalysisResult(BaseModel):
    alert_id: str
    verdict: PhishingVerdict
    phishing_score: float = Field(..., ge=0.0, le=1.0)
    indicators_found: List[PhishingIndicator] = Field(default_factory=list)
    impersonated_entity: Optional[str] = None
    credential_harvesting_risk: bool = False
    recommended_actions: List[str] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0)
    explanation: str
    reasoning_summary: str = ""
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow)

    model_config = {"use_enum_values": True}


class FalsePositivePredictionResult(BaseModel):
    alert_id: str
    false_positive_probability: float = Field(..., ge=0.0, le=1.0)
    prediction_confidence: float = Field(..., ge=0.0, le=1.0)
    explanation: str
    reasoning_summary: str
    recommended_handling: str
    priority_adjustment_suggestion: str
    risk_notes: List[str] = Field(default_factory=list)
    governance_guardrail_applied: bool = False
    prediction_timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent_version: str = "1.0.0"


class NextBestActionItem(BaseModel):
    action_id: str
    action: str
    rationale: str
    action_category: ActionCategory
    investigative_only: bool = True
    requires_analyst_review: bool = True
    sensitive: bool = False
    confidence: float = Field(..., ge=0.0, le=1.0)


class NextBestActionResult(BaseModel):
    alert_id: str
    actions: List[NextBestActionItem] = Field(default_factory=list)
    reasoning_summary: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    explanation: str
    generated_timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent_version: str = "1.0.0"


class CaseSummary(BaseModel):
    alert_id: str
    summary_title: str
    executive_summary: str
    technical_summary: str
    key_findings: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, str]] = Field(default_factory=list)
    impacted_entities: Dict[str, List[str]] = Field(default_factory=dict)
    recommended_next_steps: List[str] = Field(default_factory=list)
    risk_assessment: str
    estimated_impact: str
    requires_escalation: bool = False
    reasoning_summary: str = ""
    summary_timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent_version: str = "1.0.0"


class PolicyCheckResult(BaseModel):
    alert_id: str
    action_requested: str
    decision: PolicyDecision
    decision_severity: PolicyDecisionSeverity = PolicyDecisionSeverity.LOW
    policy_id: str = "SOC_POLICY_ENGINE_V2"
    policy_description: str = "Governed decision gate for AI-assisted recommendations."
    triggered_rules: List[str] = Field(default_factory=list)
    triggered_conditions: List[str] = Field(default_factory=list)
    decision_rationale: str
    approval_role_required: Optional[str] = None
    review_notes: List[str] = Field(default_factory=list)
    policy_reasoning_summary: str = ""
    check_timestamp: datetime = Field(default_factory=datetime.utcnow)

    model_config = {"use_enum_values": True}


class AuditLogEntry(BaseModel):
    log_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    alert_id: str
    agent_name: str
    input_summary: str
    decision: str
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    action_proposed: Optional[str] = None
    policy_result: Optional[str] = None
    requires_human_review: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class OrchestratorResult(BaseModel):
    alert_id: str
    pipeline_status: str = Field(..., description="completed | partial | failed")
    raw_alert: Optional[RawAlert] = None
    enriched_alert: Optional[EnrichedAlert] = None
    triage_result: Optional[TriageResult] = None
    phishing_result: Optional[PhishingAnalysisResult] = None
    false_positive_prediction: Optional[FalsePositivePredictionResult] = None
    next_best_action: Optional[NextBestActionResult] = None
    case_summary: Optional[CaseSummary] = None
    policy_check: Optional[PolicyCheckResult] = None
    audit_entries: List[AuditLogEntry] = Field(default_factory=list)
    audit_reference_ids: List[str] = Field(default_factory=list)
    final_consolidated_explanation: str = ""
    output_artifacts: Dict[str, str] = Field(default_factory=dict)
    total_processing_time_ms: float = 0.0
    pipeline_timestamp: datetime = Field(default_factory=datetime.utcnow)
    errors: List[str] = Field(default_factory=list)
