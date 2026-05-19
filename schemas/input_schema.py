"""
input_schema.py
---------------
Pydantic models for all incoming data structures consumed by the SOC agents.
These models enforce strict validation on every piece of data entering the pipeline.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(str, Enum):
    BRUTE_FORCE = "brute_force"
    PHISHING = "phishing"
    MALWARE = "malware"
    DATA_EXFILTRATION = "data_exfiltration"
    SUSPICIOUS_LOGIN = "suspicious_login"
    INSIDER_THREAT = "insider_threat"
    RANSOMWARE = "ransomware"
    UNKNOWN = "unknown"


class PrivilegeLevel(str, Enum):
    STANDARD = "standard"
    ELEVATED = "elevated"
    PRIVILEGED = "privileged"
    ADMIN = "admin"


class AssetCriticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


# ---------------------------------------------------------------------------
# Raw Alert (input from SIEM / source system)
# ---------------------------------------------------------------------------

class RawAlert(BaseModel):
    """Represents an alert as received from a source system (SIEM, EDR, etc.)."""

    alert_id: str = Field(..., description="Unique alert identifier")
    timestamp: datetime = Field(..., description="Alert generation timestamp (UTC)")
    source: str = Field(..., description="Source system that generated the alert")
    type: AlertType = Field(..., description="Alert type / category")
    severity: AlertSeverity = Field(..., description="Raw severity assigned by the source")
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: str = Field(..., description="Destination IP address")
    user_id: Optional[str] = Field(None, description="Associated user identifier")
    asset_id: Optional[str] = Field(None, description="Associated asset identifier")
    description: str = Field(..., description="Human-readable alert description")
    raw_log: str = Field(..., description="Original log line / raw event")
    ioc_hashes: List[str] = Field(default_factory=list, description="File hashes flagged as IOC")
    ioc_domains: List[str] = Field(default_factory=list, description="Domains flagged as IOC")
    status: AlertStatus = Field(default=AlertStatus.OPEN)

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# User Context (from IAM / HR systems)
# ---------------------------------------------------------------------------

class UserContext(BaseModel):
    """Contextual information about the user associated with the alert."""

    user_id: str
    username: str
    full_name: str
    department: str
    role: str
    privilege_level: PrivilegeLevel
    email: str
    active: bool
    mfa_enabled: bool
    risk_score: int = Field(..., ge=0, le=100, description="Current user risk score (0-100)")
    recent_incidents: List[str] = Field(default_factory=list)
    location: str
    access_clearance: str

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# Asset Context (from CMDB / asset inventory)
# ---------------------------------------------------------------------------

class AssetContext(BaseModel):
    """Contextual information about the asset associated with the alert."""

    asset_id: str
    hostname: str
    ip_address: str
    type: str
    os: str
    criticality: AssetCriticality
    classification: str
    business_function: str
    data_classification: str
    compliance_scope: List[str] = Field(default_factory=list)
    patch_status: str
    open_vulnerabilities: int = Field(..., ge=0)
    network_zone: str

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# Threat Intelligence Match
# ---------------------------------------------------------------------------

class ThreatIntelMatch(BaseModel):
    """A threat intelligence indicator match found for an alert IOC."""

    indicator_type: str = Field(..., description="ip | domain | hash")
    indicator_value: str
    reputation: str
    category: str
    threat_actor: Optional[str] = None
    confidence: float = Field(..., ge=0.0, le=1.0)
    source: str


# ---------------------------------------------------------------------------
# Historical Case Reference
# ---------------------------------------------------------------------------

class CaseReference(BaseModel):
    """A reference to a past case relevant to the current alert."""

    case_id: str
    title: str
    type: str
    status: str
    severity: str
    false_positive: bool
    ttr_hours: float
    resolution: str


# ---------------------------------------------------------------------------
# Enriched Alert (output of EnrichmentAgent, input to TriageAgent)
# ---------------------------------------------------------------------------

class EnrichedAlert(BaseModel):
    """An alert enriched with full context - this is the canonical enriched object."""

    alert_id: str
    original_alert: RawAlert

    # Enrichment fields
    user_context: Optional[UserContext] = None
    asset_context: Optional[AssetContext] = None
    threat_intel_matches: List[ThreatIntelMatch] = Field(default_factory=list)
    related_cases: List[CaseReference] = Field(default_factory=list)

    # Computed enrichment signals
    source_ip_is_known_malicious: bool = False
    ioc_matched: bool = False
    user_has_recent_incidents: bool = False
    asset_is_critical: bool = False
    user_is_privileged: bool = False

    # Enrichment metadata
    enrichment_timestamp: datetime = Field(default_factory=datetime.utcnow)
    enrichment_agent_version: str = "1.0.0"
    enrichment_confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    reasoning_summary: str = ""
    enrichment_notes: List[str] = Field(default_factory=list)

    model_config = {"use_enum_values": True}
