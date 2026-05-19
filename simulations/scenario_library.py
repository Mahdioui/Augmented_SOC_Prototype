"""
scenario_library.py
-------------------
Scenario library with metadata for thesis-grade demonstrations.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List

from schemas.input_schema import AlertSeverity, AlertType, RawAlert
from schemas.scenario_schema import ScenarioDefinition, ScenarioMetadata


def _meta(
    category: str,
    difficulty: str,
    triage: str,
    policy: str,
    fp_profile: str,
    escalation: str,
    notes: str = "",
) -> ScenarioMetadata:
    return ScenarioMetadata(
        scenario_category=category,
        expected_difficulty=difficulty,
        expected_triage_direction=triage,
        expected_policy_behavior=policy,
        expected_false_positive_profile=fp_profile,
        expected_escalation_tendency=escalation,
        notes=notes,
    )


SCENARIOS: Dict[str, ScenarioDefinition] = {
    "ransomware_critical_asset": ScenarioDefinition(
        name="ransomware_critical_asset",
        alert=RawAlert(
            alert_id="ALT-101",
            timestamp=datetime(2024, 2, 10, 9, 12, 0),
            source="EDR_MOCK",
            type=AlertType.MALWARE,
            severity=AlertSeverity.CRITICAL,
            source_ip="10.0.3.22",
            destination_ip="203.0.113.55",
            user_id="USR-012",
            asset_id="AST-001",
            description="Ransomware-like encryption behavior on core banking host.",
            raw_log="EDR_ALERT: suspicious encryption and shadow copy deletion.",
            ioc_hashes=["5d41402abc4b2a76b9719d911017c592"],
            ioc_domains=["c2-server-malicious.net"],
        ),
        metadata=_meta(
            "malware",
            "high",
            "true_positive_high_priority",
            "review_required",
            "low_false_positive",
            "strong_escalation",
        ),
    ),
    "phishing_finance_user": ScenarioDefinition(
        name="phishing_finance_user",
        alert=RawAlert(
            alert_id="ALT-102",
            timestamp=datetime(2024, 2, 10, 10, 1, 0),
            source="EMAIL_GATEWAY_MOCK",
            type=AlertType.PHISHING,
            severity=AlertSeverity.MEDIUM,
            source_ip="91.108.4.180",
            destination_ip="10.0.2.15",
            user_id="USR-005",
            asset_id="AST-003",
            description="Finance user received urgent password-reset phishing message.",
            raw_log="From: it-support@bank-secure.xyz Subject: Urgent Password Reset",
            ioc_hashes=[],
            ioc_domains=["bank-secure.xyz", "it-helpdesk-portal.ru"],
        ),
        metadata=_meta(
            "phishing",
            "medium",
            "likely_true_positive",
            "review_required",
            "medium_false_positive",
            "moderate_escalation",
        ),
    ),
    "suspicious_signin_privileged": ScenarioDefinition(
        name="suspicious_signin_privileged",
        alert=RawAlert(
            alert_id="ALT-103",
            timestamp=datetime(2024, 2, 10, 10, 35, 0),
            source="IAM_MOCK",
            type=AlertType.SUSPICIOUS_LOGIN,
            severity=AlertSeverity.HIGH,
            source_ip="185.220.101.42",
            destination_ip="10.0.1.50",
            user_id="USR-003",
            asset_id="AST-002",
            description="Privileged account suspicious sign-in with impossible travel context.",
            raw_log="IAM alert for privileged LDAP admin with geolocation anomaly.",
            ioc_hashes=[],
            ioc_domains=[],
        ),
        metadata=_meta(
            "identity",
            "high",
            "true_or_likely_true_positive",
            "review_required",
            "low_false_positive",
            "strong_escalation",
        ),
    ),
    "noisy_malware_noncritical_workstation": ScenarioDefinition(
        name="noisy_malware_noncritical_workstation",
        alert=RawAlert(
            alert_id="ALT-104",
            timestamp=datetime(2024, 2, 10, 11, 0, 0),
            source="EDR_MOCK",
            type=AlertType.MALWARE,
            severity=AlertSeverity.MEDIUM,
            source_ip="10.0.2.15",
            destination_ip="198.51.100.20",
            user_id="USR-007",
            asset_id="AST-005",
            description="Generic malware heuristic triggered by unsigned script on workstation.",
            raw_log="EDR heuristic: suspicious script behavior, confidence low.",
            ioc_hashes=[],
            ioc_domains=[],
        ),
        metadata=_meta(
            "endpoint_noise",
            "low",
            "likely_false_positive",
            "allowed_or_review",
            "high_false_positive",
            "low_escalation",
        ),
    ),
    "benign_admin_activity_misdetected": ScenarioDefinition(
        name="benign_admin_activity_misdetected",
        alert=RawAlert(
            alert_id="ALT-105",
            timestamp=datetime(2024, 2, 10, 11, 30, 0),
            source="SIEM_MOCK",
            type=AlertType.BRUTE_FORCE,
            severity=AlertSeverity.MEDIUM,
            source_ip="10.0.1.50",
            destination_ip="10.0.1.50",
            user_id="USR-003",
            asset_id="AST-002",
            description="Bulk admin account testing during planned maintenance flagged as brute-force.",
            raw_log="Multiple admin auth attempts from trusted internal maintenance host.",
            ioc_hashes=[],
            ioc_domains=[],
        ),
        metadata=_meta(
            "admin_operations_noise",
            "medium",
            "uncertain_or_likely_false_positive",
            "review_required",
            "high_false_positive",
            "low_escalation",
        ),
    ),
    "lateral_movement_precursor": ScenarioDefinition(
        name="lateral_movement_precursor",
        alert=RawAlert(
            alert_id="ALT-106",
            timestamp=datetime(2024, 2, 10, 12, 15, 0),
            source="NDR_MOCK",
            type=AlertType.INSIDER_THREAT,
            severity=AlertSeverity.HIGH,
            source_ip="10.0.1.88",
            destination_ip="10.0.3.22",
            user_id="USR-005",
            asset_id="AST-001",
            description="Unusual east-west authentication attempts to core banking segment.",
            raw_log="Lateral movement precursor indicators observed across VLAN boundaries.",
            ioc_hashes=[],
            ioc_domains=[],
        ),
        metadata=_meta(
            "lateral_movement",
            "high",
            "likely_true_positive",
            "review_required",
            "low_false_positive",
            "strong_escalation",
        ),
    ),
    "insider_data_access_anomaly": ScenarioDefinition(
        name="insider_data_access_anomaly",
        alert=RawAlert(
            alert_id="ALT-107",
            timestamp=datetime(2024, 2, 10, 13, 10, 0),
            source="UEBA_MOCK",
            type=AlertType.INSIDER_THREAT,
            severity=AlertSeverity.HIGH,
            source_ip="10.0.1.88",
            destination_ip="10.0.1.88",
            user_id="USR-005",
            asset_id="AST-003",
            description="After-hours anomalous access to sensitive finance datasets.",
            raw_log="UEBA deviation score exceeded baseline for sensitive data access.",
            ioc_hashes=[],
            ioc_domains=[],
        ),
        metadata=_meta(
            "insider_risk",
            "high",
            "uncertain_or_likely_true_positive",
            "review_required",
            "medium_false_positive",
            "moderate_escalation",
        ),
    ),
    "repeated_iam_misconfiguration_alert": ScenarioDefinition(
        name="repeated_iam_misconfiguration_alert",
        alert=RawAlert(
            alert_id="ALT-108",
            timestamp=datetime(2024, 2, 10, 14, 0, 0),
            source="IAM_MOCK",
            type=AlertType.SUSPICIOUS_LOGIN,
            severity=AlertSeverity.LOW,
            source_ip="10.0.0.1",
            destination_ip="10.0.0.1",
            user_id="USR-009",
            asset_id="AST-006",
            description="Repeated IAM policy mismatch alerts from recently changed SSO rule.",
            raw_log="IAM policy engine mismatch on token settings after config update.",
            ioc_hashes=[],
            ioc_domains=[],
        ),
        metadata=_meta(
            "iam_misconfiguration",
            "medium",
            "likely_false_positive",
            "allowed_or_review",
            "high_false_positive",
            "low_escalation",
            notes="Useful for FP prediction and rule-noise demonstration.",
        ),
    ),
}


def get_scenario(name: str) -> RawAlert:
    if name not in SCENARIOS:
        raise KeyError(f"Scenario '{name}' not found. Available: {list(SCENARIOS.keys())}")
    return SCENARIOS[name].alert


def get_scenario_definition(name: str) -> ScenarioDefinition:
    if name not in SCENARIOS:
        raise KeyError(f"Scenario '{name}' not found. Available: {list(SCENARIOS.keys())}")
    return SCENARIOS[name]


def get_all_scenarios() -> List[RawAlert]:
    return [scenario.alert for scenario in SCENARIOS.values()]


def list_scenarios() -> List[str]:
    return list(SCENARIOS.keys())
