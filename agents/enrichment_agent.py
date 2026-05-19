"""
enrichment_agent.py
-------------------
The Enrichment Agent is the first stage of the SOC pipeline.

Responsibilities (bounded):
- Load contextual data for a given raw alert (user, asset, threat intel, cases)
- Compute enrichment signals (is IP malicious? is user privileged? etc.)
- Return a fully structured EnrichedAlert object

This agent NEVER takes action. It only gathers and structures context.
All data sources are mocked via local JSON files.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional

from schemas.input_schema import (
    AssetContext,
    AssetCriticality,
    CaseReference,
    EnrichedAlert,
    PrivilegeLevel,
    RawAlert,
    ThreatIntelMatch,
    UserContext,
)

logger = logging.getLogger(__name__)

# Path to simulated data directory (relative to project root)
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")


class EnrichmentAgent:
    """
    Enrichment Agent — Stage 1 of the SOC pipeline.

    Loads context from mock data sources and assembles a rich, structured
    EnrichedAlert object ready for triage.
    """

    VERSION = "1.0.0"

    def __init__(self):
        self._users: Dict = self._load_json("users.json")
        self._assets: Dict = self._load_json("assets.json")
        self._threat_intel: Dict = self._load_json("threat_intel.json")
        self._cases: List[Dict] = self._load_json("cases.json")
        logger.info("[EnrichmentAgent] Initialized — data sources loaded.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich(self, alert: RawAlert) -> EnrichedAlert:
        """
        Main entry point. Takes a raw alert and returns a fully enriched alert.

        Args:
            alert: A validated RawAlert object.

        Returns:
            An EnrichedAlert with all available context populated.
        """
        logger.info(f"[EnrichmentAgent] Starting enrichment for alert {alert.alert_id}")

        user_ctx = self._get_user_context(alert.user_id)
        asset_ctx = self._get_asset_context(alert.asset_id)
        ti_matches = self._match_threat_intel(alert)
        related_cases = self._find_related_cases(alert, user_ctx, asset_ctx)

        # Compute boolean enrichment signals
        source_ip_malicious = self._is_ip_malicious(alert.source_ip)
        ioc_matched = len(ti_matches) > 0
        user_has_incidents = bool(user_ctx and user_ctx.recent_incidents)
        asset_critical = bool(
            asset_ctx and asset_ctx.criticality in (
                AssetCriticality.CRITICAL, AssetCriticality.HIGH
            )
        )
        user_privileged = bool(
            user_ctx and user_ctx.privilege_level in (
                PrivilegeLevel.PRIVILEGED, PrivilegeLevel.ADMIN, PrivilegeLevel.ELEVATED
            )
        )

        enrichment_confidence = self._compute_enrichment_confidence(
            user_ctx, asset_ctx, ti_matches
        )
        enrichment_notes = [
            f"user_context={'found' if user_ctx else 'missing'}",
            f"asset_context={'found' if asset_ctx else 'missing'}",
            f"threat_intel_matches={len(ti_matches)}",
            f"related_cases={len(related_cases)}",
        ]
        reasoning_summary = (
            "Context enrichment completed by correlating user, asset, threat-intelligence, "
            "and historical incident data. Confidence reflects context completeness."
        )

        enriched = EnrichedAlert(
            alert_id=alert.alert_id,
            original_alert=alert,
            user_context=user_ctx,
            asset_context=asset_ctx,
            threat_intel_matches=ti_matches,
            related_cases=related_cases,
            source_ip_is_known_malicious=source_ip_malicious,
            ioc_matched=ioc_matched,
            user_has_recent_incidents=user_has_incidents,
            asset_is_critical=asset_critical,
            user_is_privileged=user_privileged,
            enrichment_timestamp=datetime.utcnow(),
            enrichment_agent_version=self.VERSION,
            enrichment_confidence=enrichment_confidence,
            reasoning_summary=reasoning_summary,
            enrichment_notes=enrichment_notes,
        )

        logger.info(
            f"[EnrichmentAgent] Enrichment complete for {alert.alert_id} "
            f"| confidence={enrichment_confidence:.2f} | IOC_matched={ioc_matched} "
            f"| ip_malicious={source_ip_malicious}"
        )
        return enriched

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_user_context(self, user_id: Optional[str]) -> Optional[UserContext]:
        """Retrieve and validate user context from the mock IAM store."""
        if not user_id or user_id not in self._users:
            logger.warning(f"[EnrichmentAgent] User {user_id} not found in data store.")
            return None
        try:
            return UserContext(**self._users[user_id])
        except Exception as e:
            logger.error(f"[EnrichmentAgent] Failed to parse user {user_id}: {e}")
            return None

    def _get_asset_context(self, asset_id: Optional[str]) -> Optional[AssetContext]:
        """Retrieve and validate asset context from the mock CMDB."""
        if not asset_id or asset_id not in self._assets:
            logger.warning(f"[EnrichmentAgent] Asset {asset_id} not found in data store.")
            return None
        try:
            return AssetContext(**self._assets[asset_id])
        except Exception as e:
            logger.error(f"[EnrichmentAgent] Failed to parse asset {asset_id}: {e}")
            return None

    def _match_threat_intel(self, alert: RawAlert) -> List[ThreatIntelMatch]:
        """Match alert IOCs against the threat intelligence database."""
        matches: List[ThreatIntelMatch] = []

        malicious_ips = {
            entry["ip"]: entry
            for entry in self._threat_intel.get("known_malicious_ips", [])
        }
        malicious_domains = {
            entry["domain"]: entry
            for entry in self._threat_intel.get("known_malicious_domains", [])
        }
        malicious_hashes = {
            entry["hash"]: entry
            for entry in self._threat_intel.get("known_malicious_hashes", [])
        }

        # Check source IP
        if alert.source_ip in malicious_ips:
            entry = malicious_ips[alert.source_ip]
            matches.append(ThreatIntelMatch(
                indicator_type="ip",
                indicator_value=alert.source_ip,
                reputation=entry["reputation"],
                category=entry["category"],
                threat_actor=entry.get("threat_actor"),
                confidence=entry["confidence"],
                source=entry["source"],
            ))

        # Check IOC domains
        for domain in alert.ioc_domains:
            if domain in malicious_domains:
                entry = malicious_domains[domain]
                matches.append(ThreatIntelMatch(
                    indicator_type="domain",
                    indicator_value=domain,
                    reputation="malicious",
                    category=entry["category"],
                    threat_actor=entry.get("threat_actor"),
                    confidence=entry["confidence"],
                    source=entry["source"],
                ))

        # Check IOC hashes
        for file_hash in alert.ioc_hashes:
            if file_hash in malicious_hashes:
                entry = malicious_hashes[file_hash]
                matches.append(ThreatIntelMatch(
                    indicator_type="hash",
                    indicator_value=file_hash,
                    reputation="malicious",
                    category=entry["category"],
                    threat_actor=entry.get("threat_actor"),
                    confidence=entry["confidence"],
                    source=entry["source"],
                ))

        logger.info(
            f"[EnrichmentAgent] TI matching: {len(matches)} indicator(s) matched."
        )
        return matches

    def _find_related_cases(
        self,
        alert: RawAlert,
        user_ctx: Optional[UserContext],
        asset_ctx: Optional[AssetContext],
    ) -> List[CaseReference]:
        """Find historical cases related to this alert by type, user, or asset."""
        related: List[CaseReference] = []

        for case in self._cases:
            is_same_type = case.get("type") == alert.type
            involves_user = user_ctx and user_ctx.user_id in case.get("affected_user_ids", [])
            involves_asset = asset_ctx and asset_ctx.asset_id in case.get("affected_asset_ids", [])

            if is_same_type or involves_user or involves_asset:
                try:
                    related.append(CaseReference(
                        case_id=case["case_id"],
                        title=case["title"],
                        type=case["type"],
                        status=case["status"],
                        severity=case["severity"],
                        false_positive=case["false_positive"],
                        ttr_hours=case["ttr_hours"],
                        resolution=case["resolution"],
                    ))
                except Exception as e:
                    logger.warning(f"[EnrichmentAgent] Could not parse case {case.get('case_id')}: {e}")

        logger.info(
            f"[EnrichmentAgent] Related cases found: {len(related)}"
        )
        return related

    def _is_ip_malicious(self, ip: str) -> bool:
        """Check if the given IP is in the threat intelligence database."""
        known_ips = {
            entry["ip"]
            for entry in self._threat_intel.get("known_malicious_ips", [])
        }
        return ip in known_ips

    def _compute_enrichment_confidence(
        self,
        user_ctx: Optional[UserContext],
        asset_ctx: Optional[AssetContext],
        ti_matches: List[ThreatIntelMatch],
    ) -> float:
        """
        Compute overall enrichment confidence based on data availability.
        Missing context reduces confidence since the triage agent will have less information.
        """
        score = 1.0

        if user_ctx is None:
            score -= 0.2   # Missing user context is significant
        if asset_ctx is None:
            score -= 0.15  # Missing asset context reduces confidence

        # Presence of high-confidence TI matches slightly increases confidence
        if ti_matches:
            avg_ti_conf = sum(m.confidence for m in ti_matches) / len(ti_matches)
            score = min(1.0, score + (avg_ti_conf * 0.1))

        return round(max(0.0, score), 2)

    def _load_json(self, filename: str) -> dict | list:
        """Load a JSON data file from the data directory."""
        path = os.path.join(DATA_DIR, filename)
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
