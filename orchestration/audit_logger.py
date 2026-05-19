"""
audit_logger.py
---------------
The Audit Logger — immutable, append-only record of every agent decision.

Responsibilities:
- Record every significant event in the SOC pipeline with full context
- Produce structured, queryable AuditLogEntry objects
- Optionally persist to a local JSONL file (one JSON object per line)
- Never modify or delete existing log entries (append-only design)

The audit trail is critical for:
  - Regulatory compliance (DORA, ISO 27001)
  - Incident post-mortems
  - AI accountability and explainability
  - Analyst review of automated decisions
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from schemas.output_schema import AuditLogEntry

logger = logging.getLogger(__name__)

# Default path for the persistent audit log file
DEFAULT_LOG_FILE = os.path.join(
    os.path.dirname(__file__), "..", "audit_trail.jsonl"
)


class AuditLogger:
    """
    Audit Logger — append-only audit trail for the SOC pipeline.

    Every call to log() appends an immutable entry to the in-memory log
    and optionally persists it to a JSONL file.

    Thread safety: for this prototype, single-threaded usage is assumed.
    Production would use a thread-safe queue or a proper log store.
    """

    VERSION = "1.0.0"

    def __init__(self, log_file: Optional[str] = DEFAULT_LOG_FILE, persist: bool = True):
        """
        Initialize the audit logger.

        Args:
            log_file: Path to the JSONL file for persistent logging. Pass None to disable.
            persist:  Whether to write log entries to disk.
        """
        self._entries: List[AuditLogEntry] = []
        self._log_file = log_file
        self._persist = persist

        if persist and log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            logger.info(f"[AuditLogger] Persistent logging enabled → {log_file}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(
        self,
        alert_id: str,
        agent_name: str,
        input_summary: str,
        decision: str,
        confidence: Optional[float] = None,
        action_proposed: Optional[str] = None,
        policy_result: Optional[str] = None,
        requires_human_review: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditLogEntry:
        """
        Record a single audit log entry.

        Args:
            alert_id:             The alert this entry relates to.
            agent_name:           The agent or component producing this entry.
            input_summary:        A short summary of the input processed.
            decision:             The decision or output of the agent.
            confidence:           Confidence score, if applicable (0.0–1.0).
            action_proposed:      The action recommended, if any.
            policy_result:        The policy engine decision, if applicable.
            requires_human_review: Whether human review was flagged.
            metadata:             Additional key-value pairs for context.

        Returns:
            The created AuditLogEntry.
        """
        entry = AuditLogEntry(
            log_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            alert_id=alert_id,
            agent_name=agent_name,
            input_summary=input_summary,
            decision=decision,
            confidence=confidence,
            action_proposed=action_proposed,
            policy_result=policy_result,
            requires_human_review=requires_human_review,
            metadata=metadata or {},
        )

        self._entries.append(entry)

        logger.debug(
            f"[AuditLogger] [{entry.log_id[:8]}] {agent_name} | {alert_id} | "
            f"decision={decision} | confidence={confidence}"
        )

        if self._persist and self._log_file:
            self._write_to_file(entry)

        return entry

    def log_pipeline_start(self, alert_id: str, alert_type: str) -> AuditLogEntry:
        """Log the start of the orchestration pipeline for an alert."""
        return self.log(
            alert_id=alert_id,
            agent_name="Orchestrator",
            input_summary=f"Pipeline started for alert {alert_id} (type: {alert_type})",
            decision="pipeline_started",
            metadata={"alert_type": alert_type, "pipeline_version": "1.0.0"},
        )

    def log_enrichment(
        self, alert_id: str, confidence: float, ioc_matched: bool,
        ti_count: int, related_cases: int
    ) -> AuditLogEntry:
        """Log the output of the enrichment agent."""
        return self.log(
            alert_id=alert_id,
            agent_name="EnrichmentAgent",
            input_summary=f"Enriched alert {alert_id}",
            decision=f"enrichment_complete | confidence={confidence:.2f}",
            confidence=confidence,
            metadata={
                "ioc_matched": ioc_matched,
                "threat_intel_matches": ti_count,
                "related_cases": related_cases,
            },
        )

    def log_triage(
        self,
        alert_id: str,
        classification: str,
        priority: str,
        confidence: float,
        requires_human: bool,
    ) -> AuditLogEntry:
        """Log the output of the triage agent."""
        return self.log(
            alert_id=alert_id,
            agent_name="TriageAgent",
            input_summary=f"Triaged alert {alert_id}",
            decision=f"classification={classification} | priority={priority}",
            confidence=confidence,
            requires_human_review=requires_human,
            metadata={
                "classification": classification,
                "priority": priority,
                "requires_human_review": requires_human,
            },
        )

    def log_phishing_analysis(
        self,
        alert_id: str,
        verdict: str,
        phishing_score: float,
        confidence: float,
    ) -> AuditLogEntry:
        """Log the output of the phishing analysis agent."""
        return self.log(
            alert_id=alert_id,
            agent_name="PhishingAgent",
            input_summary=f"Phishing analysis for alert {alert_id}",
            decision=f"verdict={verdict} | score={phishing_score:.2f}",
            confidence=confidence,
            metadata={"verdict": verdict, "phishing_score": phishing_score},
        )

    def log_summarization(self, alert_id: str, requires_escalation: bool) -> AuditLogEntry:
        """Log the output of the summarization agent."""
        return self.log(
            alert_id=alert_id,
            agent_name="SummarizationAgent",
            input_summary=f"Generated case summary for alert {alert_id}",
            decision="summary_generated",
            metadata={"requires_escalation": requires_escalation},
        )

    def log_policy_check(
        self,
        alert_id: str,
        action: str,
        decision: str,
        triggered_rules: List[str],
    ) -> AuditLogEntry:
        """Log the output of the policy engine."""
        return self.log(
            alert_id=alert_id,
            agent_name="PolicyEngine",
            input_summary=f"Policy check for action: '{action}'",
            decision=decision,
            action_proposed=action,
            policy_result=decision,
            requires_human_review=(decision != "allowed"),
            metadata={"triggered_rules": triggered_rules},
        )

    def log_pipeline_end(
        self, alert_id: str, status: str, duration_ms: float
    ) -> AuditLogEntry:
        """Log the completion of the orchestration pipeline."""
        return self.log(
            alert_id=alert_id,
            agent_name="Orchestrator",
            input_summary=f"Pipeline completed for alert {alert_id}",
            decision=f"pipeline_{status}",
            metadata={"status": status, "duration_ms": duration_ms},
        )

    def get_entries_for_alert(self, alert_id: str) -> List[AuditLogEntry]:
        """Retrieve all audit entries for a specific alert."""
        return [e for e in self._entries if e.alert_id == alert_id]

    def get_all_entries(self) -> List[AuditLogEntry]:
        """Return all audit entries in this session."""
        return list(self._entries)

    def print_summary(self) -> None:
        """Print a human-readable summary of the audit trail to stdout."""
        print("\n" + "=" * 70)
        print(" AUDIT TRAIL SUMMARY")
        print("=" * 70)
        for entry in self._entries:
            human_flag = " [!] HUMAN_REVIEW" if entry.requires_human_review else ""
            conf_str = f" | conf={entry.confidence:.2f}" if entry.confidence is not None else ""
            print(
                f"[{entry.timestamp.strftime('%H:%M:%S')}] "
                f"{entry.agent_name:<22} | {entry.alert_id} | "
                f"{entry.decision}{conf_str}{human_flag}"
            )
        print("=" * 70)
        print(f"Total entries: {len(self._entries)}")
        human_reviews = sum(1 for e in self._entries if e.requires_human_review)
        print(f"Flagged for human review: {human_reviews}")
        print("=" * 70 + "\n")

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _write_to_file(self, entry: AuditLogEntry) -> None:
        """Append a single log entry to the JSONL file."""
        try:
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(
                    json.dumps(
                        entry.model_dump(mode="json"), ensure_ascii=False
                    ) + "\n"
                )
        except OSError as exc:
            logger.error(f"[AuditLogger] Failed to write to {self._log_file}: {exc}")
