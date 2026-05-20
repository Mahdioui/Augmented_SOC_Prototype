"""
audit_logger.py
---------------
Governance audit logger writing append-only JSONL records.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import List

from schemas.audit_schema import AuditRecord


class GovernanceAuditLogger:
    def __init__(self, log_path: str | Path = "audit_trail.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.records: List[AuditRecord] = []

    def append(self, record: AuditRecord) -> AuditRecord:
        self.records.append(record)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.model_dump(mode="json"), ensure_ascii=False) + "\n")
        return record

    def log_event(
        self,
        *,
        case_id: str,
        agent: str,
        model_id: str,
        prompt_version: str,
        sources: List[str],
        tools_called: List[str],
        proposed_action: str,
        confidence: float,
        policy_decision: str,
        human_validation: str,
        final_outcome: str,
        request_id: str | None = None,
    ) -> AuditRecord:
        record = AuditRecord(
            request_id=request_id or str(uuid.uuid4()),
            case_id=case_id,
            agent=agent,
            model_id=model_id,
            prompt_version=prompt_version,
            sources=sources,
            tools_called=tools_called,
            proposed_action=proposed_action,
            confidence=confidence,
            policy_decision=policy_decision,
            human_validation=human_validation,
            final_outcome=final_outcome,
        )
        return self.append(record)
