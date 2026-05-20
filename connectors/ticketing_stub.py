"""
ticketing_stub.py
-----------------
Synthetic ticketing connector stub (no real ticketing calls).
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List


class TicketingStub:
    def find_similar(self, alert_id: str) -> List[str]:
        return [f"TCK-SYNTH-{alert_id[-3:]}-A", f"TCK-SYNTH-{alert_id[-3:]}-B"]

    def create_draft(self, alert_id: str, summary: str) -> Dict[str, str]:
        return {
            "ticket_draft_id": f"DRAFT-{alert_id}",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "note": "Draft only, no external ticket was created.",
            "summary": summary[:180],
        }
