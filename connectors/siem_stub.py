"""
siem_stub.py
------------
Synthetic SIEM connector stub.
"""

from __future__ import annotations

from typing import Dict

from schemas.input_schema import RawAlert


class SIEMStub:
    def ingest_alert(self, alert: RawAlert) -> Dict[str, str]:
        return {
            "source": alert.source,
            "alert_id": alert.alert_id,
            "status": "ingested_synthetic",
        }
