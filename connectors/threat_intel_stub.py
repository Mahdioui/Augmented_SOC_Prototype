"""
threat_intel_stub.py
--------------------
Synthetic Threat Intelligence connector stub.
"""

from __future__ import annotations

from typing import Dict


class ThreatIntelStub:
    def summarize_matches(self, ti_match_count: int, ioc_matched: bool) -> Dict[str, str]:
        return {
            "ti_match_count": str(ti_match_count),
            "ioc_matched": str(ioc_matched),
            "assessment": (
                "strong_signal" if ioc_matched and ti_match_count > 0 else "weak_or_no_signal"
            ),
        }
