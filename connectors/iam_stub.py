"""
iam_stub.py
-----------
Synthetic IAM connector stub.
"""

from __future__ import annotations

from typing import Any, Dict

from schemas.input_schema import UserContext


class IAMStub:
    def get_user_context(self, user: UserContext | None) -> Dict[str, Any]:
        if not user:
            return {"user_found": False}
        return {
            "user_found": True,
            "user_id": user.user_id,
            "privilege_level": user.privilege_level,
            "mfa_enabled": user.mfa_enabled,
            "department": user.department,
            "risk_score": user.risk_score,
            "location": user.location,
            "recent_incidents": user.recent_incidents,
        }
