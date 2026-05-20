"""
cmdb_stub.py
------------
Synthetic CMDB connector stub.
"""

from __future__ import annotations

from typing import Any, Dict

from schemas.input_schema import AssetContext


class CMDBStub:
    def get_asset_context(self, asset: AssetContext | None) -> Dict[str, Any]:
        if not asset:
            return {"asset_found": False}
        return {
            "asset_found": True,
            "asset_id": asset.asset_id,
            "hostname": asset.hostname,
            "criticality": asset.criticality,
            "business_function": asset.business_function,
            "compliance_scope": asset.compliance_scope,
            "open_vulnerabilities": asset.open_vulnerabilities,
        }
