"""
api/main.py
-----------
FastAPI exposure layer for the AI-assisted SOC prototype.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from fastapi import FastAPI

from orchestration.runner import run_alert
from schemas.input_schema import RawAlert
from simulations.run_before_after import run_simulation
from simulations.scenario_library import SCENARIOS

app = FastAPI(title="Augmented SOC Prototype API", version="1.0.0")


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "mode": "prototype", "data_policy": "synthetic_only"}


@app.get("/scenarios")
def scenarios() -> List[Dict[str, str]]:
    out = []
    for name, definition in SCENARIOS.items():
        out.append(
            {
                "name": name,
                "category": definition.metadata.scenario_category,
                "expected_triage_direction": definition.metadata.expected_triage_direction,
                "severity": definition.alert.severity,
                "alert_type": definition.alert.type,
            }
        )
    return out


@app.post("/alerts/process")
def process_alert(alert: RawAlert, mode: str = "auto") -> Dict:
    result = run_alert(alert=alert, mode=mode)
    return result.model_dump(mode="json")


@app.post("/simulation/run")
def simulation_run() -> Dict[str, str]:
    return run_simulation()


@app.get("/reports/latest")
def latest_report() -> Dict[str, str]:
    candidates = [
        Path("reports/latest_run_summary.md"),
        Path("reports/latest_simulation_summary.md"),
        Path("reports/latest_batch_summary.md"),
    ]
    latest = [str(path) for path in candidates if path.exists()]
    return {
        "latest_reports": latest,
        "note": "Paths are local filesystem paths in prototype mode.",
    }
