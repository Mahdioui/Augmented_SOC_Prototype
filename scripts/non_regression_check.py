"""
non_regression_check.py
-----------------------
Simple non-regression validation script for chapter-6 alignment.
"""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from api.main import app
from orchestration.runner import run_alert
from simulations.run_before_after import run_simulation
from simulations.scenario_library import get_scenario


def main() -> None:
    audit_path = Path("audit_trail.jsonl")
    before = 0
    if audit_path.exists():
        before = len(audit_path.read_text(encoding="utf-8").splitlines())

    alert = get_scenario("phishing_finance_user")
    result = run_alert(alert=alert, mode="langgraph")
    assert result.alert_id == alert.alert_id
    assert audit_path.exists()
    after = len(audit_path.read_text(encoding="utf-8").splitlines())
    assert after >= before + 1, "Expected at least one new audit JSONL entry per run."

    sim_paths = run_simulation(total_cases=240)
    assert Path(sim_paths["latest_report"]).exists()

    client = TestClient(app)
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json().get("status") == "ok"

    assert Path("data/prototype_state.db").exists()
    if result.output_artifacts.get("orchestrator_json"):
        assert Path(result.output_artifacts["orchestrator_json"]).exists()

    print("Non-regression checks passed.")


if __name__ == "__main__":
    main()
