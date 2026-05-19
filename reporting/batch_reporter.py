"""
batch_reporter.py
-----------------
Batch execution and scenario comparison reporting for thesis demos.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from orchestration.orchestrator import Orchestrator
from simulations.scenario_library import SCENARIOS, get_scenario
from visualization.simulation_plots import generate_batch_run_plots


def run_batch_report(
    orchestrator: Orchestrator,
    output_root: str | Path = ".",
) -> Dict[str, str]:
    run_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    root = Path(output_root)
    output_dir = root / "outputs" / f"batch_{run_id}"
    report_dir = root / "reports"
    visual_dir = root / "visuals" / f"batch_{run_id}"
    output_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    visual_dir.mkdir(parents=True, exist_ok=True)

    rows: List[Dict[str, str | float | bool]] = []
    for scenario_name in SCENARIOS.keys():
        alert = get_scenario(scenario_name)
        result = orchestrator.process_alert(alert)

        action_categories = []
        if result.next_best_action:
            action_categories = [item.action_category for item in result.next_best_action.actions]
        action_category_counts = Counter(action_categories)
        action_category_string = ", ".join(
            f"{k}:{v}" for k, v in sorted(action_category_counts.items())
        )

        row: Dict[str, str | float | bool] = {
            "scenario_name": scenario_name,
            "alert_id": result.alert_id,
            "alert_type": alert.type,
            "severity": alert.severity,
            "classification": result.triage_result.classification if result.triage_result else "n/a",
            "priority": result.triage_result.priority if result.triage_result else "n/a",
            "triage_confidence": result.triage_result.confidence if result.triage_result else 0.0,
            "false_positive_probability": (
                result.false_positive_prediction.false_positive_probability
                if result.false_positive_prediction
                else 0.0
            ),
            "fp_prediction_confidence": (
                result.false_positive_prediction.prediction_confidence
                if result.false_positive_prediction
                else 0.0
            ),
            "policy_decision": result.policy_check.decision if result.policy_check else "n/a",
            "policy_decision_severity": (
                result.policy_check.decision_severity if result.policy_check else "n/a"
            ),
            "escalation_required": (
                result.case_summary.requires_escalation if result.case_summary else False
            ),
            "pipeline_status": result.pipeline_status,
            "processing_time_ms": result.total_processing_time_ms,
            "next_action_categories": action_category_string,
        }
        rows.append(row)

    csv_path = output_dir / "scenario_comparison_matrix.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    json_path = output_dir / "scenario_comparison_matrix.json"
    json_path.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")

    matrix_md = _build_matrix_markdown(rows)
    matrix_md_path = output_dir / "scenario_comparison_matrix.md"
    matrix_md_path.write_text(matrix_md, encoding="utf-8")

    chart_paths = generate_batch_run_plots(rows, visual_dir)

    report_content = _build_batch_report(rows, chart_paths, run_id)
    report_path = report_dir / f"batch_{run_id}_summary.md"
    report_path.write_text(report_content, encoding="utf-8")
    latest_path = report_dir / "latest_batch_summary.md"
    latest_path.write_text(report_content, encoding="utf-8")

    print(f"\nBatch report generated for {len(rows)} scenarios.")
    print(f"CSV: {csv_path}")
    print(f"JSON: {json_path}")
    print(f"Matrix MD: {matrix_md_path}")
    print(f"Report: {report_path}")
    for key, value in chart_paths.items():
        print(f"{key}: {value}")

    return {
        "batch_csv": str(csv_path),
        "batch_json": str(json_path),
        "batch_matrix_md": str(matrix_md_path),
        "batch_report_md": str(report_path),
        "latest_batch_report_md": str(latest_path),
        **chart_paths,
    }


def _build_matrix_markdown(rows: List[Dict[str, str | float | bool]]) -> str:
    lines = [
        "# Scenario Comparison Matrix",
        "",
        "| Scenario | Type | Severity | Classification | Priority | FP Prob | Policy | Escalation |",
        "|---|---|---|---|---|---:|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['scenario_name']} | {row['alert_type']} | {row['severity']} | "
            f"{row['classification']} | {row['priority']} | "
            f"{float(row['false_positive_probability']):.2f} | {row['policy_decision']} | "
            f"{row['escalation_required']} |"
        )
    return "\n".join(lines)


def _build_batch_report(
    rows: List[Dict[str, str | float | bool]],
    chart_paths: Dict[str, str],
    run_id: str,
) -> str:
    classifications = Counter(str(row["classification"]) for row in rows)
    policy_decisions = Counter(str(row["policy_decision"]) for row in rows)
    avg_fp = sum(float(row["false_positive_probability"]) for row in rows) / len(rows)
    avg_proc = sum(float(row["processing_time_ms"]) for row in rows) / len(rows)
    escalation_pct = (
        sum(1 for row in rows if bool(row["escalation_required"])) / len(rows)
    ) * 100.0

    lines = [
        f"# Batch Run Summary ({run_id})",
        "",
        "## High-Level Metrics",
        f"- Scenarios executed: {len(rows)}",
        f"- Average processing time: {avg_proc:.2f} ms",
        f"- Average false-positive probability: {avg_fp:.2f}",
        f"- Escalation ratio: {escalation_pct:.1f}%",
        "",
        "## Classification Distribution",
    ]
    lines.extend([f"- {k}: {v}" for k, v in sorted(classifications.items())])
    lines.extend(
        [
            "",
            "## Policy Decision Distribution",
        ]
    )
    lines.extend([f"- {k}: {v}" for k, v in sorted(policy_decisions.items())])
    lines.extend(
        [
            "",
            "## Visual Artifacts",
        ]
    )
    lines.extend([f"- {k}: `{v}`" for k, v in chart_paths.items()])
    lines.extend(
        [
            "",
            "## Governance Note",
            "This batch demonstrates policy-gated, analyst-supervised operation. "
            "Recommendations remain non-destructive and execution-free.",
        ]
    )
    return "\n".join(lines)
