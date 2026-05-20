"""
run_before_after.py
-------------------
Deterministic thesis-grade simulation with three operating modes:
1) Manual SOC
2) Agent-Assisted SOC
3) Governed Semi-Autonomous SOC
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from reporting.run_reporter import RunReporter
from simulations.scenario_library import SCENARIOS
from visualization.simulation_plots import (
    generate_scenario_level_plots,
    generate_simulation_plots,
)


@dataclass(frozen=True)
class ModeMetrics:
    enrichment_time_min: float
    investigation_time_min: float
    summary_time_min: float
    decision_time_min: float
    case_throughput_per_analyst_day: float
    decision_consistency_pct: float
    false_positive_handling_efficiency_pct: float
    escalation_rate_pct: float
    policy_review_burden_pct: float

    @property
    def total_time_min(self) -> float:
        return (
            self.enrichment_time_min
            + self.investigation_time_min
            + self.summary_time_min
            + self.decision_time_min
        )


@dataclass(frozen=True)
class WorkflowSimulationConfig:
    workflow: str
    manual: ModeMetrics
    assisted: ModeMetrics
    governed: ModeMetrics


WORKFLOWS: List[WorkflowSimulationConfig] = [
    WorkflowSimulationConfig(
        workflow="alert_triage",
        manual=ModeMetrics(15, 14, 8, 5, 15, 72, 48, 22, 0),
        assisted=ModeMetrics(2, 5, 2, 2, 40, 89, 68, 20, 0),
        governed=ModeMetrics(2, 6, 2, 3, 34, 92, 70, 24, 38),
    ),
    WorkflowSimulationConfig(
        workflow="phishing_triage",
        manual=ModeMetrics(20, 16, 10, 7, 8, 68, 56, 30, 0),
        assisted=ModeMetrics(1, 6, 2, 3, 25, 88, 74, 26, 0),
        governed=ModeMetrics(1, 7, 2, 4, 21, 91, 76, 30, 44),
    ),
    WorkflowSimulationConfig(
        workflow="suspicious_signin_investigation",
        manual=ModeMetrics(18, 11, 7, 8, 12, 70, 45, 18, 0),
        assisted=ModeMetrics(1, 4, 1, 2, 44, 90, 63, 16, 0),
        governed=ModeMetrics(1, 5, 1, 3, 37, 93, 66, 21, 35),
    ),
    WorkflowSimulationConfig(
        workflow="malware_investigation",
        manual=ModeMetrics(22, 25, 12, 8, 6, 74, 40, 45, 0),
        assisted=ModeMetrics(2, 10, 3, 4, 16, 88, 58, 40, 0),
        governed=ModeMetrics(2, 12, 3, 5, 13, 91, 60, 44, 52),
    ),
    WorkflowSimulationConfig(
        workflow="iam_anomaly_review",
        manual=ModeMetrics(16, 12, 6, 7, 10, 69, 42, 14, 0),
        assisted=ModeMetrics(1, 4, 1, 2, 36, 87, 62, 12, 0),
        governed=ModeMetrics(1, 5, 1, 3, 30, 90, 65, 16, 34),
    ),
]


def _row(config: WorkflowSimulationConfig) -> Dict[str, float | str]:
    manual_workload = (config.manual.total_time_min / config.manual.case_throughput_per_analyst_day) * 100
    assisted_workload = (config.assisted.total_time_min / config.assisted.case_throughput_per_analyst_day) * 100
    governed_workload = (config.governed.total_time_min / config.governed.case_throughput_per_analyst_day) * 100
    review_shift = config.governed.policy_review_burden_pct - config.assisted.escalation_rate_pct
    return {
        "workflow": config.workflow,
        "manual_total_time_min": round(config.manual.total_time_min, 2),
        "assisted_total_time_min": round(config.assisted.total_time_min, 2),
        "governed_total_time_min": round(config.governed.total_time_min, 2),
        "manual_enrichment_time_min": config.manual.enrichment_time_min,
        "assisted_enrichment_time_min": config.assisted.enrichment_time_min,
        "governed_enrichment_time_min": config.governed.enrichment_time_min,
        "manual_investigation_time_min": config.manual.investigation_time_min,
        "assisted_investigation_time_min": config.assisted.investigation_time_min,
        "governed_investigation_time_min": config.governed.investigation_time_min,
        "manual_summary_time_min": config.manual.summary_time_min,
        "assisted_summary_time_min": config.assisted.summary_time_min,
        "governed_summary_time_min": config.governed.summary_time_min,
        "manual_case_throughput": config.manual.case_throughput_per_analyst_day,
        "assisted_case_throughput": config.assisted.case_throughput_per_analyst_day,
        "governed_case_throughput": config.governed.case_throughput_per_analyst_day,
        "manual_consistency_pct": config.manual.decision_consistency_pct,
        "assisted_consistency_pct": config.assisted.decision_consistency_pct,
        "governed_consistency_pct": config.governed.decision_consistency_pct,
        "manual_fp_handling_efficiency": config.manual.false_positive_handling_efficiency_pct,
        "assisted_fp_handling_efficiency": config.assisted.false_positive_handling_efficiency_pct,
        "governed_fp_handling_efficiency": config.governed.false_positive_handling_efficiency_pct,
        "manual_escalation_rate_pct": config.manual.escalation_rate_pct,
        "assisted_escalation_rate_pct": config.assisted.escalation_rate_pct,
        "governed_escalation_rate_pct": config.governed.escalation_rate_pct,
        "governed_policy_review_burden_pct": config.governed.policy_review_burden_pct,
        "manual_workload_index": round(manual_workload, 2),
        "assisted_workload_index": round(assisted_workload, 2),
        "governed_workload_index": round(governed_workload, 2),
        "review_shift_pct": round(review_shift, 2),
    }


def run_simulation(
    output_root: str | Path = ".",
    total_cases: int = 240,
) -> Dict[str, str]:
    output_root = Path(output_root)
    run_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_dir = output_root / "reports"
    visual_dir = output_root / "visuals" / run_id
    sim_dir = output_root / "outputs" / f"simulation_{run_id}"
    report_dir.mkdir(parents=True, exist_ok=True)
    visual_dir.mkdir(parents=True, exist_ok=True)
    sim_dir.mkdir(parents=True, exist_ok=True)

    rows = [_row(item) for item in WORKFLOWS]

    csv_path = sim_dir / "simulation_summary.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    json_path = sim_dir / "simulation_summary.json"
    json_path.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")

    chart_paths = generate_simulation_plots(rows, visual_dir)
    scenario_chart_paths = generate_scenario_level_plots(
        classification_counts=_classification_counts_from_scenarios(),
        fp_by_scenario=_fp_profile_from_scenarios(),
        action_category_counts=_nba_category_counts_from_scenarios(),
        output_dir=visual_dir,
    )
    chart_paths.update(scenario_chart_paths)

    md_content = _build_markdown_summary(rows, chart_paths, run_id, total_cases=total_cases)
    md_path = sim_dir / "simulation_summary.md"
    md_path.write_text(md_content, encoding="utf-8")

    reporter = RunReporter(report_dir)
    latest_report = reporter.write_simulation_summary(md_content, f"simulation_{run_id}.md")

    _print_console_summary(rows, chart_paths, csv_path, json_path, md_path, total_cases=total_cases)

    return {
        "csv": str(csv_path),
        "json": str(json_path),
        "markdown": str(md_path),
        "latest_report": latest_report,
        **chart_paths,
    }


def _classification_counts_from_scenarios() -> Dict[str, int]:
    counts = {"true_positive": 0, "uncertain": 0, "likely_false_positive": 0}
    for scenario in SCENARIOS.values():
        direction = scenario.metadata.expected_triage_direction
        if "false_positive" in direction:
            counts["likely_false_positive"] += 1
        elif "uncertain" in direction:
            counts["uncertain"] += 1
        else:
            counts["true_positive"] += 1
    return counts


def _fp_profile_from_scenarios() -> Dict[str, float]:
    mapping = {"low_false_positive": 0.2, "medium_false_positive": 0.5, "high_false_positive": 0.8}
    values: Dict[str, float] = {}
    for name, scenario in SCENARIOS.items():
        values[name] = mapping.get(scenario.metadata.expected_false_positive_profile, 0.5)
    return values


def _nba_category_counts_from_scenarios() -> Dict[str, int]:
    counts = {
        "investigative": 0,
        "enrichment": 0,
        "escalation": 0,
        "containment_recommendation": 0,
    }
    for scenario in SCENARIOS.values():
        category = scenario.metadata.scenario_category
        if category in {"malware", "lateral_movement"}:
            counts["containment_recommendation"] += 1
            counts["investigative"] += 2
        elif category in {"phishing", "identity"}:
            counts["investigative"] += 2
            counts["enrichment"] += 1
        else:
            counts["investigative"] += 1
            counts["enrichment"] += 1
        if "escalation" in scenario.metadata.expected_escalation_tendency:
            counts["escalation"] += 1
    return counts


def _build_markdown_summary(
    rows: List[Dict[str, float | str]],
    chart_paths: Dict[str, str],
    run_id: str,
    total_cases: int,
) -> str:
    avg_manual = sum(float(row["manual_total_time_min"]) for row in rows) / len(rows)
    avg_assisted = sum(float(row["assisted_total_time_min"]) for row in rows) / len(rows)
    avg_governed = sum(float(row["governed_total_time_min"]) for row in rows) / len(rows)
    return "\n".join(
        [
            f"# Simulation Summary ({run_id})",
            "",
            "## Disclaimer",
            "All figures are illustrative assumptions for academic demonstration only.",
            "These results are illustrative simulation outputs generated on synthetic/anonymized cases and are not production measurements.",
            "",
            "## Synthetic Case Volume",
            f"- Total generated cases: {total_cases}",
            f"- alert_triage: {total_cases // 3}",
            f"- phishing: {total_cases // 3}",
            f"- suspicious_login: {total_cases - 2 * (total_cases // 3)}",
            "",
            "## Aggregate Averages",
            f"- Manual SOC avg handling time: {avg_manual:.2f} min",
            f"- Agent-Assisted SOC avg handling time: {avg_assisted:.2f} min",
            f"- Governed Semi-Autonomous SOC avg handling time: {avg_governed:.2f} min",
            "",
            "## Visual Artifacts",
            *(f"- {name}: `{path}`" for name, path in chart_paths.items()),
            "",
            "## Interpretation",
            "- Agent assistance improves throughput and consistency.",
            "- Governance controls increase review burden but preserve safety in high-risk contexts.",
            "- The model demonstrates progressive, bounded agentic evolution rather than full autonomy.",
        ]
    )


def _print_console_summary(
    rows: List[Dict[str, float | str]],
    chart_paths: Dict[str, str],
    csv_path: Path,
    json_path: Path,
    md_path: Path,
    total_cases: int,
) -> None:
    print("\n" + "#" * 72)
    print("SOC Simulation (Manual vs Assisted vs Governed)")
    print("#" * 72)
    print("All numbers are illustrative and deterministic assumptions.")
    print(
        f"Synthetic case set: total={total_cases}, "
        f"alert_triage={total_cases // 3}, phishing={total_cases // 3}, "
        f"suspicious_login={total_cases - 2 * (total_cases // 3)}"
    )
    print("")
    for row in rows:
        print(
            f"- {row['workflow']}: "
            f"manual={row['manual_total_time_min']} min, "
            f"assisted={row['assisted_total_time_min']} min, "
            f"governed={row['governed_total_time_min']} min"
        )
    print("")
    print(f"CSV summary: {csv_path}")
    print(f"JSON summary: {json_path}")
    print(f"Markdown summary: {md_path}")
    for name, path in chart_paths.items():
        print(f"{name}: {path}")
    print("#" * 72 + "\n")


if __name__ == "__main__":
    run_simulation()
