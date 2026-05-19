"""
simulation_plots.py
-------------------
Matplotlib chart generation for simulation artifacts.
"""

from __future__ import annotations

from pathlib import Path
from collections import Counter
from typing import Dict, List

import matplotlib.pyplot as plt


def generate_simulation_plots(
    summary_rows: List[Dict[str, str | float]],
    output_dir: str | Path,
) -> Dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    chart_paths: Dict[str, str] = {}

    workflows = [str(row["workflow"]) for row in summary_rows]
    manual_time = [float(row["manual_total_time_min"]) for row in summary_rows]
    assisted_time = [float(row["assisted_total_time_min"]) for row in summary_rows]
    governed_time = [float(row["governed_total_time_min"]) for row in summary_rows]

    x = range(len(workflows))
    width = 0.25
    plt.figure(figsize=(10, 5))
    plt.bar([i - width for i in x], manual_time, width=width, label="Manual SOC")
    plt.bar(x, assisted_time, width=width, label="Agent-Assisted SOC")
    plt.bar([i + width for i in x], governed_time, width=width, label="Governed Semi-Autonomous SOC")
    plt.xticks(list(x), workflows, rotation=20, ha="right")
    plt.ylabel("Average Handling Time (min)")
    plt.title("Workflow Handling Time Comparison")
    plt.legend()
    plt.tight_layout()
    path = out / "handling_time_comparison.png"
    plt.savefig(path, dpi=140)
    plt.close()
    chart_paths["handling_time_comparison"] = str(path)

    manual_throughput = [float(row["manual_case_throughput"]) for row in summary_rows]
    assisted_throughput = [float(row["assisted_case_throughput"]) for row in summary_rows]
    governed_throughput = [float(row["governed_case_throughput"]) for row in summary_rows]
    plt.figure(figsize=(10, 5))
    plt.bar([i - width for i in x], manual_throughput, width=width, label="Manual SOC")
    plt.bar(x, assisted_throughput, width=width, label="Agent-Assisted SOC")
    plt.bar([i + width for i in x], governed_throughput, width=width, label="Governed Semi-Autonomous SOC")
    plt.xticks(list(x), workflows, rotation=20, ha="right")
    plt.ylabel("Cases per Analyst per Day")
    plt.title("Throughput Comparison")
    plt.legend()
    plt.tight_layout()
    path = out / "throughput_comparison.png"
    plt.savefig(path, dpi=140)
    plt.close()
    chart_paths["throughput_comparison"] = str(path)

    policy_burden = [float(row["governed_policy_review_burden_pct"]) for row in summary_rows]
    plt.figure(figsize=(10, 5))
    plt.bar(workflows, policy_burden)
    plt.xticks(rotation=20, ha="right")
    plt.ylabel("Policy Review Burden (%)")
    plt.title("Governed SOC Review Burden by Workflow")
    plt.tight_layout()
    path = out / "policy_review_burden.png"
    plt.savefig(path, dpi=140)
    plt.close()
    chart_paths["policy_review_burden"] = str(path)

    # Approximate policy decision distribution in governed mode
    review_avg = sum(policy_burden) / len(policy_burden)
    denied_pct = 5.0
    review_pct = max(review_avg, denied_pct)
    allowed_pct = max(0.0, 100.0 - review_pct - denied_pct)
    labels = ["allowed", "review_required", "denied"]
    values = [allowed_pct, review_pct, denied_pct]
    plt.figure(figsize=(7, 4))
    plt.bar(labels, values)
    plt.ylabel("Decision Share (%)")
    plt.title("Policy Decisions Distribution (Governed Mode)")
    plt.tight_layout()
    path = out / "policy_decisions_distribution.png"
    plt.savefig(path, dpi=140)
    plt.close()
    chart_paths["policy_decisions_distribution"] = str(path)

    fp_efficiency = [float(row["governed_fp_handling_efficiency"]) for row in summary_rows]
    plt.figure(figsize=(10, 5))
    plt.bar(workflows, fp_efficiency)
    plt.xticks(rotation=20, ha="right")
    plt.ylabel("False-Positive Handling Efficiency (%)")
    plt.title("False-Positive Handling Efficiency")
    plt.tight_layout()
    path = out / "false_positive_efficiency.png"
    plt.savefig(path, dpi=140)
    plt.close()
    chart_paths["false_positive_efficiency"] = str(path)

    return chart_paths


def generate_scenario_level_plots(
    classification_counts: Dict[str, int],
    fp_by_scenario: Dict[str, float],
    action_category_counts: Dict[str, int],
    output_dir: str | Path,
) -> Dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths: Dict[str, str] = {}

    plt.figure(figsize=(8, 4))
    plt.bar(list(classification_counts.keys()), list(classification_counts.values()))
    plt.ylabel("Scenario Count")
    plt.title("Alert Classification Distribution by Scenario")
    plt.tight_layout()
    path = out / "classification_distribution_by_scenario.png"
    plt.savefig(path, dpi=140)
    plt.close()
    paths["classification_distribution_by_scenario"] = str(path)

    plt.figure(figsize=(10, 4))
    plt.bar(list(fp_by_scenario.keys()), list(fp_by_scenario.values()))
    plt.xticks(rotation=25, ha="right")
    plt.ylabel("Estimated False-Positive Probability")
    plt.title("False-Positive Prediction Profile by Scenario")
    plt.tight_layout()
    path = out / "false_positive_profile_by_scenario.png"
    plt.savefig(path, dpi=140)
    plt.close()
    paths["false_positive_profile_by_scenario"] = str(path)

    plt.figure(figsize=(8, 4))
    plt.bar(list(action_category_counts.keys()), list(action_category_counts.values()))
    plt.ylabel("Count")
    plt.title("Next-Best-Action Category Distribution by Scenario")
    plt.tight_layout()
    path = out / "next_best_action_categories_by_scenario.png"
    plt.savefig(path, dpi=140)
    plt.close()
    paths["next_best_action_categories_by_scenario"] = str(path)

    return paths


def generate_batch_run_plots(
    rows: List[Dict[str, str | float | bool]],
    output_dir: str | Path,
) -> Dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths: Dict[str, str] = {}

    classifications = Counter(str(row["classification"]) for row in rows)
    plt.figure(figsize=(8, 4))
    plt.bar(list(classifications.keys()), list(classifications.values()))
    plt.ylabel("Scenario Count")
    plt.title("Alert Classification Distribution")
    plt.tight_layout()
    path = out / "batch_alert_classification_distribution.png"
    plt.savefig(path, dpi=140)
    plt.close()
    paths["batch_alert_classification_distribution"] = str(path)

    policy_decisions = Counter(str(row["policy_decision"]) for row in rows)
    plt.figure(figsize=(8, 4))
    plt.bar(list(policy_decisions.keys()), list(policy_decisions.values()))
    plt.ylabel("Scenario Count")
    plt.title("Policy Decision Distribution")
    plt.tight_layout()
    path = out / "batch_policy_decision_distribution.png"
    plt.savefig(path, dpi=140)
    plt.close()
    paths["batch_policy_decision_distribution"] = str(path)

    scenario_names = [str(row["scenario_name"]) for row in rows]
    fp_probs = [float(row["false_positive_probability"]) for row in rows]
    plt.figure(figsize=(10, 4))
    plt.bar(scenario_names, fp_probs)
    plt.xticks(rotation=25, ha="right")
    plt.ylabel("False-Positive Probability")
    plt.title("False-Positive Prediction by Scenario")
    plt.tight_layout()
    path = out / "batch_false_positive_probability_by_scenario.png"
    plt.savefig(path, dpi=140)
    plt.close()
    paths["batch_false_positive_probability_by_scenario"] = str(path)

    action_counter: Counter[str] = Counter()
    for row in rows:
        raw = str(row.get("next_action_categories", "")).strip()
        if not raw:
            continue
        for part in raw.split(","):
            segment = part.strip()
            if not segment or ":" not in segment:
                continue
            category, count = segment.split(":", 1)
            try:
                action_counter[category.strip()] += int(count.strip())
            except ValueError:
                continue

    if action_counter:
        plt.figure(figsize=(8, 4))
        plt.bar(list(action_counter.keys()), list(action_counter.values()))
        plt.ylabel("Action Count")
        plt.title("Next-Best-Action Categories by Scenario Batch")
        plt.tight_layout()
        path = out / "batch_next_best_action_categories.png"
        plt.savefig(path, dpi=140)
        plt.close()
        paths["batch_next_best_action_categories"] = str(path)

    processing_times = [float(row["processing_time_ms"]) for row in rows]
    plt.figure(figsize=(10, 4))
    plt.bar(scenario_names, processing_times)
    plt.xticks(rotation=25, ha="right")
    plt.ylabel("Processing Time (ms)")
    plt.title("Pipeline Processing Time by Scenario")
    plt.tight_layout()
    path = out / "batch_processing_time_by_scenario.png"
    plt.savefig(path, dpi=140)
    plt.close()
    paths["batch_processing_time_by_scenario"] = str(path)

    return paths
