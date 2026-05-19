"""
app.py
------
Main entry point for the Agentic SOC Prototype.

Usage:
    python app.py --list
    python app.py --scenario ransomware_critical_asset
    python app.py --all-scenarios
    python app.py --batch-report
    python app.py --simulation
    python app.py --feedback --alert-id ALT-101 --scenario ransomware_critical_asset
"""

from __future__ import annotations

import argparse
import logging

import sys

# Force UTF-8 output on Windows to handle unicode in print statements
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Configure logging before importing project modules
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.WARNING,   # Set to DEBUG or INFO for verbose pipeline output
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
from orchestration.orchestrator import Orchestrator
from feedback.feedback_manager import FeedbackManager
from reporting.batch_reporter import run_batch_report
from simulations.run_before_after import run_simulation
from simulations.scenario_library import (
    SCENARIOS,
    get_scenario,
)


# ---------------------------------------------------------------------------
# Demo runner
# ---------------------------------------------------------------------------

def run_scenario(scenario_name: str, orchestrator: Orchestrator) -> None:
    """Process a single named scenario through the full pipeline."""
    print(f"\n{'#'*68}")
    print(f"  RUNNING SCENARIO: {scenario_name}")
    print(f"{'#'*68}")

    alert = get_scenario(scenario_name)
    result = orchestrator.process_alert(alert)
    orchestrator.print_result(result)
    if result.output_artifacts:
        print("\n OUTPUT ARTIFACTS")
        for key, value in result.output_artifacts.items():
            print(f"   - {key}: {value}")


def run_all_scenarios() -> None:
    """Run all demo scenarios sequentially."""
    print(f"\n{'#'*68}")
    print("  AGENTIC SOC PROTOTYPE — FULL DEMO")
    print("  Processing all demo scenarios through the pipeline")
    print(f"{'#'*68}")

    orchestrator = Orchestrator(persist_audit=True)

    for name in SCENARIOS.keys():
        run_scenario(name, orchestrator)
        print("\n" + "─" * 68)

    print(f"\n[app.py] All {len(SCENARIOS)} scenarios processed.")
    print("[app.py] Outputs persisted under outputs/ and reports/.")


def run_batch_reporting(no_save_output: bool = False) -> None:
    print(f"\n{'#'*68}")
    print("  AGENTIC SOC PROTOTYPE — BATCH REPORT MODE")
    print("  Running all scenarios and generating thesis artifacts")
    print(f"{'#'*68}")
    orchestrator = Orchestrator(
        persist_audit=True,
        persist_outputs=not no_save_output,
        save_case_summary_files=True,
    )
    paths = run_batch_report(orchestrator=orchestrator)
    print("\n BATCH REPORT ARTIFACTS")
    for key, value in paths.items():
        print(f"   - {key}: {value}")


def run_feedback_capture(alert_id: str, scenario_name: str | None = None) -> None:
    manager = FeedbackManager()
    feedback = manager.capture_cli(alert_id=alert_id, scenario_name=scenario_name)
    path = manager.save_feedback(feedback)
    print(f"\nFeedback saved to: {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Agentic SOC Prototype — AI-Assisted Security Operations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--scenario",
        metavar="NAME",
        help="Run a single named scenario (see --list for available names)",
    )
    group.add_argument(
        "--all-scenarios",
        action="store_true",
        help="Run all scenarios through the orchestrator pipeline",
    )
    group.add_argument(
        "--simulation",
        action="store_true",
        help="Run the before/after KPI simulation only",
    )
    group.add_argument(
        "--batch-report",
        action="store_true",
        help="Run all scenarios and generate aggregate thesis-ready artifacts",
    )
    group.add_argument(
        "--feedback",
        action="store_true",
        help="Capture analyst feedback interactively",
    )
    group.add_argument(
        "--list",
        action="store_true",
        help="List all available scenario names",
    )
    parser.add_argument(
        "--alert-id",
        help="Alert identifier for feedback capture mode",
    )
    parser.add_argument(
        "--no-save-output",
        action="store_true",
        help="Disable persistence to outputs/ for this run",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.list:
        print("\nAvailable scenarios:")
        for name in SCENARIOS.keys():
            scenario = SCENARIOS[name]
            print(
                f"  {name:<42} [{scenario.alert.type}] severity={scenario.alert.severity} "
                f"| expected={scenario.metadata.expected_triage_direction}"
            )
        return

    if args.simulation:
        run_simulation()
        return

    if args.batch_report:
        run_batch_reporting(no_save_output=args.no_save_output)
        return

    if args.feedback:
        if not args.alert_id:
            print("[ERROR] --alert-id is required with --feedback")
            sys.exit(1)
        run_feedback_capture(alert_id=args.alert_id, scenario_name=args.scenario)
        return

    if args.scenario:
        if args.scenario not in SCENARIOS:
            print(f"[ERROR] Unknown scenario: '{args.scenario}'")
            print(f"        Available: {list(SCENARIOS.keys())}")
            sys.exit(1)
        orchestrator = Orchestrator(
            persist_audit=True,
            persist_outputs=not args.no_save_output,
            save_case_summary_files=True,
        )
        run_scenario(args.scenario, orchestrator)
        return

    if args.all_scenarios:
        run_all_scenarios()
        return

    # Default: display help
    parser.print_help()


if __name__ == "__main__":
    main()
