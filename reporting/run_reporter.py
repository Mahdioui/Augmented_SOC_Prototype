"""
run_reporter.py
---------------
Markdown report generation for pipeline and simulation runs.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict, List

from schemas.output_schema import OrchestratorResult


class RunReporter:
    def __init__(self, base_dir: str | Path = "reports") -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def write_run_summary(
        self,
        result: OrchestratorResult,
        scenario_name: str,
        artifact_paths: Dict[str, str],
    ) -> str:
        run_file = self.base_dir / f"{result.alert_id}_run_summary.md"
        content = self._build_run_summary(result, scenario_name, artifact_paths)
        run_file.write_text(content, encoding="utf-8")
        latest = self.base_dir / "latest_run_summary.md"
        latest.write_text(content, encoding="utf-8")
        return str(run_file)

    def write_simulation_summary(self, content: str, filename: str) -> str:
        path = self.base_dir / filename
        path.write_text(content, encoding="utf-8")
        latest = self.base_dir / "latest_simulation_summary.md"
        latest.write_text(content, encoding="utf-8")
        return str(path)

    def write_architecture_diagram(self) -> str:
        path = self.base_dir / "architecture_diagram.mmd"
        content = "\n".join(
            [
                "flowchart LR",
                "A[Raw Alert] --> B[EnrichmentAgent]",
                "B --> C[TriageAgent]",
                "C --> D{Phishing?}",
                "D -->|Yes| E[PhishingAgent]",
                "D -->|No| F[FalsePositivePredictionAgent]",
                "E --> F",
                "F --> G[NextBestActionAgent]",
                "G --> H[SummarizationAgent]",
                "H --> I[PolicyEngine]",
                "I --> J[AuditLogger]",
                "J --> K[Persistence + Reports + Feedback]",
            ]
        )
        path.write_text(content, encoding="utf-8")
        return str(path)

    def _build_run_summary(
        self, result: OrchestratorResult, scenario_name: str, artifact_paths: Dict[str, str]
    ) -> str:
        triage = result.triage_result
        fp = result.false_positive_prediction
        nba = result.next_best_action
        policy = result.policy_check
        lines: List[str] = [
            f"# Run Summary - {result.alert_id}",
            "",
            f"- Timestamp: {datetime.utcnow().isoformat()}Z",
            f"- Scenario: {scenario_name}",
            f"- Pipeline status: {result.pipeline_status}",
            f"- Processing time (ms): {result.total_processing_time_ms}",
            "",
            "## Key Outputs",
        ]
        if triage:
            lines.extend(
                [
                    f"- Classification: {triage.classification}",
                    f"- Priority: {triage.priority}",
                    f"- Triage confidence: {triage.confidence:.2f}",
                ]
            )
        if fp:
            lines.extend(
                [
                    f"- False-positive probability: {fp.false_positive_probability:.2f}",
                    f"- FP prediction confidence: {fp.prediction_confidence:.2f}",
                ]
            )
        if nba and nba.actions:
            lines.append("- Next-best-action highlights:")
            lines.extend([f"  - {item.action}" for item in nba.actions[:3]])
        if policy:
            lines.extend(
                [
                    f"- Policy decision: {policy.decision}",
                    f"- Policy severity: {policy.decision_severity}",
                    f"- Approval role: {policy.approval_role_required or 'n/a'}",
                ]
            )
        lines.extend(
            [
                "",
                "## Output Paths",
            ]
        )
        for key, value in artifact_paths.items():
            lines.append(f"- {key}: `{value}`")
        lines.extend(
            [
                "",
                "## Audit References",
                f"- Audit entries: {len(result.audit_entries)}",
                f"- Audit IDs: {', '.join(result.audit_reference_ids[:6]) if result.audit_reference_ids else 'n/a'}",
            ]
        )
        return "\n".join(lines)
