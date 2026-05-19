"""
result_store.py
---------------
Persistence utilities for orchestrator outputs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from schemas.output_schema import OrchestratorResult


class ResultStore:
    def __init__(
        self,
        base_dir: str | Path = "outputs",
        save_summary_txt: bool = True,
        save_summary_md: bool = True,
    ) -> None:
        self.base_dir = Path(base_dir)
        self.save_summary_txt = save_summary_txt
        self.save_summary_md = save_summary_md
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def save(self, result: OrchestratorResult) -> Dict[str, str]:
        alert_id = self._safe(result.alert_id)
        paths: Dict[str, str] = {}

        json_path = self.base_dir / f"{alert_id}_orchestrator_result.json"
        json_path.write_text(
            json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        paths["orchestrator_json"] = str(json_path)

        if result.case_summary and self.save_summary_txt:
            txt_path = self.base_dir / f"{alert_id}_case_summary.txt"
            txt_path.write_text(self._summary_text(result), encoding="utf-8")
            paths["case_summary_txt"] = str(txt_path)

        if result.case_summary and self.save_summary_md:
            md_path = self.base_dir / f"{alert_id}_case_summary.md"
            md_path.write_text(self._summary_markdown(result), encoding="utf-8")
            paths["case_summary_md"] = str(md_path)

        return paths

    def _summary_text(self, result: OrchestratorResult) -> str:
        summary = result.case_summary
        if not summary:
            return "No case summary generated."
        lines = [
            f"Alert: {result.alert_id}",
            f"Title: {summary.summary_title}",
            "",
            "Executive Summary:",
            summary.executive_summary,
            "",
            "Technical Summary:",
            summary.technical_summary,
            "",
            "Key Findings:",
        ]
        lines.extend([f"- {item}" for item in summary.key_findings])
        return "\n".join(lines)

    def _summary_markdown(self, result: OrchestratorResult) -> str:
        summary = result.case_summary
        if not summary:
            return f"# Alert {result.alert_id}\n\nNo case summary generated."
        lines = [
            f"# Alert {result.alert_id} Case Summary",
            "",
            f"## {summary.summary_title}",
            "",
            "### Executive Summary",
            summary.executive_summary,
            "",
            "### Technical Summary",
            summary.technical_summary,
            "",
            "### Key Findings",
        ]
        lines.extend([f"- {item}" for item in summary.key_findings])
        lines.extend(
            [
                "",
                "### Recommended Next Steps",
            ]
        )
        lines.extend([f"- {item}" for item in summary.recommended_next_steps])
        return "\n".join(lines)

    @staticmethod
    def _safe(value: str) -> str:
        clean = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in value)
        return clean[:80]
