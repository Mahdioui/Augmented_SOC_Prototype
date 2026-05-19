"""
orchestrator.py
---------------
The Central Orchestrator — the brain of the Agentic SOC prototype.

Responsibilities:
- Accept a raw alert and drive it through the complete processing pipeline
- Coordinate: EnrichmentAgent → TriageAgent → (PhishingAgent) → SummarizationAgent
                → PolicyEngine → AuditLogger
- Enforce governance at every stage (policy checks before any recommendation)
- Return a complete, structured OrchestratorResult

Design principles:
- Semi-autonomous: the orchestrator proposes, humans decide
- All sensitive actions are gated behind the PolicyEngine
- Every step is logged by the AuditLogger
- Graceful error handling: a failure in one stage produces a partial result
  rather than crashing the entire pipeline
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from agents.enrichment_agent import EnrichmentAgent
from agents.false_positive_prediction_agent import FalsePositivePredictionAgent
from agents.next_best_action_agent import NextBestActionAgent
from agents.phishing_agent import PhishingAgent
from agents.summarization_agent import SummarizationAgent
from agents.triage_agent import TriageAgent
from orchestration.audit_logger import AuditLogger
from orchestration.policy_engine import PolicyEngine
from persistence.result_store import ResultStore
from reporting.run_reporter import RunReporter
from schemas.input_schema import AlertType, RawAlert
from schemas.output_schema import OrchestratorResult

logger = logging.getLogger(__name__)


class Orchestrator:
    """
    Central Orchestrator for the Agentic SOC prototype.

    Wires all agents together and enforces the governance pipeline.
    Maintains one AuditLogger instance per orchestrator session.
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        persist_audit: bool = True,
        persist_outputs: bool = True,
        save_case_summary_files: bool = True,
    ):
        """
        Initialize the orchestrator and all sub-agents.

        Args:
            persist_audit: Whether to write the audit trail to disk.
        """
        self.enrichment_agent = EnrichmentAgent()
        self.triage_agent = TriageAgent()
        self.false_positive_agent = FalsePositivePredictionAgent()
        self.next_best_action_agent = NextBestActionAgent()
        self.summarization_agent = SummarizationAgent()
        self.phishing_agent = PhishingAgent()
        self.policy_engine = PolicyEngine()
        self.audit_logger = AuditLogger(persist=persist_audit)
        self.result_store = ResultStore(
            save_summary_txt=save_case_summary_files,
            save_summary_md=save_case_summary_files,
        )
        self.reporter = RunReporter()
        self.architecture_diagram_path = self.reporter.write_architecture_diagram()
        self.persist_outputs = persist_outputs

        logger.info("[Orchestrator] All agents initialized.")

    # ------------------------------------------------------------------
    # Main pipeline
    # ------------------------------------------------------------------

    def process_alert(self, alert: RawAlert) -> OrchestratorResult:
        """
        Run the full SOC processing pipeline for a single raw alert.

        Pipeline stages:
        1. Enrichment      — gather context (user, asset, TI, cases)
        2. Triage          — classify and prioritize the alert
        3. Phishing check  — run specialized analysis if alert type is phishing
        4. Summarization   — generate analyst-ready case summary
        5. Policy check    — validate primary recommended action against governance rules
        6. Audit logging   — record all decisions

        Args:
            alert: A validated RawAlert object.

        Returns:
            A complete OrchestratorResult containing all pipeline outputs.
        """
        start_time = time.perf_counter()
        errors = []

        logger.info(f"\n{'='*60}")
        logger.info(f"[Orchestrator] Processing alert: {alert.alert_id}")
        logger.info(f"{'='*60}")

        # Log pipeline start
        self.audit_logger.log_pipeline_start(alert.alert_id, alert.type)

        result = OrchestratorResult(
            alert_id=alert.alert_id,
            raw_alert=alert,
            pipeline_status="in_progress",
        )

        # ------------------------------------------------------------------
        # Stage 1: Enrichment
        # ------------------------------------------------------------------
        enriched = None
        try:
            logger.info(f"[Orchestrator] Stage 1 — Enrichment")
            enriched = self.enrichment_agent.enrich(alert)
            result.enriched_alert = enriched

            self.audit_logger.log_enrichment(
                alert_id=alert.alert_id,
                confidence=enriched.enrichment_confidence,
                ioc_matched=enriched.ioc_matched,
                ti_count=len(enriched.threat_intel_matches),
                related_cases=len(enriched.related_cases),
            )
        except Exception as exc:
            msg = f"Enrichment failed: {exc}"
            logger.error(f"[Orchestrator] {msg}")
            errors.append(msg)
            # Cannot continue without enrichment
            return self._finalize(result, "failed", errors, start_time)

        # ------------------------------------------------------------------
        # Stage 2: Triage
        # ------------------------------------------------------------------
        triage = None
        try:
            logger.info(f"[Orchestrator] Stage 2 — Triage")
            triage = self.triage_agent.evaluate_alert(enriched)
            result.triage_result = triage

            self.audit_logger.log_triage(
                alert_id=alert.alert_id,
                classification=triage.classification,
                priority=triage.priority,
                confidence=triage.confidence,
                requires_human=triage.requires_human_review,
            )
        except Exception as exc:
            msg = f"Triage failed: {exc}"
            logger.error(f"[Orchestrator] {msg}")
            errors.append(msg)

        # ------------------------------------------------------------------
        # Stage 3 (conditional): Phishing Analysis
        # ------------------------------------------------------------------
        if AlertType(alert.type) == AlertType.PHISHING:
            try:
                logger.info(f"[Orchestrator] Stage 3 — Phishing Analysis (specialized)")
                phishing_result = self.phishing_agent.analyze(enriched)
                result.phishing_result = phishing_result

                self.audit_logger.log_phishing_analysis(
                    alert_id=alert.alert_id,
                    verdict=phishing_result.verdict,
                    phishing_score=phishing_result.phishing_score,
                    confidence=phishing_result.confidence,
                )
            except Exception as exc:
                msg = f"Phishing analysis failed: {exc}"
                logger.error(f"[Orchestrator] {msg}")
                errors.append(msg)

        # ------------------------------------------------------------------
        # Stage 3b: False-positive prediction
        # ------------------------------------------------------------------
        fp_result = None
        if triage:
            try:
                logger.info("[Orchestrator] Stage 3b — False-Positive Prediction")
                fp_result = self.false_positive_agent.predict(enriched, triage)
                result.false_positive_prediction = fp_result
                self.audit_logger.log(
                    alert_id=alert.alert_id,
                    agent_name="FalsePositivePredictionAgent",
                    input_summary=f"FP prediction for {alert.alert_id}",
                    decision=f"fp_probability={fp_result.false_positive_probability:.2f}",
                    confidence=fp_result.prediction_confidence,
                    requires_human_review=fp_result.governance_guardrail_applied,
                )
            except Exception as exc:
                msg = f"False-positive prediction failed: {exc}"
                logger.error(f"[Orchestrator] {msg}")
                errors.append(msg)

        # ------------------------------------------------------------------
        # Stage 4: Next Best Actions
        # ------------------------------------------------------------------
        nba_result = None
        if triage:
            try:
                logger.info("[Orchestrator] Stage 4 — Next Best Action Recommendation")
                nba_result = self.next_best_action_agent.recommend(enriched, triage, fp_result)
                result.next_best_action = nba_result
                self.audit_logger.log(
                    alert_id=alert.alert_id,
                    agent_name="NextBestActionAgent",
                    input_summary=f"Next best action recommendations for {alert.alert_id}",
                    decision=f"recommended_actions={len(nba_result.actions)}",
                    confidence=nba_result.confidence,
                )
            except Exception as exc:
                msg = f"Next-best-action recommendation failed: {exc}"
                logger.error(f"[Orchestrator] {msg}")
                errors.append(msg)

        # ------------------------------------------------------------------
        # Stage 5: Case Summarization
        # ------------------------------------------------------------------
        if triage:
            try:
                logger.info(f"[Orchestrator] Stage 5 — Case Summarization")
                summary = self.summarization_agent.summarize(enriched, triage)
                result.case_summary = summary

                self.audit_logger.log_summarization(
                    alert_id=alert.alert_id,
                    requires_escalation=summary.requires_escalation,
                )
            except Exception as exc:
                msg = f"Summarization failed: {exc}"
                logger.error(f"[Orchestrator] {msg}")
                errors.append(msg)

        # ------------------------------------------------------------------
        # Stage 6: Policy Check on primary recommended action
        # ------------------------------------------------------------------
        if triage and triage.recommended_actions:
            try:
                logger.info(f"[Orchestrator] Stage 6 — Policy Check")
                primary_action = triage.recommended_actions[0]
                policy_result = self.policy_engine.check(
                    enriched=enriched,
                    triage=triage,
                    action_requested=primary_action.description,
                    confidence=triage.confidence,
                    phishing_result=result.phishing_result,
                    false_positive_result=fp_result,
                    next_best_action=nba_result,
                )
                result.policy_check = policy_result

                self.audit_logger.log_policy_check(
                    alert_id=alert.alert_id,
                    action=primary_action.description,
                    decision=policy_result.decision,
                    triggered_rules=policy_result.triggered_rules,
                )
            except Exception as exc:
                msg = f"Policy check failed: {exc}"
                logger.error(f"[Orchestrator] {msg}")
                errors.append(msg)

        # ------------------------------------------------------------------
        # Finalize
        # ------------------------------------------------------------------
        status = "failed" if not triage else ("partial" if errors else "completed")
        return self._finalize(result, status, errors, start_time)

    def print_result(self, result: OrchestratorResult) -> None:
        """Print a formatted, readable pipeline result to stdout."""
        print("\n" + "=" * 70)
        print(f" ORCHESTRATOR RESULT — Alert: {result.alert_id}")
        print("=" * 70)
        print(f" Pipeline status : {result.pipeline_status}")
        print(f" Processing time : {result.total_processing_time_ms:.1f} ms")

        if result.errors:
            print(f"\n ERRORS ({len(result.errors)}):")
            for err in result.errors:
                print(f"   - {err}")

        if result.triage_result:
            t = result.triage_result
            print(f"\n TRIAGE RESULT")
            print(f"   Classification : {t.classification}")
            print(f"   Priority       : {t.priority}")
            print(f"   Suspicion      : {t.suspicion_level}")
            print(f"   Confidence     : {t.confidence:.0%}")
            print(f"   Human review   : {'YES [!]' if t.requires_human_review else 'No'}")
            print(f"\n   Risk factors:")
            for rf in t.risk_factors:
                print(f"     • {rf}")
            print(f"\n   Recommended actions:")
            for act in t.recommended_actions:
                human_flag = " [HUMAN REQUIRED]" if act.requires_human else ""
                print(f"     [{act.urgency.upper()}]{human_flag} {act.description}")

        if result.phishing_result:
            p = result.phishing_result
            print(f"\n PHISHING ANALYSIS")
            print(f"   Verdict        : {p.verdict}")
            print(f"   Phishing score : {p.phishing_score:.0%}")
            print(f"   Credential risk: {'YES [!]' if p.credential_harvesting_risk else 'No'}")
            print(f"   Confidence     : {p.confidence:.0%}")

        if result.false_positive_prediction:
            fp = result.false_positive_prediction
            print("\n FALSE POSITIVE PREDICTION")
            print(f"   Probability    : {fp.false_positive_probability:.0%}")
            print(f"   Confidence     : {fp.prediction_confidence:.0%}")
            print(f"   Handling       : {fp.recommended_handling}")

        if result.next_best_action and result.next_best_action.actions:
            print("\n NEXT BEST ACTIONS")
            for item in result.next_best_action.actions[:5]:
                sensitivity = "SENSITIVE" if item.sensitive else "standard"
                print(f"   - ({item.action_category}/{sensitivity}) {item.action}")

        if result.policy_check:
            pc = result.policy_check
            print(f"\n POLICY CHECK")
            print(f"   Action checked : {pc.action_requested[:60]}...")
            print(f"   Decision       : {pc.decision}")
            print(f"   Triggered rules: {', '.join(pc.triggered_rules) or 'None'}")
            print(f"   Severity       : {pc.decision_severity}")
            if pc.approval_role_required:
                print(f"   Requires       : {pc.approval_role_required} approval")

        if result.case_summary:
            cs = result.case_summary
            print(f"\n CASE SUMMARY")
            print(f"   {cs.summary_title}")
            print(f"\n   Executive summary:")
            print(f"   {cs.executive_summary}")
            print(f"\n   Key findings:")
            for kf in cs.key_findings[:5]:
                print(f"     • {kf}")
            print(f"\n   Risk assessment: {cs.risk_assessment}")
            escalation = "YES [ESCALATE]" if cs.requires_escalation else "No"
            print(f"   Escalation required: {escalation}")

        print("\n" + "=" * 70)
        self.audit_logger.print_summary()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _finalize(
        self,
        result: OrchestratorResult,
        status: str,
        errors: list,
        start_time: float,
    ) -> OrchestratorResult:
        """Finalize the pipeline result with timing and status."""
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        end_entry = self.audit_logger.log_pipeline_end(
            alert_id=result.alert_id,
            status=status,
            duration_ms=elapsed_ms,
        )

        result.pipeline_status = status
        result.errors = errors
        result.total_processing_time_ms = round(elapsed_ms, 2)
        result.audit_entries = self.audit_logger.get_entries_for_alert(result.alert_id)
        result.audit_reference_ids = [entry.log_id for entry in result.audit_entries]
        result.final_consolidated_explanation = self._build_consolidated_explanation(result)

        if self.persist_outputs:
            artifact_paths = self.result_store.save(result)
            summary_path = self.reporter.write_run_summary(
                result=result,
                scenario_name=result.raw_alert.type if result.raw_alert else "unknown",
                artifact_paths=artifact_paths,
            )
            artifact_paths["run_summary_md"] = summary_path
            artifact_paths["architecture_mermaid"] = self.architecture_diagram_path
            result.output_artifacts = artifact_paths

        return result

    def _build_consolidated_explanation(self, result: OrchestratorResult) -> str:
        parts = ["Pipeline consolidated explanation:"]
        if result.enriched_alert:
            parts.append(
                f"- Enrichment confidence={result.enriched_alert.enrichment_confidence:.2f}; "
                f"ioc_matched={result.enriched_alert.ioc_matched}; "
                f"asset_critical={result.enriched_alert.asset_is_critical}; "
                f"user_privileged={result.enriched_alert.user_is_privileged}."
            )
        if result.triage_result:
            parts.append(
                f"- Triage classified alert as {result.triage_result.classification} "
                f"with priority {result.triage_result.priority} "
                f"(confidence={result.triage_result.confidence:.2f})."
            )
        if result.false_positive_prediction:
            fp = result.false_positive_prediction
            parts.append(
                f"- False-positive estimator produced probability={fp.false_positive_probability:.2f} "
                f"(confidence={fp.prediction_confidence:.2f})."
            )
        if result.next_best_action:
            parts.append(
                f"- Next-best-action agent proposed {len(result.next_best_action.actions)} "
                "bounded investigative/recommendation steps."
            )
        if result.policy_check:
            parts.append(
                f"- Policy decision={result.policy_check.decision} "
                f"(severity={result.policy_check.decision_severity}) due to rules: "
                f"{', '.join(result.policy_check.triggered_rules) or 'none'}."
            )
        return "\n".join(parts)
