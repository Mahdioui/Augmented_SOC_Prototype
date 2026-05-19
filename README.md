# Agentic SOC Prototype (Governed Upgrade)

Thesis-oriented prototype for a banking SOC that demonstrates **AI-assisted, policy-governed, human-supervised** operations.

This system is intentionally **not** fully autonomous.

## Architecture (Upgraded)

`RawAlert -> EnrichmentAgent -> TriageAgent -> (PhishingAgent) -> FalsePositivePredictionAgent -> NextBestActionAgent -> SummarizationAgent -> PolicyEngine -> AuditLogger -> Persistence/Reports`

## What Exists Now

- Central orchestrator with modular bounded agents.
- Specialized phishing analysis (conditional).
- New false-positive prediction support (bounded, explainable).
- New next-best-action recommendation layer (bounded vocabulary, recommendation-only).
- Expanded policy engine with richer, explicit reasoning output.
- Full persistence of orchestrator outputs to `outputs/`.
- Human feedback capture to `feedback/`.
- Expanded scenario library with scenario metadata.
- Deterministic multi-mode simulation (manual vs assisted vs governed).
- Visual artifacts (`matplotlib`) and report exports (`CSV`, `JSON`, `Markdown`).

## Folder Structure

```text
soc-agentic-prototype/
├── agents/
│   ├── enrichment_agent.py
│   ├── triage_agent.py
│   ├── phishing_agent.py
│   ├── false_positive_prediction_agent.py
│   ├── next_best_action_agent.py
│   └── summarization_agent.py
├── orchestration/
│   ├── orchestrator.py
│   ├── policy_engine.py
│   └── audit_logger.py
├── schemas/
│   ├── input_schema.py
│   ├── output_schema.py
│   ├── scenario_schema.py
│   └── feedback_schema.py
├── persistence/
│   └── result_store.py
├── reporting/
│   ├── batch_reporter.py
│   └── run_reporter.py
├── feedback/
│   └── feedback_manager.py
├── visualization/
│   └── simulation_plots.py
├── simulations/
│   ├── scenario_library.py
│   └── run_before_after.py
├── data/
├── prompts/
├── outputs/            # generated
├── reports/            # generated
├── visuals/            # generated
├── app.py
└── requirements.txt
```

## Install

```bash
cd soc-agentic-prototype
python -m venv .venv
.venv\Scripts\activate    # Windows
pip install -r requirements.txt
```

Dependencies:
- `pydantic>=2.5.0`
- `matplotlib>=3.8.0`

## Run Commands

```bash
# list scenarios with expected behavior metadata
python app.py --list

# run one scenario
python app.py --scenario ransomware_critical_asset

# run all scenarios
python app.py --all-scenarios

# run all scenarios + aggregate thesis-ready batch artifacts
python app.py --batch-report

# run simulation suite + charts + csv/json/md exports
python app.py --simulation

# capture human feedback interactively
python app.py --feedback --alert-id ALT-101 --scenario ransomware_critical_asset

# run a scenario without persisting output files
python app.py --scenario ransomware_critical_asset --no-save-output
```

## Output Artifacts

Per scenario run:
- `outputs/<ALERT_ID>_orchestrator_result.json`
- `outputs/<ALERT_ID>_case_summary.txt`
- `outputs/<ALERT_ID>_case_summary.md`
- `reports/<ALERT_ID>_run_summary.md`
- `reports/latest_run_summary.md`
- `reports/architecture_diagram.mmd`

Batch report run:
- `outputs/batch_<run_id>/scenario_comparison_matrix.csv`
- `outputs/batch_<run_id>/scenario_comparison_matrix.json`
- `outputs/batch_<run_id>/scenario_comparison_matrix.md`
- `reports/batch_<run_id>_summary.md`
- `reports/latest_batch_summary.md`
- `visuals/batch_<run_id>/*.png`

Simulation run:
- `outputs/simulation_<run_id>/simulation_summary.csv`
- `outputs/simulation_<run_id>/simulation_summary.json`
- `outputs/simulation_<run_id>/simulation_summary.md`
- `visuals/<run_id>/*.png`
- `reports/simulation_<run_id>.md`
- `reports/latest_simulation_summary.md`

## Policy Output Model (Richer)

The policy engine now returns explicit, thesis-friendly decision structure:
- `policy_id`, `policy_description`
- `decision` (`allowed` / `review_required` / `denied`)
- `decision_severity` (`low` / `medium` / `high` / `critical`)
- `triggered_rules`
- `triggered_conditions`
- `decision_rationale`
- `approval_role_required`
- `review_notes`
- `policy_reasoning_summary`

This makes governance decisions auditable and easy to explain in defense slides and appendices.

Feedback:
- `feedback/<ALERT_ID>_feedback.json`

## Governance Model

- No destructive actions executed.
- No automated containment execution.
- Sensitive actions are recommendation-only and policy-reviewed.
- Critical/privileged/strong-IOC contexts force review-oriented behavior.
- High false-positive estimates **cannot** auto-dismiss high-risk alerts.
- Full audit trail remains append-only.

## Explainability Enhancements

Every major output now includes explanation and reasoning summary fields:
- Triage reasoning.
- Phishing reasoning.
- False-positive reasoning.
- Next-best-action reasoning.
- Policy rationale with triggered rules + conditions.
- Final orchestrator consolidated explanation.

## Human-in-the-Loop Feedback

Feedback capture is intentionally lightweight and structured:
- analyst agreement/disagreement with triage
- agreement with false-positive prediction
- agreement with summary quality
- agreement with next-best-action recommendations
- reviewer role, comments, and final review decision

Saved as structured JSON in `feedback/` for future governance analysis.

## Scenario Library (Expanded)

Includes realistic banking SOC scenarios such as:
- Ransomware on critical asset
- Phishing targeting finance user
- Suspicious sign-in on privileged account
- Noisy malware false-positive pattern on non-critical host
- Benign admin activity misdetected
- Lateral movement precursor
- Insider-driven access anomaly
- Repeated IAM misconfiguration noise

Each scenario carries metadata for thesis analysis:
- expected triage direction
- expected policy behavior
- expected false-positive profile
- expected escalation tendency

## Limitations (Explicit)

- Simulation metrics are illustrative assumptions.
- No external SIEM/EDR/IAM integration (mocked data only).
- No ML training loop, no autonomous remediation.
- Action recommendations remain analyst-supervised.

## Thesis Positioning

This prototype supports the thesis claim that SOC evolution is **progressive and governed**:
- AI assistance can reduce noise and improve prioritization.
- Policy controls and human oversight remain central.
- Agentic capability is staged, bounded, and auditable.
