# Augmented SOC Prototype (PFE Chapter 6 Alignment)

Prototype SOC bancaire **AI-assisted** avec gouvernance explicite, orchestration graphe d’états, validation de schémas, auditabilité et simulation.

> Ce projet est un **prototype académique**, pas un SOC de production.
> Aucune action destructive ou autonome n’est exécutée.

## Positionnement

- Mode principal: **AI-assisted / human-supervised**
- Données: **synthétiques / anonymisées uniquement**
- Objectif: démontrer une architecture crédible de SOC augmenté par l’IA dans un cadre PFE

## Stack technique

- Python 3.11 (cible)
- Pydantic (schémas I/O)
- FastAPI + Uvicorn (exposition API)
- LangGraph (orchestration d’état)
- JSONL (audit trail append-only)
- SQLite (index léger des runs)
- Matplotlib (visualisations)
- LLM configurable:
  - `LLM_PROVIDER=mock` (défaut, déterministe)
  - `LLM_PROVIDER=openai` (optionnel, nécessite `OPENAI_API_KEY`)

## Architecture (réelle)

`ingest_alert -> enrich_alert -> triage_alert -> route_specialized_agent -> (phishing_triage | identity_investigation) -> summarize_case -> policy_check -> human_validation_stub -> audit_and_persist`

### Agents principaux (alignés rapport)
1. `EnrichmentAgent`
2. `AlertTriageAgent`
3. `CaseSummaryAgent`
4. `PhishingTriageAgent`
5. `IdentityInvestigationAgent`

### Composants d’aide optionnels
- `FalsePositivePredictionAgent`
- `NextBestActionAgent`

## Arborescence

```text
soc-agentic-prototype/
├── agents/
│   ├── enrichment_agent.py
│   ├── alert_triage_agent.py
│   ├── case_summary_agent.py
│   ├── phishing_triage_agent.py
│   ├── identity_investigation_agent.py
│   ├── false_positive_prediction_agent.py
│   └── next_best_action_agent.py
├── orchestration/
│   ├── langgraph_graph.py
│   ├── routing.py
│   ├── state.py
│   ├── runner.py
│   └── orchestrator.py
├── governance/
│   ├── policy_engine.py
│   ├── action_registry.yaml
│   └── audit_logger.py
├── connectors/
│   ├── siem_stub.py
│   ├── iam_stub.py
│   ├── cmdb_stub.py
│   ├── threat_intel_stub.py
│   └── ticketing_stub.py
├── schemas/
│   ├── alert_schema.py
│   ├── agent_output_schema.py
│   ├── audit_schema.py
│   ├── workflow_schema.py
│   ├── input_schema.py
│   └── output_schema.py
├── llm/
│   ├── llm_client.py
│   ├── openai_client.py
│   └── mock_llm_client.py
├── rag/
│   ├── knowledge_base.py
│   └── retriever.py
├── api/
│   └── main.py
├── simulations/
│   ├── scenario_library.py
│   └── run_before_after.py
├── persistence/
│   ├── sqlite_store.py
│   └── result_store.py
├── reporting/
│   ├── batch_reporter.py
│   └── run_reporter.py
├── docs/
│   ├── architecture_gap_analysis.md
│   └── report_alignment.md
├── scripts/
│   └── non_regression_check.py
├── outputs/
├── reports/
├── visuals/
├── app.py
├── requirements.txt
└── README.md
```

## Installation

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Exécution CLI

```bash
# lister les scénarios
python app.py --list

# exécuter un scénario (mode auto: langgraph si dispo, sinon python)
python app.py --scenario phishing_finance_user --mode auto

# forcer orchestrateur python
python app.py --scenario phishing_finance_user --mode python

# forcer orchestrateur langgraph
python app.py --scenario phishing_finance_user --mode langgraph

# exécuter tous les scénarios
python app.py --all-scenarios --mode langgraph

# simulation before/after + artefacts
python app.py --simulation

# batch report multi-scénarios
python app.py --batch-report

# capture feedback humain
python app.py --feedback --alert-id ALT-102 --scenario phishing_finance_user
```

## Exposition API

```bash
uvicorn api.main:app --reload
```

Endpoints:
- `GET /health`
- `GET /scenarios`
- `POST /alerts/process`
- `POST /simulation/run`
- `GET /reports/latest`

## Gouvernance (YAML + policy engine)

Le fichier `governance/action_registry.yaml` décrit chaque action:
- `risk_level`
- `allowed_in_prototype`
- `requires_human_approval`
- `required_role`
- `reversible`
- `description`

Décisions possibles:
- `ALLOW`
- `REQUIRE_APPROVAL`
- `BLOCK`
- `ESCALATE`

Les actions sensibles (`block_ip`, `isolate_endpoint`, `disable_user_account`) restent bloquées ou soumises à approbation.

## Audit

Audit JSONL append-only (`audit_trail.jsonl`) avec:
- `request_id`, `case_id`, `timestamp_utc`
- `agent`, `model_id`, `prompt_version`
- `sources`, `tools_called`
- `proposed_action`, `confidence`
- `policy_decision`, `human_validation`, `final_outcome`

## Simulation

Artefacts générés:
- `simulation_summary.csv`
- `simulation_summary.json`
- `simulation_summary.md`
- graphiques PNG

Le mode simulation inclut un paramètre de volume synthétique (par défaut `240` cas: 80/80/80).
Le rapport simulation inclut explicitement:

> “These results are illustrative simulation outputs generated on synthetic/anonymized cases and are not production measurements.”

## Prototype vs Production

### Dans ce prototype
- données synthétiques/anonymisées
- connecteurs stubs
- policy déclarative YAML
- orchestration démonstrative LangGraph
- LLM mock déterministe par défaut

### En production (hors scope PFE)
- connecteurs réels SIEM/IAM/CMDB/Ticketing
- gestion des secrets et IAM durcis
- contrôle d’accès fort et observabilité complète
- gouvernance et approbation intégrées aux workflows d’entreprise

## Limites assumées

- Pas de données bancaires réelles
- Pas de remédiation autonome
- Pas de vector DB (RAG simplifié keyword)
- OpenAI optionnel uniquement pour accélération de prototypage
