# Report Alignment Notes (PFE Chapter 6)

## Ce qui correspond au rapport

- **FastAPI/Uvicorn** expose le prototype via `api/main.py`.
- **LangGraph** matérialise l’orchestration sous forme de graphe d’états (`orchestration/langgraph_graph.py`).
- **Mode fallback Python** conservé pour non-régression (`orchestration/runner.py`).
- **5 agents principaux** alignés au naming du rapport :
  - `EnrichmentAgent`
  - `AlertTriageAgent`
  - `CaseSummaryAgent`
  - `PhishingTriageAgent`
  - `IdentityInvestigationAgent`
- **Policy engine YAML** auditable (`governance/action_registry.yaml` + `governance/policy_engine.py`).
- **Audit JSONL append-only** (`governance/audit_logger.py`).
- **Connecteurs simulés** (SIEM/IAM/CMDB/TI/Ticketing) via `connectors/`.
- **SQLite index léger** (`persistence/sqlite_store.py`).
- **Simulation + reporting + visuals** conservés et enrichis.

## Ce qui reste simplifié (volontairement)

- Aucune intégration bancaire réelle (SIEM/EDR/IAM/CMDB/Ticketing).
- RAG interne implémenté en mode simple keyword retrieval (pas de vector DB).
- Gouvernance orientée prototype (décision/règle) sans exécution d’actions sensibles.
- LLM OpenAI optionnel ; mode mock par défaut pour exécution offline.

## Éléments volontairement mockés

- Données d’alerte/contextes : synthétiques et anonymisées.
- LLM : `MockLLMClient` déterministe par défaut.
- Ticketing : création de draft uniquement, sans envoi externe.

## Justification en soutenance (phrases prêtes)

- **“GPT/OpenAI est optionnel et utilisé uniquement comme accélérateur de prototypage.”**
- **“Le mode mock garantit que le prototype reste exécutable sans données sensibles ni dépendance cloud.”**
- **“LangGraph matérialise explicitement l’orchestration multi-agents décrite dans le rapport.”**
- **“FastAPI expose le prototype comme service testable, sans connexion à des systèmes réels.”**
- **“Le policy engine YAML rend la gouvernance explicable et auditable.”**

## Message clé

Le prototype démontre une trajectoire **AI-assisted et gouvernée**, non une autonomie non contrôlée.
