# Architecture Gap Analysis (Chapitre 6)

| Élément attendu (rapport) | État actuel du code | Action corrective | Statut |
|---|---|---|---|
| Python 3.11 | Projet Python compatible, environnement local variable | Documenter cible Python 3.11 | partial |
| FastAPI + Uvicorn | Non présent initialement | `api/main.py` ajouté + dépendances | done |
| LangGraph orchestration | Orchestrateur Python séquentiel uniquement | `orchestration/langgraph_graph.py` + `state.py` + `routing.py` | done |
| Fallback orchestrateur Python | Orchestrateur existant présent | `orchestration/runner.py` avec `mode=python|langgraph|auto` | done |
| GPT-4o OpenAI optionnel | Pas de couche LLM modulaire | Package `llm/` avec mock par défaut + OpenAI optionnel | done |
| Pydantic I/O | Déjà en place | Schémas compatibilité chapitre 6 (`alert_schema`, etc.) | done |
| 5 agents principaux alignés | Noms legacy partiellement différents | Wrappers `alert_triage_agent`, `case_summary_agent`, `phishing_triage_agent`, + `identity_investigation_agent` | done |
| Policy Engine YAML déclaratif | Règles codées en dur | `governance/action_registry.yaml` + `governance/policy_engine.py` | done |
| Audit Logger JSONL enrichi | Logger JSONL existant mais champs différents | `governance/audit_logger.py` + `schemas/audit_schema.py` | done |
| Connecteurs simulés SIEM/IAM/CMDB/TI/Ticketing | Accès direct données JSON principalement | Package `connectors/` stubs ajouté | done |
| RAG interne simplifié | Non présent | Package `rag/` (knowledge base + retriever keyword) | done |
| SQLite léger | Non présent initialement | `persistence/sqlite_store.py` + index des runs | done |
| Simulation before/after artefacts complets | Déjà partiellement implémenté | CSV/JSON/MD/PNG conservés + paramètre `total_cases=240` + disclaimer explicite | done |
| API endpoints demandés | Non présents | `/health`, `/scenarios`, `/alerts/process`, `/simulation/run`, `/reports/latest` | done |
| CLI `--mode` | Non présent | Ajout `--mode python|langgraph|auto` | done |
| Documentation d’alignement soutenance | Partielle | `docs/report_alignment.md` à jour + README refactorisé | done |

## Notes d’audit

- Le prototype reste **non destructif** : aucune action sensible n’est exécutée automatiquement.
- Les modes mock permettent une exécution **sans dépendance OpenAI**.
- Les données restent synthétiques/anonymisées (stubs + corpus interne mock).
