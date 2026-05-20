"""
sqlite_store.py
---------------
Lightweight SQLite index of prototype runs.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path


class SQLiteStore:
    def __init__(self, db_path: str | Path = "data/prototype_state.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS run_index (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    workflow TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    final_decision TEXT,
                    policy_decision TEXT,
                    output_path TEXT
                )
                """
            )

    def insert_run(
        self,
        *,
        alert_id: str,
        workflow: str,
        status: str,
        final_decision: str | None,
        policy_decision: str | None,
        output_path: str | None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO run_index
                (alert_id, workflow, status, created_at, final_decision, policy_decision, output_path)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    workflow,
                    status,
                    datetime.utcnow().isoformat() + "Z",
                    final_decision,
                    policy_decision,
                    output_path,
                ),
            )
