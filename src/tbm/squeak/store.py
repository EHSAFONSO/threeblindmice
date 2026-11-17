"""Histórico de scans em SQLite: é o que permite responder "o que mudou?"."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from tbm.models import ScanResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id    TEXT PRIMARY KEY,
    label      TEXT NOT NULL,
    started_at TEXT NOT NULL,
    score      INTEGER,
    grade      TEXT,
    hosts      INTEGER,
    findings   INTEGER,
    data       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_label_time ON scans(label, started_at);
"""


def tbm_home() -> Path:
    return Path(os.environ.get("TBM_HOME") or Path.home() / ".threeblindmice")


class HistoryStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or tbm_home() / "history.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def save(self, result: ScanResult) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?,?)",
                (
                    result.scan_id,
                    result.label,
                    result.started_at.isoformat(),
                    result.score,
                    result.grade,
                    len(result.hosts),
                    len(result.findings),
                    result.model_dump_json(),
                ),
            )

    def get(self, scan_id: str) -> ScanResult | None:
        """Aceita prefixo do ID, como o git aceita hash curto."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT data FROM scans WHERE scan_id LIKE ? LIMIT 2", (f"{scan_id}%",)
            ).fetchall()
        if len(rows) > 1:
            raise ValueError(f"prefixo ambíguo: {scan_id}")
        return ScanResult.model_validate_json(rows[0]["data"]) if rows else None

    def latest(self, label: str, *, exclude: str | None = None) -> ScanResult | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT data FROM scans WHERE label = ? AND scan_id != ? "
                "ORDER BY started_at DESC LIMIT 1",
                (label, exclude or ""),
            ).fetchone()
        return ScanResult.model_validate_json(row["data"]) if row else None

    def list(self, label: str | None = None, limit: int = 20) -> list[sqlite3.Row]:
        query = "SELECT scan_id, label, started_at, score, grade, hosts, findings FROM scans"
        params: tuple = ()
        if label:
            query += " WHERE label = ?"
            params = (label,)
        query += " ORDER BY started_at DESC LIMIT ?"
        with self._conn() as conn:
            return conn.execute(query, (*params, limit)).fetchall()
