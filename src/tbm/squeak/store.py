"""Histórico de scans em SQLite: é o que permite responder "o que mudou?".

O banco tem o inventário da sua rede, então ele e a pasta ficam restritos ao
dono (chmod 600/700 no POSIX; no Windows o perfil do usuário já é restrito).
"""

from __future__ import annotations

import builtins
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from tbm.models import ScanResult
from tbm.paths import private_dir, private_file, tbm_home

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
CREATE TABLE IF NOT EXISTS devices (
    identity   TEXT PRIMARY KEY,   -- Host.identity (mac:…, name:… ou ip:…)
    alias      TEXT,
    trusted    INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS accepted (
    fingerprint TEXT PRIMARY KEY,
    label       TEXT,
    reason      TEXT NOT NULL,
    until       TEXT,              -- AAAA-MM-DD; NULL = sem prazo
    created_at  TEXT NOT NULL,
    title       TEXT,
    location    TEXT
);
"""

# Migrações aditivas: colunas novas entram com ALTER TABLE em bancos antigos.
COLUMNS = {"critical": "INTEGER", "high": "INTEGER", "medium": "INTEGER", "low": "INTEGER"}


class HistoryStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or private_dir(tbm_home()) / "history.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(SCHEMA)
            existing = {row["name"] for row in conn.execute("PRAGMA table_info(scans)")}
            for col, kind in COLUMNS.items():
                if col not in existing:
                    conn.execute(f"ALTER TABLE scans ADD COLUMN {col} {kind}")
        private_file(self.path)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def save(self, result: ScanResult) -> None:
        counts = {sev.value: n for sev, n in result.severity_counts().items()}
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans (scan_id, label, started_at, score, grade, hosts, "
                "findings, data, critical, high, medium, low) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    result.scan_id,
                    result.label,
                    result.started_at.isoformat(),
                    result.score,
                    result.grade,
                    len(result.hosts),
                    len(result.findings),
                    result.model_dump_json(),
                    counts["critical"],
                    counts["high"],
                    counts["medium"],
                    counts["low"],
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
        return self._hydrate(ScanResult.model_validate_json(rows[0]["data"])) if rows else None

    def latest(self, label: str, *, exclude: str | None = None, before: str | None = None) -> ScanResult | None:
        query = "SELECT data FROM scans WHERE label = ? AND scan_id != ?"
        params: list = [label, exclude or ""]
        if before:
            query += " AND started_at < ?"
            params.append(before)
        with self._conn() as conn:
            row = conn.execute(query + " ORDER BY started_at DESC LIMIT 1", params).fetchone()
        return self._hydrate(ScanResult.model_validate_json(row["data"])) if row else None

    def list(self, label: str | None = None, limit: int = 20) -> list[sqlite3.Row]:
        query = ("SELECT scan_id, label, started_at, score, grade, hosts, findings, "
                 "critical, high, medium, low FROM scans")
        params: tuple = ()
        if label:
            query += " WHERE label = ?"
            params = (label,)
        query += " ORDER BY started_at DESC LIMIT ?"
        with self._conn() as conn:
            return conn.execute(query, (*params, limit)).fetchall()

    # ───────────────────────── aparelhos conhecidos ─────────────────────────

    def devices(self) -> dict[str, sqlite3.Row]:
        with self._conn() as conn:
            return {r["identity"]: r for r in conn.execute("SELECT * FROM devices")}

    def set_device(self, identity: str, *, alias: str | None = None, trusted: bool | None = None) -> None:
        """Atualiza só o que foi passado (alias "" apaga o nome)."""
        current = self.devices().get(identity)
        new_alias = (alias.strip() or None) if alias is not None else (current["alias"] if current else None)
        new_trusted = int(trusted) if trusted is not None else (current["trusted"] if current else 0)
        with self._conn() as conn:
            conn.execute("INSERT OR REPLACE INTO devices VALUES (?,?,?,?)",
                         (identity, new_alias, new_trusted, datetime.now(UTC).isoformat()))

    def _hydrate(self, result: ScanResult) -> ScanResult:
        """Aplica nomes e aprovações atuais, inclusive em scans antigos."""
        known = self.devices()
        for h in result.hosts:
            if row := known.get(h.identity):
                h.alias, h.trusted = row["alias"], bool(row["trusted"])
        return result

    def meta(self, key: str) -> str | None:
        with self._conn() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._conn() as conn:
            conn.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, value))

    # ───────────────────────── riscos aceitos ─────────────────────────

    def accept(self, fingerprint: str, reason: str, *, until: str | None = None, label: str | None = None,
               title: str | None = None, location: str | None = None) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO accepted VALUES (?,?,?,?,?,?,?)",
                (fingerprint, label, reason, until, datetime.now(UTC).isoformat(), title, location),
            )

    def unaccept(self, fingerprint: str) -> int:
        with self._conn() as conn:
            return conn.execute(
                "DELETE FROM accepted WHERE fingerprint LIKE ?", (f"{fingerprint}%",)
            ).rowcount

    def acceptances(self) -> dict[str, sqlite3.Row]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM accepted ORDER BY created_at").fetchall()
        return {r["fingerprint"]: r for r in rows}

    # `builtins.list`: dentro da classe, "list" já é o método acima, e a anotação
    # `-> list[...]` apontaria para ele (o mypy acusou).
    def labels(self) -> builtins.list[sqlite3.Row]:
        """Último scan de cada rótulo (para a página inicial do dashboard)."""
        with self._conn() as conn:
            return conn.execute(
                "SELECT s.label, s.scan_id, s.started_at, s.score, s.grade, s.hosts, s.findings, "
                "s.critical, s.high, s.medium, s.low, c.n AS total "
                "FROM scans s JOIN (SELECT label, MAX(started_at) AS m, COUNT(*) AS n FROM scans "
                "GROUP BY label) c ON s.label = c.label AND s.started_at = c.m ORDER BY s.label"
            ).fetchall()
