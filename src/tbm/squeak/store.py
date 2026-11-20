"""Histórico de scans em SQLite: é o que permite responder "o que mudou?".

O banco tem o inventário da sua rede, então ele e a pasta ficam restritos ao
dono (chmod 600/700 no POSIX; no Windows o perfil do usuário já é restrito).
"""

from __future__ import annotations

import builtins
import sqlite3
import sys
import threading
import zlib
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path

from tbm.models import Finding, Host, ScanResult, Service, Severity
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
CREATE TABLE IF NOT EXISTS events (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    at    TEXT NOT NULL,
    kind  TEXT NOT NULL,           -- scan_done, unknown_device, resolved, alert_sent, verify
    label TEXT,
    data  TEXT NOT NULL,           -- JSON com os valores do texto (traduzido na hora de mostrar)
    link  TEXT,
    read  INTEGER NOT NULL DEFAULT 0
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

INDEX_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_hosts (
    scan_id     TEXT NOT NULL,
    identity    TEXT NOT NULL,
    address     TEXT NOT NULL,
    mac         TEXT,
    hostname    TEXT,
    device_name TEXT,
    device_type TEXT,
    vendor      TEXT,
    ports       TEXT NOT NULL DEFAULT ''   -- "80/tcp,53/udp"
);
CREATE INDEX IF NOT EXISTS idx_scan_hosts_scan ON scan_hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_hosts_identity ON scan_hosts(identity);
CREATE TABLE IF NOT EXISTS scan_findings (
    scan_id     TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    check_id    TEXT NOT NULL,
    host        TEXT NOT NULL,
    device      TEXT,
    port        INTEGER,
    key         TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL,
    accepted    INTEGER NOT NULL DEFAULT 0,
    title       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_findings_scan ON scan_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_findings_fp ON scan_findings(fingerprint);
"""

# Blob comprimido: prefixo de versão + zlib. Blobs antigos (texto JSON puro) continuam legíveis.
ZPREFIX = b"z1:"


def encode_blob(result: ScanResult) -> bytes:
    return ZPREFIX + zlib.compress(result.model_dump_json().encode("utf-8"), 6)


def decode_blob(data: str | bytes) -> ScanResult:
    if isinstance(data, bytes):
        raw = zlib.decompress(data[len(ZPREFIX):]) if data.startswith(ZPREFIX) else data
        return ScanResult.model_validate_json(raw)
    return ScanResult.model_validate_json(data)


def _ports_text(host: Host) -> str:
    return ",".join(f"{s.port}/{s.transport}" for s in host.services)


def _index_rows(conn: sqlite3.Connection, result: ScanResult) -> None:
    conn.execute("DELETE FROM scan_hosts WHERE scan_id = ?", (result.scan_id,))
    conn.execute("DELETE FROM scan_findings WHERE scan_id = ?", (result.scan_id,))
    conn.executemany(
        "INSERT INTO scan_hosts VALUES (?,?,?,?,?,?,?,?,?)",
        [(result.scan_id, h.identity, h.address, h.mac, h.hostname, h.device_name, h.device_type, h.vendor,
          _ports_text(h)) for h in result.hosts])
    conn.executemany(
        "INSERT INTO scan_findings VALUES (?,?,?,?,?,?,?,?,?,?)",
        [(result.scan_id, f.fingerprint, f.check_id, f.host, f.device, f.port, f.key, f.severity.value,
          int(f.accepted), f.title) for f in result.findings])


def _m1_columns(conn: sqlite3.Connection) -> None:
    """Colunas que as versões até a 0.9 acrescentavam com ALTER solto."""
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(scans)")}
    for col in ("critical", "high", "medium", "low"):
        if col not in existing:
            conn.execute(f"ALTER TABLE scans ADD COLUMN {col} INTEGER")
    dev_cols = {row["name"] for row in conn.execute("PRAGMA table_info(devices)")}
    for col in ("category", "note"):
        if col not in dev_cols:
            conn.execute(f"ALTER TABLE devices ADD COLUMN {col} TEXT")


def _m2_index_tables(conn: sqlite3.Connection) -> None:
    for stmt in INDEX_SCHEMA.split(";"):
        if stmt.strip():
            conn.execute(stmt)


def _m3_backfill(conn: sqlite3.Connection) -> None:
    """Preenche as tabelas de índice a partir dos scans já salvos e comprime os blobs (uma vez só)."""
    total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    loud = total >= 200
    for i, row in enumerate(conn.execute("SELECT scan_id, data FROM scans").fetchall(), 1):
        try:
            result = decode_blob(row["data"])
        except ValueError:  # blob corrompido: o scan continua listado, só fica fora dos índices
            continue
        _index_rows(conn, result)
        if not isinstance(row["data"], bytes):
            conn.execute("UPDATE scans SET data = ? WHERE scan_id = ?", (encode_blob(result), row["scan_id"]))
        if loud and i % 100 == 0:
            print(f"tbm: indexando o histórico… {i}/{total}", file=sys.stderr)  # noqa: T201 (progresso na tela)


# Migrações numeradas: a posição na lista é a versão (PRAGMA user_version).
# Cada uma roda numa transação; nunca altere uma que já saiu, só acrescente.
MIGRATIONS: list[Callable[[sqlite3.Connection], None]] = [_m1_columns, _m2_index_tables, _m3_backfill]
SCHEMA_VERSION = len(MIGRATIONS)


def light_scan(row: sqlite3.Row, hosts: Iterable[sqlite3.Row], findings: Iterable[sqlite3.Row]) -> ScanResult:
    """ScanResult só com o que está nos índices: aparelhos, portas e achados (sem evidências).

    Os `Service` (só porta e transporte) se repetem muito entre aparelhos e scans: são montados uma
    vez por combinação e compartilhados. Quem usa um scan leve só lê, nunca altera.
    """
    return ScanResult(
        scan_id=row["scan_id"], label=row["label"], started_at=datetime.fromisoformat(row["started_at"]),
        score=row["score"], grade=row["grade"],
        hosts=[Host(address=h["address"], mac=h["mac"], hostname=h["hostname"], device_name=h["device_name"],
                    device_type=h["device_type"], vendor=h["vendor"]) for h in hosts],
        findings=[Finding(check_id=f["check_id"], title=f["title"], severity=Severity(f["severity"]), host=f["host"],
                          device=f["device"], port=f["port"], key=f["key"], accepted=bool(f["accepted"]))
                  for f in findings],
    )


def _attach_services(scan: ScanResult, hosts: Iterable[sqlite3.Row], cache: dict[str, list[Service]]) -> None:
    for host, row in zip(scan.hosts, hosts, strict=True):
        text = row["ports"]
        if text not in cache:
            items = [item.partition("/") for item in text.split(",") if item]
            cache[text] = [Service(port=int(p), transport=t or "tcp") for p, _, t in items]
        host.services = list(cache[text])


class HistoryStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or private_dir(tbm_home()) / "history.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        conn = self._conn()
        conn.executescript(SCHEMA)
        self._migrate(conn)
        private_file(self.path)

    def _conn(self) -> sqlite3.Connection:
        """Uma conexão por thread (o SQLite não deixa compartilhar entre threads), reaproveitada.

        `with conn:` continua valendo como transação: confirma no fim ou desfaz no erro.
        """
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=5.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 5000")
            try:  # WAL: a interface lê enquanto o vigia grava, sem "database is locked"
                conn.execute("PRAGMA journal_mode = WAL")
            except sqlite3.OperationalError:  # sistemas de arquivos que não aceitam WAL (alguns de rede)
                pass
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def _migrate(self, conn: sqlite3.Connection) -> None:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                f"o histórico ({self.path}) foi criado por uma versão mais nova do tbm; atualize o tbm")
        if version < SCHEMA_VERSION and conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]:
            # Cópia de segurança antes de mexer num histórico que já tem scans (a migração é
            # testada, mas o histórico é seu): history.db.v0.bak ao lado do original.
            backup = self.path.with_name(f"{self.path.name}.v{version}.bak")
            if not backup.exists():
                dest = sqlite3.connect(backup)
                with dest:
                    conn.backup(dest)
                dest.close()
                private_file(backup)
        for number in range(version + 1, SCHEMA_VERSION + 1):
            with conn:
                MIGRATIONS[number - 1](conn)
                conn.execute(f"PRAGMA user_version = {number}")
        if version < SCHEMA_VERSION:
            from tbm.log import get_logger

            get_logger(__name__).info("histórico migrado da versão %d para a %d", version, SCHEMA_VERSION)

    @property
    def schema_version(self) -> int:
        return self._conn().execute("PRAGMA user_version").fetchone()[0]

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
                    encode_blob(result),
                    counts["critical"],
                    counts["high"],
                    counts["medium"],
                    counts["low"],
                ),
            )
            _index_rows(conn, result)

    def get(self, scan_id: str) -> ScanResult | None:
        """Aceita prefixo do ID, como o git aceita hash curto."""
        rows = self._conn().execute(
            "SELECT data FROM scans WHERE scan_id LIKE ? LIMIT 2", (f"{scan_id}%",)
        ).fetchall()
        if len(rows) > 1:
            raise ValueError(f"prefixo ambíguo: {scan_id}")
        return self._hydrate(decode_blob(rows[0]["data"])) if rows else None

    def latest(self, label: str, *, exclude: str | None = None, before: str | None = None) -> ScanResult | None:
        query = "SELECT data FROM scans WHERE label = ? AND scan_id != ?"
        params: list = [label, exclude or ""]
        if before:
            query += " AND started_at < ?"
            params.append(before)
        row = self._conn().execute(query + " ORDER BY started_at DESC LIMIT 1", params).fetchone()
        return self._hydrate(decode_blob(row["data"])) if row else None

    # ───────────────────────── consultas pelos índices (sem abrir os blobs) ─────────────────────────

    def light(self, label: str, limit: int = 30, *, skip_latest: bool = False,
              exclude: str | None = None) -> builtins.list[ScanResult]:
        """Os `limit` scans mais recentes do rótulo, do mais antigo para o mais novo, montados só
        pelos índices: aparelhos, portas e achados, sem evidências. Serve para histórico, contagens
        e comparações; o relatório completo continua vindo de `get`/`latest`."""
        conn = self._conn()
        rows = conn.execute(
            "SELECT scan_id, label, started_at, score, grade FROM scans WHERE label = ? AND scan_id != ? "
            "ORDER BY started_at DESC LIMIT ?", (label, exclude or "", limit)).fetchall()
        if skip_latest:
            rows = rows[1:]
        if not rows:
            return []
        ids = [r["scan_id"] for r in rows]
        marks = ",".join("?" * len(ids))
        hosts: dict[str, builtins.list[sqlite3.Row]] = {i: [] for i in ids}
        findings: dict[str, builtins.list[sqlite3.Row]] = {i: [] for i in ids}
        for h in conn.execute(f"SELECT * FROM scan_hosts WHERE scan_id IN ({marks})", ids):  # noqa: S608
            hosts[h["scan_id"]].append(h)
        for f in conn.execute(f"SELECT * FROM scan_findings WHERE scan_id IN ({marks})", ids):  # noqa: S608
            findings[f["scan_id"]].append(f)
        known = self.devices()
        cache: dict[str, builtins.list[Service]] = {}
        out = []
        for r in reversed(rows):
            scan = light_scan(r, hosts[r["scan_id"]], findings[r["scan_id"]])
            _attach_services(scan, hosts[r["scan_id"]], cache)
            self._hydrate(scan, known)
            out.append(scan)
        return out

    def sightings(self, label: str, limit: int = 50) -> tuple[dict[str, dict], int]:
        """Por aparelho, nos `limit` scans mais recentes: primeira vez visto, em quantos scans
        apareceu e a sequência de IPs. Devolve também quantos scans entraram na conta."""
        conn = self._conn()
        ids = conn.execute("SELECT scan_id FROM scans WHERE label = ? ORDER BY started_at DESC LIMIT ?",
                           (label, limit)).fetchall()
        seen: dict[str, dict] = {}
        if not ids:
            return seen, 0
        marks = ",".join("?" * len(ids))
        for r in conn.execute(
                "SELECT h.identity, h.address, s.started_at FROM scan_hosts h JOIN scans s ON s.scan_id = h.scan_id "
                f"WHERE h.scan_id IN ({marks}) ORDER BY s.started_at", [i[0] for i in ids]):  # noqa: S608
            entry = seen.get(r[0])
            if entry is None:
                entry = seen[r[0]] = {"first": datetime.fromisoformat(r[2]), "times": 0, "ips": []}
            entry["times"] += 1
            if not entry["ips"] or entry["ips"][-1] != r[1]:
                entry["ips"].append(r[1])
        return seen, len(ids)

    def first_seen(self, label: str, identity: str) -> datetime | None:
        row = self._conn().execute(
            "SELECT MIN(s.started_at) FROM scan_hosts h JOIN scans s ON s.scan_id = h.scan_id "
            "WHERE s.label = ? AND h.identity = ?", (label, identity)).fetchone()
        return datetime.fromisoformat(row[0]) if row and row[0] else None

    # ───────────────────────── retenção ─────────────────────────

    def prune(self, *, keep_days: int = 30, weekly_until_days: int = 365, now: datetime | None = None,
              dry_run: bool = False) -> builtins.list[str]:
        """Apaga scans antigos: mantém tudo dos últimos `keep_days`, depois 1 por semana até
        `weekly_until_days`, depois 1 por mês. O scan mais recente de cada rótulo nunca sai."""
        now = now or datetime.now(UTC)
        conn = self._conn()
        rows = conn.execute("SELECT scan_id, label, started_at FROM scans ORDER BY started_at DESC").fetchall()
        kept: set[tuple[str, str]] = set()
        newest: set[str] = set()
        drop: builtins.list[str] = []
        for r in rows:
            when = datetime.fromisoformat(r["started_at"])
            if when.tzinfo is None:
                when = when.replace(tzinfo=UTC)
            age = (now - when).days
            if r["label"] not in newest:
                newest.add(r["label"])
                continue
            if age <= keep_days:
                continue
            year, week, _ = when.isocalendar()
            bucket = f"w{year}-{week}" if age <= weekly_until_days else f"m{when:%Y-%m}"
            if (r["label"], bucket) in kept:
                drop.append(r["scan_id"])
            else:
                kept.add((r["label"], bucket))
        if drop and not dry_run:
            with conn:
                for table in ("scans", "scan_hosts", "scan_findings"):
                    conn.executemany(f"DELETE FROM {table} WHERE scan_id = ?",  # noqa: S608
                                     [(i,) for i in drop])
        return drop

    def vacuum(self) -> None:
        self._conn().execute("VACUUM")

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

    def set_device(self, identity: str, *, alias: str | None = None, trusted: bool | None = None,
                   category: str | None = None, note: str | None = None) -> None:
        """Atualiza só o que foi passado ("" apaga o nome, a categoria ou a nota)."""
        current = self.devices().get(identity)

        def keep(new: str | None, col: str) -> str | None:
            if new is not None:
                return new.strip() or None
            return current[col] if current else None

        new_trusted = int(trusted) if trusted is not None else (current["trusted"] if current else 0)
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO devices (identity, alias, trusted, updated_at, category, note) "
                "VALUES (?,?,?,?,?,?)",
                (identity, keep(alias, "alias"), new_trusted, datetime.now(UTC).isoformat(),
                 keep(category, "category"), keep(note, "note")))

    def _hydrate(self, result: ScanResult, known: dict[str, sqlite3.Row] | None = None) -> ScanResult:
        """Aplica nomes e aprovações atuais, inclusive em scans antigos."""
        known = self.devices() if known is None else known
        for h in result.hosts:
            if row := known.get(h.identity):
                h.alias, h.trusted = row["alias"], bool(row["trusted"])
                h.category, h.note = row["category"], row["note"]
        return result

    # ───────────────────────── notificações ─────────────────────────

    def add_event(self, kind: str, data: dict, *, label: str | None = None, link: str | None = None) -> None:
        import json

        with self._conn() as conn:
            conn.execute("INSERT INTO events (at, kind, label, data, link) VALUES (?,?,?,?,?)",
                         (datetime.now(UTC).isoformat(), kind, label, json.dumps(data, ensure_ascii=False), link))
            # guarda só as 200 mais recentes
            conn.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 200)")

    def events(self, limit: int = 30) -> builtins.list[dict]:
        import json

        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(r), "data": json.loads(r["data"])} for r in rows]

    def unread_events(self) -> int:
        with self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM events WHERE read = 0").fetchone()[0]

    def mark_events_read(self) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE events SET read = 1 WHERE read = 0")

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
