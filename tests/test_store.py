"""Fase 1 do plano: migrações versionadas, índices, blob comprimido, retenção e concorrência."""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime, timedelta

import pytest

from tbm.dashboard.views import device_history, offline_hosts, timeline
from tbm.models import Finding, Host, ScanResult, Service, Severity
from tbm.squeak import HistoryStore
from tbm.squeak.actions import progress
from tbm.squeak.store import SCHEMA_VERSION, ZPREFIX

# Esquema da v0.8/v0.9: sem user_version, sem tabelas de índice, blob em texto puro.
OLD_SCHEMA = """
CREATE TABLE scans (scan_id TEXT PRIMARY KEY, label TEXT NOT NULL, started_at TEXT NOT NULL, score INTEGER,
    grade TEXT, hosts INTEGER, findings INTEGER, data TEXT NOT NULL);
CREATE TABLE devices (identity TEXT PRIMARY KEY, alias TEXT, trusted INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL);
"""


def make_scan(i: int, *, label: str = "casa", extra_host: bool = False, start: datetime | None = None) -> ScanResult:
    gw = Host(address="192.168.0.1", mac="aa:aa:aa:aa:aa:01", device_type="roteador/modem",
              services=[Service(port=80), Service(port=53, transport="udp")])
    tv = Host(address=f"192.168.0.{20 + i}", mac="aa:aa:aa:aa:aa:02", device_name="TV",
              services=[Service(port=8008)] + ([Service(port=23)] if i % 2 else []))
    hosts = [gw, tv] + ([Host(address="192.168.0.99", device_name="Visita")] if extra_host else [])
    findings = [Finding(check_id="http.admin", title="Painel", severity=Severity.MEDIUM, host=gw.address,
                        device=gw.identity, port=80, evidence="x" * 500)]
    if i % 2:
        findings.append(Finding(check_id="telnet", title="Telnet", severity=Severity.HIGH, host=tv.address,
                                device=tv.identity, port=23))
    return ScanResult(label=label, started_at=start or datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=i),
                      hosts=hosts, findings=findings, score=90 - i, grade="B")


def old_db(path, scans: list[ScanResult]) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(OLD_SCHEMA)
    for s in scans:
        conn.execute("INSERT INTO scans VALUES (?,?,?,?,?,?,?,?)",
                     (s.scan_id, s.label, s.started_at.isoformat(), s.score, s.grade, len(s.hosts),
                      len(s.findings), s.model_dump_json()))
    conn.commit()
    conn.close()


def test_old_database_migrates_and_keeps_everything(tmp_path):
    scans = [make_scan(i, extra_host=(i == 1)) for i in range(4)]
    old_db(tmp_path / "h.db", scans)
    store = HistoryStore(tmp_path / "h.db")
    assert store.schema_version == SCHEMA_VERSION
    # cópia de segurança do banco antigo, intacta, antes de migrar
    bak = sqlite3.connect(tmp_path / "h.db.v0.bak")
    assert bak.execute("PRAGMA user_version").fetchone()[0] == 0
    assert bak.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == len(scans)
    bak.close()
    # o relatório completo continua igual, agora com o blob comprimido
    assert store.latest("casa").model_dump() == scans[-1].model_dump()
    assert all(isinstance(r[0], bytes) for r in store._conn().execute("SELECT data FROM scans"))
    # e os índices foram preenchidos a partir dos blobs
    n_hosts = store._conn().execute("SELECT COUNT(*) FROM scan_hosts").fetchone()[0]
    assert n_hosts == sum(len(s.hosts) for s in scans)
    store.close()
    # reabrir não roda as migrações de novo
    again = HistoryStore(tmp_path / "h.db")
    assert again._conn().execute("SELECT COUNT(*) FROM scan_hosts").fetchone()[0] == n_hosts


def test_newer_schema_is_refused(tmp_path):
    conn = sqlite3.connect(tmp_path / "h.db")
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    conn.close()
    with pytest.raises(RuntimeError, match="mais nova"):
        HistoryStore(tmp_path / "h.db")


def test_blob_is_compressed_and_round_trips(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    scan = make_scan(1)
    store.save(scan)
    raw = store._conn().execute("SELECT data FROM scans").fetchone()[0]
    assert isinstance(raw, bytes) and raw.startswith(ZPREFIX)
    assert len(raw) < len(scan.model_dump_json())
    assert store.get(scan.scan_id[:6]).model_dump() == scan.model_dump()


def test_light_scans_match_full_scans(tmp_path):
    """O que as páginas calculam pelos índices é o mesmo que calculavam abrindo os blobs."""
    store = HistoryStore(tmp_path / "h.db")
    scans = [make_scan(i, extra_host=(i == 2)) for i in range(5)]
    for s in scans:
        store.save(s)
    store.set_device("mac:aa:aa:aa:aa:aa:02", alias="TV da sala", trusted=True)
    light = store.light("casa", 30)
    assert [s.scan_id for s in light] == [s.scan_id for s in scans]  # do mais antigo ao mais novo
    for lt, full in zip(light, scans, strict=True):
        assert {h.identity for h in lt.hosts} == {h.identity for h in full.hosts}
        assert {f.fingerprint for f in lt.findings} == {f.fingerprint for f in full.findings}
        assert {(h.identity, s.port, s.transport) for h in lt.hosts for s in h.services} == \
               {(h.identity, s.port, s.transport) for h in full.hosts for s in h.services}
    assert light[-1].host(scans[-1].hosts[1].address).alias == "TV da sala"  # cadastro aplicado
    assert store.light("casa", 30, skip_latest=True)[-1].scan_id == scans[-2].scan_id
    # progresso, aparelhos fora do ar e histórico do aparelho funcionam com os índices
    p = progress(light[:-1], store.latest("casa"))
    assert p.resolved == 1  # o Telnet (scan ímpar) sumiu no último (par)
    assert [h.device_name for h in offline_hosts(store, "casa", store.latest("casa"))] == ["Visita"]
    hist = device_history(store, "casa", "mac:aa:aa:aa:aa:aa:02")
    assert len(hist["series"]) == 5 and any("23" in e["text"] for e in hist["events"])
    assert len(timeline(store, "casa")["points"]) == 5
    assert store.first_seen("casa", "name:visita") == scans[2].started_at
    # inventário pelo SQL == inventário calculado scan a scan
    from tbm.dashboard.app import build_inventory

    seen, n = store.sightings("casa", 50)
    latest = store.latest("casa")
    assert n == 5
    assert build_inventory([latest], seen) == build_inventory([*store.light("casa", 50)[:-1], latest])


def test_prune_policy(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    now = datetime(2026, 11, 20, tzinfo=UTC)
    # um scan por dia nos últimos 400 dias
    for d in range(400):
        store.save(ScanResult(label="casa", started_at=now - timedelta(days=d, hours=1), score=80))
    store.save(ScanResult(label="antigo", started_at=now - timedelta(days=900), score=50))
    gone = store.prune(now=now, dry_run=True)
    assert len(store.list(None, 1000)) == 401  # dry-run não apaga
    gone = store.prune(now=now)
    rows = store.list(None, 1000)
    assert len(rows) == 401 - len(gone)
    recent = [r for r in rows if r["label"] == "casa" and r["started_at"] >= (now - timedelta(days=30)).isoformat()]
    assert len(recent) >= 30  # tudo do último mês
    assert any(r["label"] == "antigo" for r in rows)  # o último de cada rótulo nunca sai
    assert 70 < len(rows) < 110  # ~30 diários + ~48 semanais + 1 mensal
    left = {r[0] for r in store._conn().execute("SELECT DISTINCT scan_id FROM scan_hosts")}
    assert left <= {r["scan_id"] for r in rows}  # índices limpos junto


def test_wal_and_concurrent_writer_and_reader(tmp_path):
    """O vigia grava numa thread enquanto a interface lê em outra: sem 'database is locked'."""
    store = HistoryStore(tmp_path / "h.db")
    assert store._conn().execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    errors: list[BaseException] = []

    def writer() -> None:
        try:
            for i in range(40):
                store.save(make_scan(i))
                store.add_event("scan_done", {"n": i})
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def reader() -> None:
        try:
            for _ in range(80):
                store.light("casa", 10)
                store.latest("casa")
                store.labels()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer), threading.Thread(target=reader), threading.Thread(target=reader)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(store.list("casa", 100)) == 40
