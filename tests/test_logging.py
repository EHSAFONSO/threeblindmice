"""Fase 5: log técnico em arquivo, sem IP/MAC em INFO, e CLI que não quebra em pipes."""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import sys

import pytest

from tbm import log as tbmlog
from tbm.models import Finding, Host, ScanResult, Severity


@pytest.fixture(autouse=True)
def fresh_logger():
    yield
    root = logging.getLogger("tbm")
    for h in [h for h in root.handlers if h.get_name() == "tbm-file"]:  # só o nosso, não os do pytest
        root.removeHandler(h)
        h.close()


def test_configure_writes_private_rotating_file(tmp_path):
    path = tbmlog.configure("info")
    assert path == tbmlog.log_file() and path.parent.name == "logs"
    tbmlog.get_logger("tbm.teste").info("olá")
    tbmlog.get_logger("tbm.teste").debug("não aparece em INFO")
    for h in logging.getLogger("tbm").handlers:
        h.flush()
    text = path.read_text(encoding="utf-8")
    assert "olá" in text and "não aparece" not in text
    assert tbmlog.configure("info") == path  # idempotente: um handler só
    assert sum(h.get_name() == "tbm-file" for h in logging.getLogger("tbm").handlers) == 1
    with pytest.raises(ValueError):
        tbmlog.configure("barulhento")


def test_scan_summary_in_log_has_no_ip_or_mac(monkeypatch):
    from tbm import pipeline
    from tbm.scope import Scope
    from tbm.scout import ScoutOptions
    from tbm.sniffer import SnifferOptions
    from tbm.squeak import HistoryStore

    host = Host(address="192.168.0.9", mac="aa:bb:cc:dd:ee:ff", device_name="Notebook-da-Ana")

    async def fake_scan(**kw):
        return pipeline.finalize(ScanResult(label="casa", hosts=[host], errors=["http.x: falhou em 192.168.0.9"],
                                            findings=[Finding(check_id="x", title="t", severity=Severity.LOW,
                                                              host=host.address)]))

    monkeypatch.setattr(pipeline, "run_full_scan", fake_scan)
    path = tbmlog.configure("info")
    job = pipeline.ScanJob(specs=["192.168.0.9"], scope=Scope.default(), label="casa",
                           scout_options=ScoutOptions(ports=[80]), sniffer_options=SnifferOptions())
    asyncio.run(pipeline.execute(job, HistoryStore()))
    for h in logging.getLogger("tbm").handlers:
        h.flush()
    text = path.read_text(encoding="utf-8")
    assert "rótulo=casa aparelhos=1 achados=1" in text
    assert "192.168.0.9" not in text and "aa:bb:cc" not in text and "Ana" not in text
    tbmlog.configure("debug")
    asyncio.run(pipeline.execute(job, HistoryStore()))
    for h in logging.getLogger("tbm").handlers:
        h.flush()
    assert "falhou em 192.168.0.9" in path.read_text(encoding="utf-8")  # o detalhe fica no DEBUG


def test_cli_log_level_option():
    from typer.testing import CliRunner

    from tbm.cli import app

    assert CliRunner().invoke(app, ["--log-level", "debug", "--version"]).exit_code == 0
    assert logging.getLogger("tbm").level == logging.DEBUG
    assert CliRunner().invoke(app, ["--log-level", "xyz", "--version"]).exit_code != 0


def test_help_survives_a_cp1252_pipe(tmp_path):
    """No Windows, `tbm scan --help | findstr` quebrava no "→" da descrição (UnicodeEncodeError)."""
    env = {**os.environ, "PYTHONIOENCODING": "cp1252", "TBM_HOME": str(tmp_path)}
    proc = subprocess.run([sys.executable, "-m", "tbm", "scan", "--help"], capture_output=True, env=env,
                          timeout=60, check=False)
    assert proc.returncode == 0, proc.stderr.decode("cp1252", "replace")[-500:]
    assert b"--discovery" in proc.stdout
