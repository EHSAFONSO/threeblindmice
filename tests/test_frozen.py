"""Versão instalada pelo setup.exe: sem python.exe, com threeblindmice.exe e tbm.exe lado a lado."""

import re
import subprocess
import sys
from pathlib import Path

import pytest

from tbm import frozen, schedule
from tbm.desktop import shortcut
from tbm.desktop.app import APP_ID

ROOT = Path(__file__).resolve().parent.parent
WIN = ROOT / "packaging" / "windows"


@pytest.fixture
def installed(monkeypatch, tmp_path):
    app_dir = tmp_path / "Programs" / "threeblindmice"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(app_dir / "threeblindmice.exe"))
    monkeypatch.setenv("TBM_HOME", str(tmp_path / "home"))
    return app_dir


def test_scheduled_task_uses_the_installed_app(installed):
    plan = schedule.build_plan("win32", ["192.168.0.0/24"], "casa", 3600, [])
    tr = plan.commands[0][plan.commands[0].index("/TR") + 1]
    assert tr.endswith("threeblindmice.exe --scheduled casa") and "-m tbm" not in tr
    assert not any("pythonw" in w for w in plan.warnings)
    assert schedule.tbm_executable() == str(installed / "tbm.exe")


def test_shortcut_points_to_the_installed_app(installed):
    exe, args = shortcut.launcher()
    assert exe == str(installed / "threeblindmice.exe") and args == []


def test_gui_main_dispatches_scheduled_runs(monkeypatch):
    seen = {}
    monkeypatch.setattr("tbm._scheduled.main", lambda argv: seen.setdefault("argv", argv) and 0)
    assert frozen.gui_main(["--scheduled", "casa"]) == 0
    assert seen["argv"] == ["casa"]


def test_uninstall_only_touches_tasks_of_this_copy(installed, monkeypatch):
    specs = installed.parent.parent / "home" / "schedules"
    specs.mkdir(parents=True)
    for label in ("casa", "escritorio"):
        (specs / f"threeblindmice-{label}.json").write_text("{}", encoding="utf-8")
    xml = {  # casa: tarefa antiga do pip (outro Python); escritorio: criada pelo app instalado
        "threeblindmice-casa": r"<Command>C:\Users\x\.venv\Scripts\pythonw.exe</Command>",
        "threeblindmice-escritorio": f"<Command>{installed}\\threeblindmice.exe</Command>",
    }

    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, stdout=xml[cmd[3]], stderr="")

    monkeypatch.setattr(schedule.subprocess, "run", fake_run)
    assert schedule.windows_tasks_using(installed) == ["escritorio"]


def test_installer_matches_the_app():
    iss = (WIN / "threeblindmice.iss").read_text(encoding="utf-8")
    # mesmo AppUserModelID do app: a janela agrupa sob o atalho fixado na barra
    assert set(re.findall(r'AppUserModelID: "([^"]+)"', iss)) == {APP_ID}
    assert "PrivilegesRequired=lowest" in iss and "uninstall-cleanup" in iss
    spec = (WIN / "threeblindmice.spec").read_text(encoding="utf-8")
    assert '"threeblindmice"' in spec and '"tbm"' in spec and "upx=False" in spec
    assert frozen.GUI_EXE == "threeblindmice.exe" and frozen.CLI_EXE == "tbm.exe"
