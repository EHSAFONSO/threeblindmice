"""App de desktop: servidor em thread, instância única, ícone, atalho e comportamento da janela."""

import asyncio
import time
from types import SimpleNamespace

import pytest

from tbm.dashboard import create_app
from tbm.dashboard.jobs import Job, JobRunner, ScanParams
from tbm.dashboard.security import GuiSettings
from tbm.desktop import shortcut
from tbm.desktop.app import DesktopApp, job_message
from tbm.desktop.server import (
    ServerThread,
    clear_lock,
    free_port,
    read_lock,
    running_instance,
    write_lock,
)
from tbm.models import ScanResult
from tbm.pipeline import finalize
from tbm.squeak import HistoryStore, diff_scans

# ───────────────────────────── servidor e instância única ─────────────────────────────


@pytest.fixture
def server(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    settings = GuiSettings(port=free_port())
    srv = ServerThread(create_app(store, gui=settings), settings.port)
    srv.start()
    yield settings
    srv.stop()


def test_running_instance_detection(server):
    assert running_instance() is None  # sem lock
    write_lock(server.port, "token-de-outra-instancia")
    assert running_instance() is None  # lock com token errado: não é a nossa sessão
    write_lock(server.port, server.token)
    assert running_instance() == {"port": server.port, "token": server.token}
    clear_lock("outro")  # não apaga lock alheio
    assert read_lock() is not None
    clear_lock(server.token)
    assert read_lock() is None


def test_stale_lock_after_server_stops(tmp_path):
    settings = GuiSettings(port=free_port())
    srv = ServerThread(create_app(HistoryStore(tmp_path / "h.db"), gui=settings), settings.port)
    srv.start()
    write_lock(settings.port, settings.token)
    srv.stop()
    assert not srv.thread.is_alive()
    assert running_instance() is None  # app fechou sem limpar o lock: não pode bloquear o próximo


# ───────────────────────────── notificações ─────────────────────────────


def test_job_message():
    done = Job(id="1", params=ScanParams(targets="10.0.0.1"), status="done",
               summary={"label": "casa", "grade": "D", "score": 49, "hosts": 6, "previous": "abc",
                        "new_findings": 2, "new_devices": ["192.168.0.9 (celular Apple)"]})
    title, text = job_message(done)
    assert title == "Scan 'casa' concluído" and "Nota D (49/100)" in text and "2 achado(s) novo(s)" in text
    assert "aparelho inédito" in text
    err = Job(id="2", params=ScanParams(targets="10.0.0.1"), status="error", error="x" * 500)
    assert job_message(err)[0] == "Scan falhou" and len(job_message(err)[1]) == 200


def test_runner_calls_on_done_and_survives_callback_errors(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    seen = []

    async def fake(spec, store, progress):
        r = finalize(ScanResult(label=spec.label))
        return r, diff_scans(None, r)

    def callback(job):
        seen.append(job.status)
        raise RuntimeError("bandeja indisponível")  # não pode derrubar o scan

    runner = JobRunner(store, executor=fake, on_done=callback)
    job = runner.submit(ScanParams(targets="192.168.0.1", label="casa"))
    for _ in range(100):
        if seen:
            break
        time.sleep(0.02)
    assert seen == ["done"] and job.status == "done"
    asyncio.run(asyncio.sleep(0))


# ───────────────────────────── janela e bandeja ─────────────────────────────


class FakeWindow:
    def __init__(self):
        self.hidden = 0
        self.destroyed = False

    def hide(self):
        self.hidden += 1

    def destroy(self):
        self.destroyed = True


def test_closing_hides_to_tray_and_quit_closes():
    notes = []
    app = DesktopApp(window=FakeWindow(), tray=SimpleNamespace(notify=lambda text, title: notes.append(title)))
    assert app._on_closing() is False  # fechar = esconder
    assert app._on_closing() is False
    time.sleep(0.1)
    assert app.window.hidden == 2 and notes == ["threeblindmice continua rodando"]  # aviso só uma vez
    app.quit()
    assert app.window.destroyed and app._on_closing() is True  # "Sair" fecha de verdade


def test_closing_without_tray_really_closes():
    assert DesktopApp(window=FakeWindow(), tray=None)._on_closing() is True


# ───────────────────────────── ícone e atalho ─────────────────────────────


def test_icon_is_valid_ico():
    pytest.importorskip("PIL")
    from tbm.desktop.icon import ensure_ico, make_icon

    assert make_icon(64).size == (64, 64)
    path = ensure_ico()
    assert path.read_bytes()[:4] == b"\x00\x00\x01\x00"  # cabeçalho ICO


def test_windows_shortcut_plan(tmp_path):
    plan = shortcut.build_plan("win32", desktop=True, icon=tmp_path / "i.ico", home=tmp_path,
                               appdata=str(tmp_path / "Roaming"))
    assert [p.name for p in plan.paths] == ["threeblindmice.lnk", "threeblindmice.lnk"]
    assert "Start Menu" in str(plan.paths[0]) and plan.paths[1].parent.name == "Desktop"
    ps = plan.powershell or ""
    assert "WScript.Shell" in ps and "-m tbm app" in ps and "IconLocation" in ps
    # aspas simples no caminho não quebram o script do PowerShell
    tricky = shortcut.build_plan("win32", home=tmp_path / "O'Brien", appdata=str(tmp_path / "x'y"))
    assert "x''y" in (tricky.powershell or "")


def test_linux_shortcut_and_remove(tmp_path):
    plan = shortcut.build_plan("linux", home=tmp_path)
    [(path, entry)] = plan.files.items()
    assert path.name == "threeblindmice.desktop" and "Exec=" in entry and "-m tbm app" in entry
    shortcut.install(plan)
    assert path.exists()
    assert shortcut.remove("linux", home=tmp_path) == [path] and not path.exists()
    assert not shortcut.build_plan("darwin").supported
