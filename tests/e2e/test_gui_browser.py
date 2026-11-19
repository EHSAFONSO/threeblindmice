"""Interface no navegador de verdade (Playwright), clicando como uma pessoa.

Usa o navegador já instalado (Edge no Windows, Chrome no Linux/macOS) em vez
de baixar um Chromium: nada entra sem passar pelos locks. Sem navegador ou sem
o Playwright, os testes são pulados.

O servidor roda numa thread com um histórico temporário e um "scan" falso:
nada sai para a rede.
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
import threading
import time
from datetime import timedelta

import pytest

pytest.importorskip("playwright.sync_api")
uvicorn = pytest.importorskip("uvicorn")

from playwright.sync_api import Error as PlaywrightError  # noqa: E402
from playwright.sync_api import expect, sync_playwright  # noqa: E402

from tbm.dashboard import create_app  # noqa: E402
from tbm.dashboard.jobs import JobRunner  # noqa: E402
from tbm.dashboard.security import GuiSettings  # noqa: E402
from tbm.models import Finding, Host, ScanResult, Service, Severity  # noqa: E402
from tbm.pipeline import finalize  # noqa: E402
from tbm.progress import report_found  # noqa: E402
from tbm.squeak import HistoryStore, diff_scans  # noqa: E402

pytestmark = pytest.mark.e2e

GW = Host(address="192.168.0.1", mac="fc:bc:d1:72:57:48", device_type="roteador/modem", vendor="ZTE Corporation",
          services=[Service(port=23), Service(port=80)])
TV = Host(address="192.168.0.50", mac="aa:bb:cc:00:11:22", device_type="TV", device_name="Sala",
          services=[Service(port=8008)])


def lab_scan(**kw) -> ScanResult:
    return finalize(ScanResult(label="casa", gateway=GW.address, hosts=[GW, TV], findings=[
        Finding(check_id="service.exposed", title="Telnet exposto", severity=Severity.HIGH, host=GW.address,
                port=23, device=GW.identity),
        Finding(check_id="upnp.igd", title="UPnP ligado", severity=Severity.LOW, host=GW.address, port=1900,
                device=GW.identity),
    ], **kw))


def fake_executor(job, store, progress):
    """Faz o papel do Scout+Sniffer: anuncia aparelhos e devolve um resultado pronto."""

    async def run():
        progress.start("Scout · descoberta de hosts", 2)
        for h in (GW, TV):
            report_found(progress, h.address, name=h.device_name, gateway=h is GW, type=h.device_type)
            await asyncio.sleep(0.3)
        result = lab_scan()
        previous = store.latest("casa")
        store.save(result)
        return result, diff_scans(previous, result)

    return run()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    home = tmp_path_factory.mktemp("home")
    mp = pytest.MonkeyPatch()
    mp.setenv("TBM_HOME", str(home))
    mp.delenv("TBM_WEBHOOK", raising=False)
    mp.setattr("tbm.schedule.status", lambda platform, label: {
        "installed": False, "supported": True, "next": None, "last": None, "result": None, "state": None})

    async def no_update(*a, **k):
        return None

    mp.setattr("tbm.update.check", no_update)
    store = HistoryStore(home / "history.db")
    older = lab_scan()
    older.started_at -= timedelta(days=1)
    store.save(older)
    port = free_port()
    settings = GuiSettings(port=port)
    app = create_app(store, gui=settings, runner=JobRunner(store, executor=fake_executor))
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield settings.login_url(), f"http://127.0.0.1:{port}", store
    srv.should_exit = True
    thread.join(5)
    mp.undo()


@pytest.fixture(scope="module")
def browser():
    channel = "msedge" if sys.platform == "win32" else "chrome"
    with sync_playwright() as p:
        try:
            b = p.chromium.launch(channel=channel, headless=True)
        except PlaywrightError as exc:
            reason = f"navegador {channel} indisponível: {exc.message.splitlines()[0]}"
            if os.environ.get("TBM_E2E_REQUIRED"):  # no CI, pular seria esconder uma falha
                pytest.fail(reason)
            pytest.skip(reason)
        yield b
        b.close()


@pytest.fixture
def page(browser, server):
    login, _, _ = server
    # locale fixo: o navegador do CI pede en-US, e a interface obedeceria (os textos aqui são em português)
    ctx = browser.new_context(viewport={"width": 1200, "height": 900}, locale="pt-BR")
    pg = ctx.new_page()
    errors: list[str] = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.goto(login)
    yield pg
    ctx.close()
    assert not errors, f"erros de JavaScript: {errors}"


def test_home_shows_health_and_actions(page):
    expect(page.get_by_text("Saúde da rede")).to_be_visible()
    expect(page.get_by_text("Desativar o Telnet").first).to_be_visible()
    expect(page.locator(".gauge")).to_be_visible()


def test_theme_toggle_cycles(page):
    root = page.locator("html")
    first = root.get_attribute("data-theme")
    page.get_by_role("button", name="Alternar tema: automático, claro ou escuro").click()
    assert root.get_attribute("data-theme") != first


def test_map_node_opens_device_drawer(page, server):
    page.goto(server[1] + "/map/casa")
    page.locator('g.node[data-drawer$="192.168.0.50"]').click()
    drawer = page.locator(".drawer")
    expect(drawer).to_have_class("drawer open")
    expect(drawer.get_by_text("aa:bb:cc:00:11:22")).to_be_visible()
    page.keyboard.press("Escape")
    expect(drawer).not_to_have_class("drawer open")


def test_findings_guide_and_accept_risk(page, server):
    page.goto(server[1] + "/findings/casa")
    card = page.locator(".action-card", has_text="Desativar o Telnet")
    card.locator("summary", has_text="Como fazer no seu ZTE").click()
    expect(card.get_by_text("Controle de serviço").first).to_be_visible()
    card.locator("summary", has_text="Telnet exposto").click()
    card.get_by_role("button", name="Aceitar risco…").click()
    card.get_by_placeholder("Motivo").fill("modem da operadora, chamado aberto")
    card.get_by_role("button", name="Aceitar", exact=True).click()
    expect(page.get_by_text("aceito").first).to_be_visible()


def test_rename_and_approve_device(page, server):
    page.goto(server[1] + "/inventory/casa")
    card = page.locator("article", has_text="192.168.0.50")
    card.get_by_role("button", name="Renomear").click()
    dialog = page.locator("dialog.tbm")
    dialog.get_by_role("textbox").fill("TV da sala")
    dialog.get_by_role("button", name="Salvar").click()
    card = page.locator("article", has_text="192.168.0.50")
    expect(card.get_by_text("TV da sala")).to_be_visible()
    card.get_by_role("button", name="Aprovar").click()
    expect(page.locator("article", has_text="192.168.0.50").get_by_text("✓ conhecido")).to_be_visible()
    assert any(r["alias"] == "TV da sala" and r["trusted"] for r in server[2].devices().values())


def test_live_scan_shows_devices_as_they_appear(page, server):
    page.goto(server[1] + "/scan")
    page.locator("#targets").fill("192.168.0.0/24")
    page.get_by_role("button", name="Iniciar scan").click()
    expect(page.locator("#progress-section")).to_be_visible()
    expect(page.get_by_text("192.168.0.50").first).to_be_visible(timeout=10_000)
    expect(page.get_by_text("Scan concluído")).to_be_visible(timeout=15_000)
