"""Fase 2 da interface: configuração de alertas, vigia sem janela e carta para o provedor."""

import json
from datetime import datetime
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from tbm import config, schedule
from tbm.dashboard import create_app
from tbm.dashboard.jobs import JobRunner
from tbm.dashboard.security import GuiSettings
from tbm.models import Finding, Host, ScanResult, Service, Severity
from tbm.pipeline import finalize
from tbm.squeak import HistoryStore

ORIGIN = {"Origin": "http://testserver"}
TOKEN = "7123456789:" + "A" * 35


# ───────────────────────────── configuração ─────────────────────────────


def test_notify_precedence_env_over_config(monkeypatch):
    assert config.notify_target() == (None, "none")
    config.save({"notify": "ntfy://topico-arquivo"})
    assert config.notify_target() == ("ntfy://topico-arquivo", "config")
    monkeypatch.setenv("TBM_WEBHOOK", "ntfy://topico-env")
    assert config.notify_target() == ("ntfy://topico-env", "env")


def test_describe_never_leaks_secrets():
    tg = config.describe(f"tg://{TOKEN}/123456")
    assert tg == {"kind": "telegram", "label": "Telegram · chat ••••3456"} and "AAAA" not in str(tg)
    hook = config.describe("https://discord.com/api/webhooks/1/SEGREDO")
    assert "SEGREDO" not in hook["label"] and hook["kind"] == "discord"
    ntfy = config.describe("ntfy://tbm-abcdef123")
    assert "abcdef123" not in ntfy["label"]
    assert config.describe(None)["kind"] == "none"


def test_persist_notify_keeps_env_in_sync(monkeypatch):
    calls = []
    monkeypatch.setattr(config, "_setx", lambda v: calls.append(v) or True)
    assert config.persist_notify("ntfy://novo-topico") == []  # sem variável no ambiente: só o arquivo
    assert config.load()["notify"] == "ntfy://novo-topico" and calls == []

    monkeypatch.setenv("TBM_WEBHOOK", "tg://antigo/1")
    notes = config.persist_notify("ntfy://outro-topico")
    assert calls == ["ntfy://outro-topico"] and "atualizada" in notes[0]
    assert config.notify_target() == ("ntfy://outro-topico", "env")  # não divergem


def test_persist_notify_warns_when_env_cannot_be_updated(monkeypatch):
    monkeypatch.setattr(config, "_setx", lambda v: False)  # ex.: Linux
    monkeypatch.setenv("TBM_WEBHOOK", "tg://antigo/1")
    assert "prioridade" in config.persist_notify("ntfy://x-topico")[0]


# ───────────────────────────── execução agendada ─────────────────────────────


def test_scheduled_runner_writes_log_without_console():
    from tbm._scheduled import main

    spec = schedule.windows_spec("casa")
    spec.parent.mkdir(parents=True)
    spec.write_text(json.dumps({"label": "casa", "argv": ["checks"]}), encoding="utf-8")
    assert main(["casa"]) == 0
    log = schedule.read_log("casa", 200)
    assert "início do scan agendado 'casa'" in log and "cve.nvd" in log and "fim · código 0" in log


def test_scheduled_runner_records_failures():
    from tbm._scheduled import main

    assert main(["sem-spec"]) == 1  # spec inexistente: erro vai para o log, não para uma janela
    assert "FileNotFoundError" in schedule.read_log("sem-spec")


def test_schedule_status_parsing():
    assert schedule._parse_iso("1999-11-30T00:00:00") is None  # "nunca rodou"
    assert schedule._parse_iso("2026-11-17T09:00:00-03:00").hour == 9
    assert schedule.status("win32", "rótulo inválido!")["installed"] is False


# ───────────────────────────── interface ─────────────────────────────


@pytest.fixture
def gui(tmp_path, monkeypatch):
    store = HistoryStore(tmp_path / "h.db")
    ont = Host(address="192.168.100.175", mac="cc:ba:bd:99:74:01", device_type="roteador/modem",
               services=[Service(port=23, name="telnet")])
    store.save(finalize(ScanResult(label="casa", hosts=[ont, Host(address="192.168.100.183")], findings=[
        Finding(check_id="service.exposed", title="Telnet exposto", severity=Severity.HIGH,
                host=ont.address, port=23, evidence="Porta 23/tcp aberta")])))
    settings = GuiSettings(port=8770, extra_hosts={"testserver"})
    client = TestClient(create_app(store, gui=settings, runner=JobRunner(store)))
    client.get(f"/?token={settings.token}")
    sent = []

    async def fake_send(target, transport=None):
        sent.append(target)
        return 401 if "RUIM" in target else 200

    monkeypatch.setattr("tbm.dashboard.routes.alerts.send_test", fake_send)
    monkeypatch.setattr(config, "_setx", lambda v: True)
    monkeypatch.setattr(schedule, "status", lambda platform, label: {
        "installed": False, "supported": True, "next": None, "last": None, "result": None, "state": None})

    def post(url, body):
        return client.post(url, json=body, headers={**ORIGIN, "X-TBM-Token": settings.token})

    return SimpleNamespace(client=client, post=post, sent=sent, store=store)


def test_alerts_page_and_new_endpoints_need_token(gui):
    page = gui.client.get("/alerts")
    assert page.status_code == 200 and "nenhum destino configurado" in page.text and "@BotFather" in page.text
    for url in ("/api/alerts/save", "/api/telegram/lookup", "/api/watch/install", "/api/letter"):
        assert gui.client.post(url, json={}, headers=ORIGIN).status_code == 403  # sem X-TBM-Token


def test_telegram_wizard(gui, monkeypatch):
    async def bot(token):
        return "vigia_bot"

    async def chats(token):
        return [SimpleNamespace(id=555, title="Eu", kind="private")]

    monkeypatch.setattr("tbm.dashboard.routes.alerts.bot_username", bot)
    monkeypatch.setattr("tbm.dashboard.routes.alerts.find_chats", chats)
    assert gui.post("/api/telegram/lookup", {"token": "curto"}).status_code == 400
    r = gui.post("/api/telegram/lookup", {"token": TOKEN}).json()
    assert r == {"bot": "vigia_bot", "chats": [{"id": 555, "title": "Eu", "kind": "private"}]}

    saved = gui.post("/api/alerts/save", {"kind": "telegram", "token": TOKEN, "chat_id": "555"})
    assert saved.status_code == 200 and saved.json()["current"]["label"] == "Telegram · chat 555"
    assert TOKEN not in saved.text  # a resposta nunca devolve o token
    assert config.notify_target() == (f"tg://{TOKEN}/555", "config")
    assert gui.sent == [f"tg://{TOKEN}/555"]  # testou antes de salvar


def test_failed_test_message_does_not_save(gui):
    r = gui.post("/api/alerts/save", {"kind": "url", "url": "https://hooks.slack.com/RUIM"})
    assert r.status_code == 400 and "401" in r.json()["error"]
    assert config.notify_target() == (None, "none")
    assert gui.post("/api/alerts/save", {"kind": "url", "url": "http://inseguro"}).status_code == 400
    assert gui.post("/api/alerts/save", {"kind": "ntfy", "topic": "ab"}).status_code == 400


def test_ntfy_save_test_and_remove(gui):
    assert gui.post("/api/alerts/test", {}).status_code == 400  # nada configurado ainda
    assert gui.post("/api/alerts/save", {"kind": "ntfy", "topic": "tbm-abc123"}).status_code == 200
    assert gui.post("/api/alerts/test", {}).json() == {"ok": True}
    assert "ntfy" in gui.client.get("/alerts").text
    assert gui.post("/api/alerts/remove", {}).json()["ok"]
    assert config.notify_target() == (None, "none")


def test_watch_install_and_remove(gui, monkeypatch):
    executed = []
    monkeypatch.setattr(schedule, "execute", lambda plan: executed.append(plan) or [])
    page = gui.client.get("/watch")
    assert page.status_code == 200 and "Ligar vigia" in page.text and "Configure os alertas" in page.text

    bad = gui.post("/api/watch/install", {"targets": "8.8.8.8", "label": "casa", "hours": 6})
    assert bad.status_code == 400 and "fora do escopo" in bad.json()["error"]
    assert gui.post("/api/watch/install", {"targets": "192.168.100.0/24", "hours": 5}).status_code == 400

    ok = gui.post("/api/watch/install", {"targets": "192.168.100.0/24", "label": "casa", "hours": 6, "udp": True})
    assert ok.status_code == 200 or ok.json().get("manual")
    if executed:
        argv = json.dumps(executed[0].files and next(iter(executed[0].files.values())))
        assert "--active" not in argv and "--notify" not in argv  # vigia nunca faz testes ativos
    assert gui.post("/api/watch/remove", {"label": "casa"}).status_code == 200
    assert gui.post("/api/watch/remove", {"label": "x y"}).status_code == 400


def test_watch_page_shows_status_and_log(gui, monkeypatch):
    monkeypatch.setattr(schedule, "status", lambda platform, label: {
        "installed": True, "supported": True, "state": "Ready", "result": 0,
        "next": datetime(2026, 11, 17, 15, 0), "last": datetime(2026, 11, 17, 9, 0)})
    log = schedule.log_path("casa")
    log.parent.mkdir(parents=True)
    log.write_text("=== 2026-11-17 09:00:00 · início do scan agendado 'casa' ===\nNota: D 49/100\n", encoding="utf-8")
    page = gui.client.get("/watch?label=casa").text
    assert "Ativo" in page and "17/11 15:00" in page and "Nota: D 49/100" in page and "Desligar vigia" in page
    assert gui.client.get("/watch?label=<script>").status_code == 400


def test_letter_page_and_generation(gui):
    page = gui.client.get("/letter")
    assert "192.168.100.175" in page.text and "192.168.100.183" not in page.text  # só quem tem achados
    r = gui.post("/api/letter", {"label": "casa", "host": "192.168.100.175", "name": "Fulano"})
    assert r.status_code == 200 and "Telnet" in r.json()["text"] and "Fulano" in r.json()["text"]
    assert gui.post("/api/letter", {"label": "casa", "host": "10.9.9.9"}).status_code == 404
    assert gui.post("/api/letter", {"label": "casa", "host": "192.168.100.175",
                                    "min_severity": "xx"}).status_code == 400
    inv = gui.client.get("/inventory/casa").text
    assert "/letter?label=casa&host=192.168.100.175" in inv
