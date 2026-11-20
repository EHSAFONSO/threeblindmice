"""v0.9: verificação de um aparelho, nota projetada, notificações, categorias, busca e gráficos."""

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from tbm.dashboard import create_app
from tbm.dashboard.app import mini_path, sev_name
from tbm.dashboard.jobs import JobRunner, merge_host
from tbm.dashboard.security import GuiSettings
from tbm.i18n import use
from tbm.models import Finding, Host, ScanResult, Service, Severity
from tbm.pipeline import finalize, record_events
from tbm.squeak import HistoryStore, diff_scans
from tbm.squeak.actions import build_actions, impacts, project

GW = Host(address="192.168.0.1", mac="fc:bc:d1:72:57:48", device_type="roteador/modem",
          services=[Service(port=23), Service(port=80)])
PC = Host(address="192.168.0.20", mac="aa:aa:aa:aa:aa:aa", services=[Service(port=445)])


def f(check, title, sev, host, port=None, key=""):
    return Finding(check_id=check, title=title, severity=sev, host=host.address, port=port, key=key,
                   device=host.identity)


def lab() -> ScanResult:
    return finalize(ScanResult(label="casa", gateway=GW.address, hosts=[GW, PC], findings=[
        f("service.exposed", "Telnet exposto", Severity.HIGH, GW, 23),
        f("upnp.igd", "UPnP ligado", Severity.LOW, GW, 1900),
        f("service.exposed", "SMB exposto", Severity.MEDIUM, PC, 445),
        Finding(check_id="network.wifi", title="Wi-Fi WPA2", severity=Severity.INFO, host="wifi", key="wpa2"),
        Finding(check_id="network.ipv6", title="IPv6", severity=Severity.INFO, host=GW.address, key="prefix"),
    ]))


def test_merge_host_replaces_only_that_device():
    before = lab()
    fixed_gw = GW.model_copy(update={"services": [Service(port=80)]})
    partial = finalize(ScanResult(label="casa", hosts=[fixed_gw], findings=[
        f("upnp.igd", "UPnP ligado", Severity.LOW, GW, 1900)]))
    merged = merge_host(before, partial, GW.address)
    titles = {x.title for x in merged.findings}
    assert "Telnet exposto" not in titles and "UPnP ligado" in titles
    assert "SMB exposto" in titles  # outro aparelho intacto
    assert "IPv6" in titles and "Wi-Fi WPA2" in titles  # achados da rede como um todo ficam
    assert merged.scan_id != before.scan_id and merged.score > before.score
    assert [h.address for h in merged.hosts] == [GW.address, PC.address]


def test_projection_and_impacts():
    scan = lab()
    actions = build_actions(scan)
    telnet = next(a for a in actions if a.kind == "telnet")
    p = project(scan, [telnet])
    assert p.gain > 0 and p.score == scan.score + p.gain
    every = project(scan, actions)
    assert every.score == 100 and every.grade == "A"
    assert impacts(scan, actions)[telnet.key] == p.gain


def test_events_and_device_metadata(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    old = lab()
    store.save(old)
    new = lab()
    tv = Host(address="192.168.0.50", mac="bb:bb:bb:bb:bb:bb", device_name="TV")
    new.hosts.append(tv)
    d = diff_scans(old, new)
    d.novel_hosts = [tv]
    record_events(store, new, d)
    kinds = [e["kind"] for e in store.events()]
    assert kinds == ["unknown_device", "scan_done"] and store.unread_events() == 2
    store.mark_events_read()
    assert store.unread_events() == 0

    store.set_device(tv.identity, category="familia", note="TV da sala")
    store.set_device(tv.identity, alias="Sala")  # não apaga categoria/nota
    row = store.devices()[tv.identity]
    assert (row["alias"], row["category"], row["note"]) == ("Sala", "familia", "TV da sala")
    store.save(finalize(new))
    loaded = store.latest("casa").host(tv.address)
    assert loaded.category == "familia" and loaded.note == "TV da sala"


def test_severity_names_and_curves():
    assert sev_name(Severity.HIGH) == "alto"
    with use("en"):
        assert sev_name("high") == "high" and sev_name(Severity.CRITICAL) == "critical"
    p = mini_path([40, 45, 45, 60], 100, 40)
    assert p["line"].startswith("M") and p["line"].count("C") == 3 and p["area"].endswith("Z")
    assert mini_path([])["line"] == "" and mini_path([50])["line"].startswith("M")


@pytest.fixture
def gui(tmp_path, monkeypatch):
    store = HistoryStore(tmp_path / "h.db")
    store.save(lab())
    settings = GuiSettings(port=8770, extra_hosts={"testserver"})
    client = TestClient(create_app(store, gui=settings, runner=JobRunner(store)))
    client.get(f"/?token={settings.token}")
    monkeypatch.setattr("tbm.schedule.status", lambda platform, label: {
        "installed": False, "supported": True, "next": None, "last": None, "result": None, "state": None})
    headers = {"X-TBM-Token": settings.token, "Origin": "http://testserver"}
    return SimpleNamespace(client=client, store=store, headers=headers)


def test_new_pages_and_apis(gui):
    c = gui.client
    items = c.get("/api/search").json()["items"]
    groups = {i["group"] for i in items}
    assert {"Páginas", "Dispositivos", "Ações"} <= groups
    fix = next(i for i in items if i["group"] == "Ações" and "Telnet" in i["title"])
    page = c.get(fix["href"]).text
    assert "Já fiz, verificar" in page and "Passo a passo" in page
    assert c.get("/fix/casa/naoexiste", follow_redirects=False).status_code == 303

    dev = c.get(f"/device/casa/{GW.address}").text
    assert "Categoria e notas" in dev and "Corrigir agora" in dev

    r = c.post("/api/device", json={"identity": GW.identity, "category": "infraestrutura", "note": "modem"},
               headers=gui.headers)
    assert r.status_code == 200
    bad = c.post("/api/device", json={"identity": GW.identity, "category": "xyz"}, headers=gui.headers)
    assert bad.status_code == 400

    gui.store.add_event("resolved", {"n": 2}, label="casa", link="/findings/casa")
    assert c.get("/api/notifications/count").json()["unread"] == 1
    assert "2 problema(s) resolvido(s)" in c.get("/partials/notifications").text
    assert c.get("/api/notifications/count").json()["unread"] == 0

    home = c.get("/").text
    assert "Corrigir agora" in home and "pontos" in home and 'class="side-nav"' in home
    assert c.get("/api/app/version").json()["version"]
    assert c.post("/api/app/show", headers=gui.headers).status_code == 404  # sem janela (não é o app de desktop)
