"""Melhorias visuais: ações por correção, painel, mapa, linha do tempo, scan ao vivo e segurança das dicas."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from tbm.dashboard import create_app
from tbm.dashboard.icons import device_icon
from tbm.dashboard.jobs import Job, JobProgress, JobRunner, ScanParams
from tbm.dashboard.security import GuiSettings
from tbm.dashboard.views import gauge, humanize_age, network_map, timeline, worst
from tbm.models import Finding, Host, ScanResult, Service, Severity
from tbm.pipeline import finalize
from tbm.squeak import HistoryStore, render_html
from tbm.squeak.actions import build_actions, classify, progress

ONT = Host(address="192.168.100.175", mac="cc:ba:bd:99:74:01", device_type="roteador/modem",
           services=[Service(port=22), Service(port=23), Service(port=7547)])
GW = Host(address="192.168.100.1", mac="fc:bc:d1:72:57:48", device_type="roteador/modem", services=[Service(port=80)])
PC = Host(address="192.168.100.183", device_type="computador Windows", hostname="Eduardo", services=[Service(port=445)])


def f(check, title, sev, host=ONT, port=None, key="", **kw):
    return Finding(check_id=check, title=title, severity=sev, host=host.address, port=port, key=key,
                   device=host.identity, **kw)


def home_scan(**kw) -> ScanResult:
    return finalize(ScanResult(label="casa", gateway=GW.address, hosts=[GW, ONT, PC], findings=[
        f("cve.nvd", "CVE-2021-36369 em Dropbear", Severity.HIGH, port=22, key="CVE-2021-36369", cvss=7.5, epss=0.02),
        f("ssh.algorithms", "SSH vulnerável ao Terrapin (CVE-2023-48795)", Severity.MEDIUM, port=22, key="terrapin",
          epss=0.94),
        f("ssh.algorithms", "SSH aceita key exchange fraco", Severity.MEDIUM, port=22, key="kex"),
        f("service.exposed", "Telnet exposto", Severity.HIGH, port=23),
        f("service.exposed", "TR-069 exposto", Severity.MEDIUM, port=7547),
        f("http.cleartext-login", "Formulário de senha via HTTP", Severity.MEDIUM, host=GW, port=80),
        f("http.headers", "Headers ausentes", Severity.LOW, host=GW, port=80),
        f("service.exposed", "SMB exposto", Severity.MEDIUM, host=PC, port=445),
        f("udp.services", "mDNS", Severity.INFO, host=PC, port=5353, key="mdns"),
    ], **kw))


# ───────────────────────────── ações por correção ─────────────────────────────


def test_actions_group_by_fix():
    actions = build_actions(home_scan())
    titles = [a.title for a in actions]
    update = next(a for a in actions if a.kind == "update")
    assert len(update.findings) == 3  # 1 CVE + 2 de algoritmos SSH: uma atualização resolve todos
    assert update.title.startswith("Atualizar o firmware") and "roteador/modem" in update.title
    assert update.isp and update.letter_url("casa") == "/letter?label=casa&host=192.168.100.175"
    assert not next(a for a in actions if a.kind == "smb").isp  # PC não é equipamento do provedor
    assert len(actions) == 6 and not any("mDNS" in t for t in titles)  # informativos ficam de fora
    assert actions[0].priority >= actions[-1].priority


def test_classify_examples():
    assert classify(f("service.exposed", "x", Severity.HIGH, port=23)) == "telnet"
    assert classify(f("udp.services", "x", Severity.HIGH, key="snmp-public")) == "snmp"
    assert classify(f("upnp.igd", "x", Severity.LOW)) == "upnp"
    assert classify(f("service.exposed", "x", Severity.LOW, port=9999)) is None


def test_accepted_findings_leave_actions_and_progress_counts():
    scan = home_scan()
    telnet = next(x for x in scan.findings if x.title == "Telnet exposto")
    telnet.accepted = True
    assert not any(a.kind == "telnet" for a in build_actions(scan))
    older = home_scan()
    older.findings.append(f("tls.config", "Certificado expirado", Severity.HIGH, host=GW, port=443, key="expired"))
    p = progress([older], scan)
    assert (p.resolved, p.open, p.accepted) == (1, 7, 1) and p.percent == 12


# ───────────────────────────── painel, mapa e linha do tempo ─────────────────────────────


def test_worst_gauge_age_and_icons():
    scan = home_scan()
    assert worst(scan, ONT.address) == "high" and worst(scan, "10.9.9.9") == "ok"
    g = gauge(50)
    assert g["offset"] == pytest.approx(g["c"] / 2, rel=0.01)
    now = datetime(2026, 11, 17, 12, tzinfo=UTC)
    assert humanize_age(now - timedelta(minutes=5), now) == "há 5 min"
    assert humanize_age(now - timedelta(days=1, hours=1), now) == "ontem"
    assert device_icon("roteador/modem") == "router" and device_icon(None) == "device"


def test_network_map_layout_and_double_nat_note():
    m = network_map(home_scan())
    by_addr = {n["address"]: n for n in m["nodes"]}
    assert by_addr[None]["label"] == "Internet"
    assert by_addr[GW.address]["role"] == "gateway" and by_addr[ONT.address]["role"] == "router"
    assert by_addr[ONT.address]["sev"] == "high" and by_addr[PC.address]["role"] == "device"
    assert any("NAT duplo" in n for n in m["notes"])
    assert m["legend"]["high"] == 1


def test_map_tooltip_escapes_names_from_the_network():
    """Um aparelho pode se anunciar via mDNS com um nome malicioso. A dica não pode virar HTML ativo."""
    evil = Host(address="192.168.100.66", device_name='<img src=x onerror="alert(1)">')
    scan = finalize(ScanResult(hosts=[GW, evil], gateway=GW.address))
    node = next(n for n in network_map(scan)["nodes"] if n["address"] == evil.address)
    assert "<img" not in node["tip"] and "&lt;img" in node["tip"]


def test_timeline_labels_never_overlap(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    base = datetime(2026, 11, 17, 1, 0, tzinfo=UTC)
    # Reproduz o print: vários scans muito próximos no fim
    for i, minutes in enumerate([0, 25, 28, 69, 199, 210, 211]):
        findings = [] if i % 2 else [f("service.exposed", "Telnet", Severity.HIGH, port=23)]
        store.save(finalize(ScanResult(label="casa", started_at=base + timedelta(minutes=minutes), hosts=[GW],
                                       findings=findings)))
    t = timeline(store, "casa")
    xs = [lbl["x"] for lbl in t["labels"]]
    assert all(b - a >= 95 for a, b in zip(xs, xs[1:], strict=False)), xs
    assert t["labels"][-1]["anchor"] == "end"
    assert any(p["event"] for p in t["points"])  # scans com mudança ficam marcados
    assert "resolvido" in t["points"][1]["tip"]


# ───────────────────────────── scan ao vivo ─────────────────────────────


def test_job_progress_collects_devices():
    job = Job(id="1", params=ScanParams(targets="192.168.0.1"))
    hook = JobProgress(job)
    hook.found("192.168.0.1", name=None, gateway=True)
    hook.found("192.168.0.1", type="roteador/modem", ports=3)
    [d] = job.to_dict()["devices"]
    assert d == {"address": "192.168.0.1", "gateway": True, "type": "roteador/modem", "ports": 3, "icon": "router"}


# ───────────────────────────── páginas ─────────────────────────────


@pytest.fixture
def gui(tmp_path, monkeypatch):
    store = HistoryStore(tmp_path / "h.db")
    settings = GuiSettings(port=8770, extra_hosts={"testserver"})
    client = TestClient(create_app(store, gui=settings, runner=JobRunner(store)))
    client.get(f"/?token={settings.token}")
    monkeypatch.setattr("tbm.schedule.status", lambda platform, label: {
        "installed": True, "supported": True, "next": None, "last": None, "result": None, "state": "Ready"})
    return SimpleNamespace(client=client, store=store)


def test_first_run_goes_to_welcome(gui):
    r = gui.client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/welcome"
    page = gui.client.get("/welcome").text
    assert "Fazer o primeiro scan" in page and "Bem-vindo" in page


def test_health_findings_map_inventory_pages(gui):
    gui.store.save(home_scan())
    home = gui.client.get("/").text
    assert "Saúde da rede" in home and "O que fazer agora" in home and "Atualizar o firmware" in home
    assert "Carta para o provedor" in home and 'href="#i-logo"' in home
    status = gui.client.get("/partials/status").text
    assert "Vigia ativo" in status and "Alertas desligados" in status

    findings = gui.client.get("/findings/casa").text
    assert "O que corrigir" in findings and "resolve <b>3</b> achado(s)" in findings and "Informativos (1)" in findings

    page = gui.client.get("/map/casa").text
    assert 'class="netmap"' in page and "NAT duplo" in page and "roteador principal" in page
    assert gui.client.get("/map", follow_redirects=False).headers["location"] == "/map/casa"

    drawer = gui.client.get(f"/partials/device/casa/{ONT.address}").text
    assert "Telnet exposto" in drawer and "cc:ba:bd:99:74:01" in drawer and "O que fazer" in drawer
    assert gui.client.get("/partials/device/casa/10.9.9.9").status_code == 404

    inv = gui.client.get("/inventory/casa").text
    assert 'data-drawer="/partials/device/casa/192.168.100.175"' in inv and "#i-router" in inv

    timeline_html = gui.client.get("/partials/label/casa").text
    assert 'class="chart"' in timeline_html


def test_report_has_actions_and_print_support():
    html = render_html(home_scan())
    assert "O que fazer, por prioridade" in html and "Atualizar o firmware" in html
    assert "@media print" in html and "Imprimir / salvar PDF" in html


def test_hosts_file_aliases_are_not_device_names():
    from tbm.scout.portscan import is_alias_name

    assert is_alias_name("host.docker.internal") and is_alias_name("gateway.docker.internal.")
    assert is_alias_name("localhost") and not is_alias_name("Eduardo-PC.lan")


def test_tray_status_icon_colors():
    pytest.importorskip("PIL")
    from tbm.desktop.icon import make_status_icon

    red = make_status_icon("F", 64).getpixel((56, 56))
    green = make_status_icon("A", 64).getpixel((56, 56))
    assert red[0] > red[1] and green[1] > green[0]
    plain = make_status_icon(None, 64)
    assert plain.size == (64, 64)
