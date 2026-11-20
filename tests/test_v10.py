"""v0.10: modelo do aparelho, NAT, Wi-Fi falso/DHCP intruso, IoT, novos alertas, métricas e demo."""

from datetime import datetime

import httpx
import pytest

from tbm import config
from tbm.models import Host, ScanResult, Service, Severity
from tbm.scout.model import firmware_from_text, model_label, parse_description
from tbm.scout.wifi import WifiNetwork, build_discover, evil_twin, parse_netsh_networks, server_ids
from tbm.squeak import HistoryStore
from tbm.squeak.notify import in_quiet_hours, text_delivery

# ───────────────────────────── modelo do aparelho ─────────────────────────────

UPNP_XML = """<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<friendlyName>Meu Roteador</friendlyName><manufacturer>Huawei</manufacturer>
<modelName>EG8145V5</modelName><modelNumber>V5</modelNumber>
<device><friendlyName>WANDevice</friendlyName><manufacturer>Outra</manufacturer></device>
</device></root>"""


def test_parse_upnp_description_and_label():
    d = parse_description(UPNP_XML)
    assert d["upnp_manufacturer"] == "Huawei" and d["upnp_model"] == "EG8145V5"
    assert d.get("upnp_manufacturer") != "Outra"  # subdispositivo ignorado
    h = Host(address="192.168.0.1", discovery=d)
    assert model_label(h) == "Huawei EG8145V5"
    h.discovery["firmware"] = "V5R020"
    assert "firmware V5R020" in model_label(h)
    assert parse_description("<nope") == {}


def test_firmware_from_text():
    assert firmware_from_text("RouterOS version 6.49.7") == "6.49.7"
    assert firmware_from_text("Linux firmware version V5R020C10") == "V5R020C10"
    assert firmware_from_text(None) is None


# ───────────────────────────── NAT / CGNAT ─────────────────────────────


def test_nat_findings():
    from tbm.sniffer.upnp_checks import nat_finding

    gw = Host(address="192.168.0.1", device_type="roteador/modem")
    assert nat_finding("upnp.igd", gw, "100.80.1.1").key == "cgnat"
    assert nat_finding("upnp.igd", gw, "192.168.100.1").key == "double-nat"
    assert nat_finding("upnp.igd", gw, "200.1.2.3") is None  # IP público de verdade: nada
    assert nat_finding("upnp.igd", gw, "lixo") is None


# ───────────────────────────── Wi-Fi falso e DHCP intruso ─────────────────────────────

NETSH_NETS = """
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : CasaNet
    Authentication         : WPA2-Personal
    Encryption             : CCMP
SSID 2 : CasaNet
    Authentication         : Open
    Encryption             : None
"""


def test_evil_twin_detection():
    nets = parse_netsh_networks(NETSH_NETS)
    assert WifiNetwork("CasaNet", True) in nets and WifiNetwork("CasaNet", False) in nets
    assert evil_twin("CasaNet", nets) == ["CasaNet"]  # existe uma aberta com o mesmo nome
    assert evil_twin("Outra", nets) == []
    assert evil_twin(None, nets) == []


def test_dhcp_server_counting():

    xid = b"\x11\x22\x33\x44"
    def reply(server_ip: str) -> bytes:
        header = bytearray(236)  # op..file, antes do magic cookie (offset 236)
        header[0] = 2
        header[4:8] = xid
        opts = bytes([54, 4]) + bytes(int(x) for x in server_ip.split(".")) + b"\xff"
        return bytes(header) + bytes.fromhex("63825363") + opts
    assert build_discover(b"\x00" * 6, xid)[:1] == b"\x01"
    servers = server_ids([reply("192.168.0.1"), reply("192.168.0.9"), reply("192.168.0.1")], xid)
    assert servers == {"192.168.0.1", "192.168.0.9"}
    assert server_ids([b"short"], xid) == set()


# ───────────────────────────── IoT ─────────────────────────────


def test_iot_service_inventory_and_password_hint():
    from tbm.sniffer.base import CheckContext, SnifferOptions
    from tbm.sniffer.iot_checks import IoTServicesCheck, likely_default_password

    cam = Host(address="192.168.0.55", device_type="câmera/DVR", services=[Service(port=80), Service(port=37777)])
    scan = ScanResult(gateway="192.168.0.1", hosts=[cam])
    ctx = CheckContext(scan=scan, http=httpx.AsyncClient(), options=SnifferOptions())
    import asyncio

    out = {f.key: f for f in asyncio.run(IoTServicesCheck().run(ctx))}
    assert "37777" in out and out["37777"].severity is Severity.MEDIUM
    assert likely_default_password(cam) and not likely_default_password(
        Host(address="192.168.0.20", device_type="computador Windows"))


# ───────────────────────────── alertas: novos destinos, silêncio, vencimento ─────────────────────────────


def test_new_alert_destinations():
    assert text_delivery("pushover://TOK@USR", "oi").url == "https://api.pushover.net/1/messages.json"
    assert text_delivery("pushover://TOK@USR", "oi").json["user"] == "USR"
    assert text_delivery("hass://ha.local:8123/wh1", "oi").url == "http://ha.local:8123/api/webhook/wh1"
    assert config.describe("pushover://t@u")["kind"] == "pushover"
    assert config.describe("hass://ha/wh")["kind"] == "hass"
    assert config.describe("smtp://u:p@s/a@b.com")["label"].endswith("a@b.com")
    with pytest.raises(ValueError, match="Pushover"):
        text_delivery("pushover://onlytoken", "x")


def test_quiet_hours():
    d = datetime(2026, 1, 1, 3, 0)
    assert in_quiet_hours("22:00", "07:00", d) and not in_quiet_hours("22:00", "07:00", datetime(2026, 1, 1, 12))
    assert in_quiet_hours("08:00", "18:00", datetime(2026, 1, 1, 12))
    assert not in_quiet_hours("bad", "07:00", d)


def test_acceptance_expiry(tmp_path):
    from tbm.squeak.summary import expiring_acceptances

    store = HistoryStore(tmp_path / "h.db")
    now = datetime(2026, 6, 10)
    store.accept("fp1", "modem", until="2026-06-14", title="Telnet")
    store.accept("fp2", "ok", until="2026-12-01", title="Longe")
    store.accept("fp3", "sem prazo", title="SemPrazo")
    assert expiring_acceptances(store, now) == ["Telnet"]


# ───────────────────────────── métricas e demo ─────────────────────────────


def test_metrics_has_no_private_data(tmp_path):
    from tbm.dashboard.metrics import render_metrics
    from tbm.demo import seed

    store = HistoryStore(tmp_path / "h.db")
    seed(store)
    text = render_metrics(store)
    assert 'tbm_score{label="casa"}' in text and "tbm_findings_open" in text
    assert "192.168" not in text and "aa:bb" not in text  # nada de IP/MAC


def test_demo_seed_progresses(tmp_path):
    from tbm.demo import seed

    store = HistoryStore(tmp_path / "h.db")
    seed(store)
    rows = list(reversed(store.list("casa")))
    scores = [r["score"] for r in rows]
    assert scores == sorted(scores) and scores[0] < scores[-1]  # melhora com o tempo
    assert store.latest("casa").findings  # o último ainda tem o que mostrar


# ───────────────────────────── autostart (desligado) e vigia ─────────────────────────────


def test_autostart_is_off_and_reversible(monkeypatch, tmp_path):
    import sys

    from tbm.desktop import autostart

    monkeypatch.setattr(autostart, "_autostart_desktop", lambda: tmp_path / "ts.desktop")
    if sys.platform != "win32":
        assert not autostart.is_enabled()
        autostart.enable()
        assert autostart.is_enabled() and "--hidden" in (tmp_path / "ts.desktop").read_text()
        autostart.disable()
        assert not autostart.is_enabled()
    assert autostart.supported() == (sys.platform in ("win32", "linux"))


def test_live_monitor_baseline(tmp_path):
    from tbm.desktop.monitor import LiveMonitor
    from tbm.pipeline import finalize

    store = HistoryStore(tmp_path / "h.db")
    gw = Host(address="192.168.0.1", mac="aa:aa:aa:aa:aa:aa")
    store.save(finalize(ScanResult(label="casa", hosts=[gw])))
    store.set_device("mac:bb:bb:bb:bb:bb:bb", trusted=True)
    seen = []
    mon = LiveMonitor(store, lambda t, x: seen.append((t, x)))
    base = mon._baseline()
    assert "aa:aa:aa:aa:aa:aa" in base and "bb:bb:bb:bb:bb:bb" in base


def test_remember_network(tmp_path):
    from tbm.pipeline import finalize, remember_network

    store = HistoryStore(tmp_path / "h.db")
    gw = Host(address="192.168.0.1", mac="fc:fc:fc:fc:fc:fc", device_type="roteador/modem")
    scan = finalize(ScanResult(label="escritorio", gateway="192.168.0.1", hosts=[gw]))
    remember_network(store, scan)
    assert store.meta("net:fc:fc:fc:fc:fc:fc") == "escritorio"
