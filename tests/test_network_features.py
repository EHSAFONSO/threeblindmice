"""Nomes (NetBIOS/LLMNR), IPv6, Wi-Fi, DNS, visão externa, aparelhos conhecidos, guias, resumo e versão.

Tudo offline: pacotes montados à mão, comandos do sistema como texto e as APIs
externas (Cloudflare, Shodan, GitHub) simuladas com httpx.MockTransport.
"""

import asyncio
import json
import struct
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from tbm import update
from tbm.models import Finding, Host, ScanResult, Service, Severity
from tbm.pipeline import finalize
from tbm.scout import wire
from tbm.scout.ipv6 import is_global_v6, parse_neighbors
from tbm.scout.names import nbstat_query, parse_llmnr_ptr, parse_nbstat, reverse_name
from tbm.sniffer import network_checks as nc
from tbm.sniffer.base import CheckContext, SnifferOptions
from tbm.squeak import HistoryStore, diff_scans, summary
from tbm.squeak.actions import build_actions, classify
from tbm.squeak.guides import detect_brand, guide_for
from tbm.squeak.notify import build_message

# ───────────────────────────── NetBIOS / LLMNR ─────────────────────────────


def nbstat_response(names: list[tuple[str, int, int]]) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x8400, 0, 1, 0, 0)
    name = bytes([32]) + b"CK" + b"AA" * 15 + b"\x00"
    entries = b"".join(n.ljust(15).encode()[:15] + bytes([suffix]) + struct.pack("!H", flags)
                       for n, suffix, flags in names)
    rdata = bytes([len(names)]) + entries + b"\x00" * 46
    return header + name + struct.pack("!HHIH", 0x21, 1, 0, len(rdata)) + rdata


def test_nbstat_query_and_parse():
    q = nbstat_query(txid=7)
    assert q[:2] == b"\x00\x07" and q[12] == 32 and q.endswith(b"\x00\x00\x21\x00\x01")
    data = nbstat_response([("WORKGROUP", 0x00, 0x8400), ("DESKTOP-ABC", 0x00, 0x0400), ("DESKTOP-ABC", 0x20, 0x0400)])
    assert parse_nbstat(data) == "DESKTOP-ABC"  # o nome de grupo (flag 0x8000) é ignorado


@pytest.mark.parametrize("junk", [b"", b"\x00" * 11, b"\xff" * 64, nbstat_response([])[:40]])
def test_nbstat_parser_survives_garbage(junk):
    assert parse_nbstat(junk) is None


def test_llmnr_ptr():
    assert reverse_name("192.168.0.10") == "10.0.168.192.in-addr.arpa"
    q = wire.build_query(reverse_name("192.168.0.10"), wire.TYPE_PTR, recursion=False, txid=1)
    qname_end = q.index(b"\x00", 12) + 5
    target = wire.encode_name("notebook-ana.local")
    answer = b"\xc0\x0c" + struct.pack("!HHIH", wire.TYPE_PTR, 1, 30, len(target)) + target
    resp = struct.pack("!HHHHHH", 1, 0x8000, 1, 1, 0, 0) + q[12:qname_end] + answer
    assert parse_llmnr_ptr(resp) == "notebook-ana.local"
    assert parse_llmnr_ptr(b"garbage") is None


# ───────────────────────────── IPv6 ─────────────────────────────


NETSH = """Interface 19: Wi-Fi

Endereço na Internet                              Endereço Físico   Tipo
--------------------------------------------  -----------------  -----------
2804:1e68:c60b:d788::7                        aa-bb-cc-00-11-22  Acessível
2804:1e68:c60b:14a:3874:4692:33d9:1f40        00-00-00-00-00-00  Inalcançável
fe80::1                                       fc-bc-d1-72-57-48  Acessível (Roteador)
ff02::1                                       33-33-00-00-00-01  Permanente
"""
IP_NEIGH = ("2001:db8::5 dev wlan0 lladdr de:ad:be:ef:00:01 REACHABLE\n"
            "2a00:1450:4001::1 dev wlan0 lladdr de:ad:be:ef:00:02 STALE\n")


def test_neighbor_tables():
    # sem MAC zerado, link-local ou multicast
    assert parse_neighbors(NETSH) == {"aa:bb:cc:00:11:22": {"2804:1e68:c60b:d788::7"}}
    assert parse_neighbors(IP_NEIGH) == {"de:ad:be:ef:00:02": {"2a00:1450:4001::1"}}  # 2001:db8:: é documentação
    assert is_global_v6("2804:1e68::1") and not is_global_v6("fe80::1") and not is_global_v6("fd00::1")


# ───────────────────────────── Wi-Fi ─────────────────────────────


NETSH_WLAN_PT = """
    Nome                   : Wi-Fi
    Estado                 : conectado
    SSID                   : CasaNet
    Autenticação           : WPA2-Personal
    Codificação            : CCMP
"""
NETSH_WLAN_EN = "    State : connected\n    SSID : Cafe\n    Authentication : Open\n    Cipher : None\n"


def test_wifi_parsers_and_verdicts():
    pt = nc.parse_netsh_wlan(NETSH_WLAN_PT)
    assert (pt.ssid, pt.auth, pt.cipher) == ("CasaNet", "WPA2-Personal", "CCMP")
    assert nc.classify_wifi(pt)[0] is Severity.INFO
    assert nc.classify_wifi(nc.parse_netsh_wlan(NETSH_WLAN_EN))[1] == "open"
    assert nc.parse_netsh_wlan("    Estado : desconectado\n    Autenticação : WPA2") is None
    assert nc.parse_nmcli("no:Vizinho:WPA2\nyes:Casa\\:5G:WEP\n").auth == "WEP"
    assert nc.classify_wifi(nc.WifiInfo("x", "WPA-Personal", "TKIP"))[1] == "wpa1"
    assert nc.classify_wifi(nc.WifiInfo("x", "WPA3-Personal", "GCMP")) is None
    airport = "Current Network Information:\n          Casa:\n            Security: WPA2 Personal\n\n"
    assert nc.parse_airport(airport).auth == "WPA2 Personal"


# ───────────────────────────── checks de rede ─────────────────────────────

GW = Host(address="192.168.0.1", mac="fc:bc:d1:72:57:48", device_type="roteador/modem", vendor="ZTE Corporation",
          services=[Service(port=23)])


def ctx(transport=None, **scan_kw) -> CheckContext:
    scan = ScanResult(gateway=GW.address, hosts=[GW], **scan_kw)
    http = httpx.AsyncClient(transport=transport or httpx.MockTransport(lambda r: httpx.Response(404)))
    return CheckContext(scan=scan, http=http, options=SnifferOptions(external=True))


def test_external_checks_are_opt_in():
    assert not nc.ExternalViewCheck().enabled(SnifferOptions())
    assert not nc.DNSHijackCheck().enabled(SnifferOptions())
    assert nc.ExternalViewCheck().enabled(SnifferOptions(external=True))
    assert nc.WifiCheck().enabled(SnifferOptions())


def test_network_checks_skip_non_lan_scans():
    c = ctx()
    c.scan.gateway = None
    assert asyncio.run(nc.ExternalViewCheck().run(c)) == []
    assert asyncio.run(nc.IPv6ExposureCheck().run(c)) == []


def test_external_view_reports_internet_ports():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "1.1.1.1":
            return httpx.Response(200, text="fl=1\nip=203.0.113.9\nts=1\n".replace("203.0.113.9", "200.100.50.25"))
        assert request.url.host == "internetdb.shodan.io" and request.url.path == "/200.100.50.25"
        return httpx.Response(200, json={"ports": [23, 443], "vulns": ["CVE-2023-1389"], "cpes": [], "hostnames": []})

    findings = asyncio.run(nc.ExternalViewCheck().run(ctx(httpx.MockTransport(handler))))
    sev = {f.key: f.severity for f in findings}
    assert sev == {"wan:23": Severity.HIGH, "wan:443": Severity.MEDIUM, "vulns": Severity.HIGH}
    assert all(f.host == GW.address for f in findings)


def test_external_view_nothing_seen():
    def handler(request):
        return httpx.Response(200, text="ip=200.100.50.25\n") if request.url.host == "1.1.1.1" else httpx.Response(404)

    assert asyncio.run(nc.ExternalViewCheck().run(ctx(httpx.MockTransport(handler)))) == []


def test_dns_hijack_detected(monkeypatch):
    async def fake_router(server, name, timeout=2.0):
        if name.startswith("tbm-"):
            return 0, {"198.51.100.7"}  # NXDOMAIN redirecionado
        return 0, {"203.0.113.66"}  # mentira

    async def fake_system(name):
        return nc.STABLE_NAMES[name]

    async def fake_doh(http, name):
        return None  # usa os valores conhecidos

    monkeypatch.setattr(nc, "ask_dns", fake_router)
    monkeypatch.setattr(nc, "ask_system", fake_system)
    monkeypatch.setattr(nc, "ask_doh", fake_doh)
    findings = {f.key: f for f in asyncio.run(nc.DNSHijackCheck().run(ctx()))}
    assert findings["hijack"].severity is Severity.CRITICAL and "roteador: dns.google" in findings["hijack"].evidence
    assert "sistema" not in findings["hijack"].evidence
    assert findings["nxdomain"].severity is Severity.LOW


def test_ipv6_exposure():
    pc = Host(address="192.168.0.20", mac="aa:aa:aa:aa:aa:aa", services=[Service(port=445), Service(port=8080)],
              ipv6=["2804:1e68::20"], ipv6_services=[445, 8080])
    c = ctx()
    c.scan.hosts.append(pc)
    findings = {f.key: f for f in asyncio.run(nc.IPv6ExposureCheck().run(c))}
    assert findings["services"].severity is Severity.HIGH and findings["services"].host == pc.address
    assert findings["prefix"].severity is Severity.INFO


def test_network_findings_group_into_actions():
    scan = finalize(ScanResult(gateway=GW.address, hosts=[GW], findings=[
        Finding(check_id="network.dns", title="DNS falso", severity=Severity.CRITICAL, host=GW.address, key="hijack"),
        Finding(check_id="network.wifi", title="Wi-Fi WEP", severity=Severity.HIGH, host="wifi", key="wep"),
    ]))
    actions = {a.kind: a for a in build_actions(scan)}
    assert actions["dns"].isp and actions["dns"].letter_url("casa")
    assert actions["wifi"].title == "Reforçar a segurança da rede Wi-Fi"
    assert classify(Finding(check_id="network.external", title="x", severity=Severity.LOW, host="h")) == "exposure"


# ───────────────────────────── aparelhos conhecidos ─────────────────────────────


def test_known_devices_names_trust_and_alerts(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    tv = Host(address="192.168.0.50", mac="aa:bb:cc:00:11:22", device_name="Chromecast")
    old = finalize(ScanResult(label="casa", hosts=[GW]))
    store.save(old)
    new = finalize(ScanResult(label="casa", hosts=[GW, tv]))
    store.save(new)
    store.set_device(tv.identity, alias="TV da sala")
    loaded = store.latest("casa")
    tv_loaded = loaded.host(tv.address)
    assert tv_loaded.name == "TV da sala" and not tv_loaded.trusted  # alias sem mudar a aprovação
    store.set_device(tv.identity, trusted=True)
    assert store.latest("casa").host(tv.address).trusted and store.devices()[tv.identity]["alias"] == "TV da sala"
    store.set_device(tv.identity, alias="")
    assert store.latest("casa").host(tv.address).name == "Chromecast"

    d = diff_scans(old, new)
    d.novel_hosts = [tv]
    assert "DESCONHECIDO" in build_message(new, d, [])
    tv.trusted = True
    assert "DESCONHECIDO" not in build_message(new, d, []) and "aprovados" in build_message(new, d, [])


# ───────────────────────────── guias ─────────────────────────────


def test_brand_detection_and_guides():
    assert detect_brand(GW).name == "ZTE"
    huawei = Host(address="192.168.100.1", device_type="roteador/modem", discovery={"http_title": "HG8245H"})
    assert detect_brand(huawei).name == "Huawei"
    g = guide_for("telnet", GW)
    assert g.brand == "ZTE" and any("Controle de serviço" in s for s in g.steps) and "http://192.168.0.1" in g.steps[0]
    unknown = Host(address="10.0.0.1", device_type="roteador/modem")
    assert guide_for("upnp", unknown).brand is None
    assert guide_for("smb", Host(address="10.0.0.9", device_type="computador Windows")) is None
    assert guide_for("wifi", None, gateway="10.0.0.1").steps[0].startswith("Abra http://10.0.0.1")


# ───────────────────────────── resumo semanal ─────────────────────────────


def test_weekly_summary(tmp_path, monkeypatch):
    monkeypatch.setenv("TBM_HOME", str(tmp_path))
    store = HistoryStore(tmp_path / "h.db")
    now = datetime(2026, 11, 18, 12, tzinfo=UTC)
    telnet = Finding(check_id="service.exposed", title="Telnet exposto", severity=Severity.HIGH, host=GW.address,
                     port=23, device=GW.identity)
    store.save(finalize(ScanResult(label="casa", started_at=now - timedelta(days=8), hosts=[GW], findings=[telnet])))
    store.save(finalize(ScanResult(label="casa", started_at=now - timedelta(hours=1), hosts=[GW])))
    text = summary.build_summary(store, "casa", now=now)
    assert "Resumo da semana" in text and "1 problema(s) resolvido(s)" in text and "Nada pendente" in text
    assert summary.due(store, "casa", now)
    summary.mark_sent(store, "casa", now)
    assert not summary.due(store, "casa", now + timedelta(days=6))
    assert summary.due(store, "casa", now + timedelta(days=7))
    summary.set_enabled(False)
    assert not summary.due(store, "casa", now + timedelta(days=30))


# ───────────────────────────── aviso de versão ─────────────────────────────


def gh_release(tag="v9.9.0", url="https://github.com/EHSAFONSO/threeblindmice/releases/tag/v9.9.0"):
    name = f"threeblindmice_{tag[1:]}_x64-setup.exe"
    base = "https://github.com/EHSAFONSO/threeblindmice/releases/download/" + tag
    return {"tag_name": tag, "html_url": url, "published_at": "2026-11-20T00:00:00Z", "assets": [
        {"name": name, "browser_download_url": f"{base}/{name}"},
        {"name": name + ".sha256", "browser_download_url": f"{base}/{name}.sha256"}]}


def test_update_check(tmp_path, monkeypatch):
    monkeypatch.setenv("TBM_HOME", str(tmp_path))
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if request.url.path.endswith("/releases/latest"):
            return httpx.Response(200, json=gh_release())
        return httpx.Response(200, text="ab" * 32 + "  threeblindmice_9.9.0_x64-setup.exe\n")

    t = httpx.MockTransport(handler)
    r = asyncio.run(update.check(transport=t))
    assert r.version == "9.9.0" and r.sha256 == "ab" * 32 and "attestation verify" in r.verify_command
    assert asyncio.run(update.check(transport=t)).version == "9.9.0"
    assert len(calls) == 2  # segunda chamada veio do cache diário
    update.set_enabled(False)
    assert asyncio.run(update.check(transport=t)) is None
    assert json.loads((tmp_path / "update.json").read_text())["release"]["version"] == "9.9.0"


def test_update_ignores_foreign_links_and_old_versions():
    assert update.parse_release(gh_release(url="https://evil.example/x")) is None
    assert not update.newer("0.1.0") and update.newer("99.0.0") and update.parse_version("v1.2.3") == (1, 2, 3)
