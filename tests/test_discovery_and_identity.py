"""Descoberta, classificação, identidade no diff, aceitação de risco e contexto."""

import struct
from datetime import UTC, date, datetime

from tbm.models import Finding, Host, ScanResult, Service, Severity
from tbm.pipeline import finalize
from tbm.scout import wire
from tbm.scout.classify import classify
from tbm.scout.discovery import (
    Announcement,
    absorb_mdns,
    absorb_ssdp,
    parse_default_gateway,
    ping_command,
    ping_replied,
)
from tbm.scout.engine import ScoutOptions
from tbm.sniffer.context import apply_context
from tbm.squeak import HistoryStore, diff_scans
from tbm.squeak.acceptance import apply_acceptances
from tbm.squeak.scoring import score_findings

# ───────────────────────────── descoberta ─────────────────────────────


def test_ping_reply_detection_ignores_unreachable():
    assert ping_replied(b"Resposta de 192.168.100.1: bytes=32 tempo=2ms TTL=64")
    assert ping_replied(b"64 bytes from 10.0.0.1: icmp_seq=1 ttl=63 time=1.2 ms")
    # Windows devolve exit 0 nesse caso: o TTL é o que diferencia
    assert not ping_replied(b"Resposta de 192.168.100.1: Host de destino inacessivel.")
    assert ping_command("10.0.0.1", 1.0)[-1] == "10.0.0.1"


def test_default_gateway_parsers():
    win = ("Rotas ativas:\n Endereço de rede  Máscara  Gateway  Interface  Custo\n"
           "          0.0.0.0          0.0.0.0    192.168.100.1  192.168.100.183     35\n")
    assert parse_default_gateway(win, "win32") == "192.168.100.1"
    linux = ("Iface\tDestination\tGateway \tFlags\n"
             "eth0\t00000000\t0164A8C0\t0003\n")
    assert parse_default_gateway(linux, "linux") == "192.168.100.1"
    assert parse_default_gateway("   gateway: 10.0.0.1\n", "bsd") == "10.0.0.1"


def _mdns_response(ptrs: list[tuple[str, str]], a_records: dict[str, str]) -> bytes:
    body = b""
    for name, target in ptrs:
        rdata = wire.encode_name(target)
        body += wire.encode_name(name) + struct.pack("!HHIH", wire.TYPE_PTR, 1, 120, len(rdata)) + rdata
    extra = b""
    for name, ip in a_records.items():
        extra += wire.encode_name(name) + struct.pack("!HHIH", wire.TYPE_A, 1, 120, 4) + bytes(
            int(x) for x in ip.split("."))
    header = struct.pack("!HHHHHH", 0, 0x8400, 0, len(ptrs), 0, len(a_records))
    return header + body + extra


def test_mdns_announcement_parsing():
    found: dict[str, Announcement] = {}
    data = _mdns_response(
        [("_googlecast._tcp.local", "Sala de Estar._googlecast._tcp.local"),
         ("_services._dns-sd._udp.local", "_spotify-connect._tcp.local")],
        {"Chromecast-abc.local": "192.168.100.50"},
    )
    absorb_mdns(found, data, "192.168.100.50")
    ann = found["192.168.100.50"]
    assert ann.services == {"_googlecast._tcp", "_spotify-connect._tcp"}
    assert ann.best_name == "Sala de Estar"  # nome da instância vence o hostname
    assert "Chromecast-abc.local" in ann.names


def test_ssdp_announcement_parsing():
    found: dict[str, Announcement] = {}
    absorb_ssdp(found, b"HTTP/1.1 200 OK\r\nSERVER: Linux UPnP/1.0 Roku/9.4\r\n"
                       b"LOCATION: http://192.168.100.60:8060/\r\nST: roku:ecp\r\n\r\n", "192.168.100.60")
    ann = found["192.168.100.60"]
    assert "Roku" in ann.ssdp_server and ann.ssdp_location.endswith(":8060/")


def test_multi_question_query_sets_qu_bit():
    q = wire.build_multi_query(["_a._tcp.local", "_b._tcp.local"], wire.TYPE_PTR, unicast_response=True)
    assert struct.unpack("!H", q[4:6])[0] == 2
    assert q[-2:] == b"\x80\x01"  # classe IN com bit QU


# ───────────────────────────── classificação ─────────────────────────────


def test_classify_examples():
    router = Host(address="192.168.100.175",
                  services=[Service(port=7547), Service(port=22, banner="SSH-2.0-dropbear_2020.80")])
    assert classify(router) == "roteador/modem"
    pc = Host(address="192.168.100.183", services=[Service(port=135), Service(port=445)])
    assert classify(pc) == "computador Windows"
    tv = Host(address="10.0.0.5", discovery={"mdns_services": "_googlecast._tcp"})
    assert classify(tv) == "TV/Chromecast"
    phone = Host(address="10.0.0.6", device_name="iPhone-de-Ana")
    assert classify(phone) == "celular Apple"
    assert classify(Host(address="10.0.0.7")) is None
    assert classify(Host(address="10.0.0.1"), is_gateway=True) == "roteador/modem"


def test_identity_prefers_mac_then_name():
    assert Host(address="1.1.1.1", mac="aa:bb:cc:dd:ee:ff", device_name="x").identity == "mac:aa:bb:cc:dd:ee:ff"
    assert Host(address="1.1.1.1", device_name="TV-Sala").identity == "name:tv-sala"
    assert Host(address="1.1.1.1").identity == "ip:1.1.1.1"


def test_gentle_options():
    o = ScoutOptions.gentle([80], udp=True)
    assert o.concurrency == 16 and o.rate == 50.0 and o.udp


# ───────────────────────────── diff por identidade ─────────────────────────────


def _phone(ip: str) -> Host:
    return Host(address=ip, mac="3a:11:22:33:44:55", services=[Service(port=62078)])


def test_ip_change_is_not_new_device_and_keeps_findings():
    f_old = Finding(check_id="c", title="t", severity=Severity.LOW, host="10.0.0.20",
                    device="mac:3a:11:22:33:44:55", key="k")
    f_new = f_old.model_copy(update={"host": "10.0.0.31"})
    assert f_old.fingerprint == f_new.fingerprint  # o IP não entra no fingerprint
    old = finalize(ScanResult(hosts=[_phone("10.0.0.20")], findings=[f_old], ports_scanned=[62078]))
    new = finalize(ScanResult(hosts=[_phone("10.0.0.31")], findings=[f_new], ports_scanned=[62078]))
    d = diff_scans(old, new)
    assert not d.new_hosts and not d.gone_hosts and not d.new_findings and not d.resolved_findings
    [(host, before, after)] = d.ip_changes
    assert (before, after) == ("10.0.0.20", "10.0.0.31") and host.mac == "3a:11:22:33:44:55"


def test_upgrade_from_ip_fingerprints_does_not_flood_alerts():
    """Scan antigo (sem `device`) x scan novo (com `device`): nada deve parecer novo."""
    legacy = Finding(check_id="service.exposed", title="Telnet", severity=Severity.HIGH,
                     host="192.168.100.175", port=23)
    upgraded = legacy.model_copy(update={"device": "mac:cc:ba:bd:99:74:01"})
    assert legacy.fingerprint != upgraded.fingerprint
    d = diff_scans(ScanResult(findings=[legacy]), ScanResult(findings=[upgraded]))
    assert not d.new_findings and not d.resolved_findings and len(d.persisting_findings) == 1


# ───────────────────────────── AJP x Google Cast ─────────────────────────────


async def _server(reply: bytes | None):
    import asyncio

    async def handler(reader, writer):
        await reader.read(5)
        if reply is not None:
            writer.write(reply)
            await writer.drain()
        await asyncio.sleep(0.3)
        writer.close()

    return await asyncio.start_server(handler, "127.0.0.1", 0)


async def test_ajp_confirmed_only_by_cpong():
    from tbm.sniffer.service_checks import AJP_CPONG, speaks_ajp

    tomcat = await _server(AJP_CPONG)
    cast = await _server(None)  # Google Cast: fala TLS, ignora o CPing
    try:
        assert await speaks_ajp("127.0.0.1", tomcat.sockets[0].getsockname()[1], timeout=1)
        assert not await speaks_ajp("127.0.0.1", cast.sockets[0].getsockname()[1], timeout=1)
    finally:
        tomcat.close()
        cast.close()


def test_classify_matter_google_device():
    nest = Host(address="192.168.100.182", services=[Service(port=8009)],
                discovery={"mdns_services": "_matterd._udp"})
    assert classify(nest) == "casa inteligente (Matter)"


# ───────────────────────────── aceitação de risco ─────────────────────────────


def test_accept_removes_from_score_and_expires(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    telnet = Finding(check_id="service.exposed", title="Telnet exposto", severity=Severity.HIGH,
                     host="192.168.100.175", port=23)
    r = ScanResult(findings=[telnet])
    before = score_findings(r.findings)

    store.accept(telnet.fingerprint, "ONT da operadora", until="2099-01-01")
    assert apply_acceptances(r, store.acceptances()) == 1
    assert telnet.accepted and "ONT da operadora" in telnet.acceptance
    assert score_findings(r.findings) == 100 > before

    store.accept(telnet.fingerprint, "ONT da operadora", until="2020-01-01")
    apply_acceptances(r, store.acceptances(), today=date(2026, 11, 17))
    assert not telnet.accepted and "expirou" in telnet.acceptance
    assert store.unaccept(telnet.fingerprint[:8]) == 1 and not store.acceptances()


# ───────────────────────────── contexto ─────────────────────────────


def test_context_policy_lan_vs_internet():
    smb_lan = Finding(check_id="service.exposed", title="SMB", severity=Severity.MEDIUM, host="192.168.0.5", port=445)
    smb_wan = smb_lan.model_copy(update={"host": "8.8.8.8"})
    other = Finding(check_id="tls.config", title="x", severity=Severity.LOW, host="8.8.8.8", port=443)
    apply_context([smb_lan, smb_wan, other])
    assert smb_lan.severity is Severity.MEDIUM and smb_wan.severity is Severity.CRITICAL
    assert "internet" in smb_wan.description and other.severity is Severity.LOW
    apply_context([smb_wan])  # idempotente: não duplica a nota
    assert smb_wan.description.count("Severidade ajustada") == 1


def test_inventory_tracks_first_seen_and_ips():
    from tbm.dashboard.app import build_inventory

    s1 = ScanResult(started_at=datetime(2026, 11, 1, tzinfo=UTC), hosts=[_phone("10.0.0.20")])
    s2 = ScanResult(started_at=datetime(2026, 11, 2, tzinfo=UTC), hosts=[_phone("10.0.0.31")])
    [dev] = build_inventory([s1, s2])
    assert dev["ips"] == ["10.0.0.20", "10.0.0.31"] and dev["times_seen"] == 2
    assert dev["first_seen"] == "01/11/2026"
