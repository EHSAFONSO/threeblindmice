"""Protocolos implementados à mão: DNS, SNMP, SSH KEXINIT, SMB, UDP e ARP."""

import asyncio
import struct
from pathlib import Path

import pytest

from tbm.scout import wire
from tbm.scout.arp import OUIDatabase, is_randomized, parse_arp_output
from tbm.scout.banner import grab_service
from tbm.scout.udp import UDP_PROBES, probe_udp
from tbm.sniffer.smb_checks import (
    parse_smb1_response,
    parse_smb2_response,
    smb1_negotiate_request,
    smb2_negotiate_request,
)
from tbm.sniffer.ssh_checks import (
    analyze_kexinit,
    build_kexinit_payload,
    fetch_kexinit,
    parse_kexinit,
    terrapin_vulnerable,
)

# ───────────────────────────── DNS ─────────────────────────────


def _dns_response(query: bytes, answers: list[tuple[int, bytes]], ra: bool = True) -> bytes:
    txid = query[:2]
    flags = 0x8180 if ra else 0x8100
    header = txid + struct.pack("!HHHHH", flags, 1, len(answers), 0, 0)
    question = query[12:]
    body = b""
    for rtype, rdata in answers:
        body += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 60, len(rdata)) + rdata
    return header + question + body


def test_dns_roundtrip_with_compression():
    q = wire.build_query("example.com", wire.TYPE_A, txid=0x1234)
    assert q[:2] == b"\x12\x34" and q[2:4] == b"\x01\x00"  # RD ligado
    resp = wire.parse_response(_dns_response(q, [(wire.TYPE_A, bytes([93, 184, 216, 34]))]))
    assert resp.txid == 0x1234 and resp.recursion_available and resp.answers[0].name == "example.com"


def test_dns_ptr_targets():
    q = wire.build_query("_services._dns-sd._udp.local", wire.TYPE_PTR, recursion=False)
    resp = wire.parse_response(_dns_response(q, [(wire.TYPE_PTR, wire.encode_name("_airplay._tcp.local"))]))
    assert resp.ptr_targets() == ["_airplay._tcp.local"]


def test_dns_compression_loop_rejected():
    evil = b"\x00" * 12 + b"\xc0\x0c"
    with pytest.raises(ValueError):
        wire.decode_name(evil, 12)


# ───────────────────────────── SNMP / BER ─────────────────────────────


def test_ber_oid_multibyte():
    assert wire.ber_oid("1.3.6.1.4.1.311") == bytes([0x06, 0x07, 0x2B, 6, 1, 4, 1, 0x82, 0x37])


def test_snmp_request_and_response():
    req = wire.snmp_get("public")
    assert req[0] == 0x30 and b"public" in req
    oid = wire.ber_oid(wire.SYS_DESCR_OID)
    varbind = wire.tlv(0x30, oid + wire.tlv(0x04, b"Linux router 5.10"))
    pdu = wire.tlv(0xA2, wire.ber_int(1) + wire.ber_int(0) + wire.ber_int(0) + wire.tlv(0x30, varbind))
    resp = wire.tlv(0x30, wire.ber_int(0) + wire.tlv(0x04, b"public") + pdu)
    assert wire.snmp_response_value(resp) == "Linux router 5.10"


# ───────────────────────────── UDP ao vivo ─────────────────────────────


class _FakeDNS(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(_dns_response(data, [(wire.TYPE_A, b"\x01\x02\x03\x04")]), addr)


async def test_udp_probe_against_fake_dns(monkeypatch):
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(_FakeDNS, local_addr=("127.0.0.1", 0))
    port = transport.get_extra_info("sockname")[1]
    monkeypatch.setitem(UDP_PROBES, port, UDP_PROBES[53].__class__(
        port, "dns", UDP_PROBES[53].payload, UDP_PROBES[53].parse))
    try:
        svc = await probe_udp("127.0.0.1", port, timeout=1.0)
    finally:
        transport.close()
    assert svc is not None and svc.transport == "udp" and svc.extra["recursion"] == "yes"


async def test_udp_silence_is_none():
    assert await probe_udp("127.0.0.1", 9, timeout=0.3, retries=0) is None  # porta sem sonda
    # porta com sonda mas ninguém escutando
    assert await probe_udp("127.0.0.1", 161, timeout=0.3, retries=0) is None


# ───────────────────────────── SSH ─────────────────────────────

OLD_ALGOS = {
    "kex": ["diffie-hellman-group1-sha1", "curve25519-sha256"],
    "hostkey": ["ssh-rsa", "ssh-ed25519"],
    "enc_c2s": ["aes128-cbc", "chacha20-poly1305@openssh.com"],
    "enc_s2c": ["aes128-cbc", "chacha20-poly1305@openssh.com"],
    "mac_c2s": ["hmac-sha1", "hmac-sha2-256-etm@openssh.com"],
    "mac_s2c": ["hmac-sha1", "hmac-sha2-256-etm@openssh.com"],
}
MODERN_ALGOS = {
    "kex": ["curve25519-sha256", "kex-strict-s-v00@openssh.com"],
    "hostkey": ["ssh-ed25519", "rsa-sha2-512"],
    "enc_c2s": ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
    "enc_s2c": ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
    "mac_c2s": ["hmac-sha2-256-etm@openssh.com"],
    "mac_s2c": ["hmac-sha2-256-etm@openssh.com"],
}


def test_kexinit_roundtrip():
    assert parse_kexinit(build_kexinit_payload(OLD_ALGOS))["kex"] == OLD_ALGOS["kex"]


def test_ssh_weak_algorithms_and_terrapin():
    keys = {f.key for f in analyze_kexinit("10.0.0.5", 22, OLD_ALGOS)}
    assert keys == {"kex", "hostkey", "ciphers", "macs", "terrapin"}
    assert analyze_kexinit("10.0.0.5", 22, MODERN_ALGOS) == []
    assert not terrapin_vulnerable(MODERN_ALGOS)  # strict kex mitiga


@pytest.fixture
async def fake_sshd():
    payload = build_kexinit_payload(OLD_ALGOS)
    padding = 4
    packet_len = 1 + len(payload) + padding
    packet = struct.pack("!IB", packet_len, padding) + payload + b"\x00" * padding

    async def handler(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH_7.4\r\n")
        await writer.drain()
        await reader.readline()
        writer.write(packet)
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    yield server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()


async def test_fetch_kexinit_live(fake_sshd):
    banner, algos = await fetch_kexinit("127.0.0.1", fake_sshd, timeout=2)
    assert banner == "SSH-2.0-OpenSSH_7.4"
    assert "aes128-cbc" in algos["enc_s2c"]


# ───────────────────────────── SMB ─────────────────────────────


def test_smb_requests_are_well_formed():
    r1 = smb1_negotiate_request()
    assert r1[4:8] == b"\xffSMB" and int.from_bytes(r1[1:4], "big") == len(r1) - 4
    r2 = smb2_negotiate_request()
    assert r2[4:8] == b"\xfeSMB" and struct.unpack("<H", r2[4 + 64: 4 + 66])[0] == 36


def _smb2_response(mode: int, dialect: int = 0x0311) -> bytes:
    header = b"\xfeSMB" + struct.pack("<HHI", 64, 0, 0) + b"\x00" * 52
    return header + struct.pack("<HHH", 65, mode, dialect) + b"\x00" * 58


def test_smb2_signing_parse():
    info = parse_smb2_response(_smb2_response(mode=0x01))
    assert info.dialect == "3.1.1" and info.signing_enabled and not info.signing_required
    assert parse_smb2_response(_smb2_response(mode=0x03)).signing_required


def test_smb1_parse():
    ok = b"\xffSMB\x72" + b"\x00" * 27 + b"\x11" + struct.pack("<H", 0) + b"\x00" * 10
    refused = b"\xffSMB\x72" + b"\x00" * 27 + b"\x01" + struct.pack("<H", 0xFFFF)
    assert parse_smb1_response(ok) is True
    assert parse_smb1_response(refused) is False
    assert parse_smb1_response(b"\xfeSMB" + b"\x00" * 80) is False


# ───────────────────────────── banner rápido ─────────────────────────────


async def test_binary_ports_skip_probing():
    loop = asyncio.get_running_loop()
    start = loop.time()
    svc = await grab_service("127.0.0.1", 445, hostname=None, timeout=3, legacy_tls=True)
    assert svc.name == "smb" and loop.time() - start < 0.1


# ───────────────────────────── ARP / OUI ─────────────────────────────

WINDOWS_ARP = """
Interface: 192.168.0.10 --- 0x7
  Endereço IP           Endereço físico       Tipo
  192.168.0.1           a4-2b-b0-11-22-33     dinâmico
  192.168.0.25          3a-11-22-33-44-55     dinâmico
  192.168.0.255         ff-ff-ff-ff-ff-ff     estático
  224.0.0.22            01-00-5e-00-00-16     estático
"""
LINUX_ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.0.1      0x1         0x2         a4:2b:b0:11:22:33     *        eth0
"""


def test_parse_arp_outputs():
    table = parse_arp_output(WINDOWS_ARP)
    assert table == {"192.168.0.1": "a4:2b:b0:11:22:33", "192.168.0.25": "3a:11:22:33:44:55"}
    assert parse_arp_output(LINUX_ARP) == {"192.168.0.1": "a4:2b:b0:11:22:33"}


def test_oui_lookup(tmp_path: Path):
    csv = tmp_path / "oui.csv"
    csv.write_text("Registry,Assignment,Organization Name,Organization Address\n"
                   "MA-L,A42BB0,TP-LINK TECHNOLOGIES CO.,LTD.,China\n", encoding="utf-8")
    db = OUIDatabase(csv)
    assert db.lookup("a4:2b:b0:11:22:33").startswith("TP-LINK")
    assert is_randomized("3a:11:22:33:44:55")
    assert db.lookup("3a:11:22:33:44:55") == "MAC aleatório (privacidade)"
    assert db.lookup("00:11:22:33:44:55") is None
