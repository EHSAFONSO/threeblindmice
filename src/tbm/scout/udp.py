"""Varredura UDP baseada em sondas de protocolo.

Em UDP não existe handshake: uma porta "aberta" só se revela quando o serviço
responde a um pacote válido do seu protocolo. Por isso, em vez de varrer
portas às cegas, mandamos uma sonda específica para cada serviço que importa.
Silêncio pode ser porta fechada ou filtrada; não dá para distinguir.
"""

from __future__ import annotations

import asyncio
import re
import struct
from collections.abc import Callable
from dataclasses import dataclass

from tbm.models import Service
from tbm.scout import wire
from tbm.scout.banner import _clean_banner


class _Collector(asyncio.DatagramProtocol):
    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self.future: asyncio.Future[bytes] = loop.create_future()

    def datagram_received(self, data: bytes, addr) -> None:
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        # ICMP port unreachable vira ConnectionRefusedError em alguns SOs
        if not self.future.done():
            self.future.set_exception(exc)


async def udp_exchange(host: str, port: int, payload: bytes, timeout: float) -> bytes | None:
    loop = asyncio.get_running_loop()
    try:
        transport, proto = await loop.create_datagram_endpoint(
            lambda: _Collector(loop), remote_addr=(host, port)
        )
    except OSError:
        return None
    try:
        transport.sendto(payload)
        return await asyncio.wait_for(proto.future, timeout)
    except (TimeoutError, OSError):
        return None
    finally:
        transport.close()


@dataclass(frozen=True)
class UDPProbe:
    port: int
    name: str
    payload: Callable[[], bytes]
    parse: Callable[[bytes], dict[str, str] | None]  # None = resposta não reconhecida


def _parse_dns(data: bytes) -> dict[str, str] | None:
    try:
        resp = wire.parse_response(data)
    except (ValueError, struct.error, IndexError):
        return None
    answered = resp.rcode == 0 and bool(resp.answers)
    return {"recursion": "yes" if resp.recursion_available and answered else "no"}


def _parse_snmp(data: bytes) -> dict[str, str] | None:
    value = wire.snmp_response_value(data)
    if value is None:
        return None
    return {"community": "public", "sysdescr": value[:200]}


def _parse_ssdp(data: bytes) -> dict[str, str] | None:
    text = data.decode("latin-1", "replace")
    if not text.startswith("HTTP/1.1 200"):
        return None
    info = {}
    for header in ("server", "location", "st"):
        if m := re.search(rf"^{header}:\s*(.+?)\s*$", text, re.I | re.M):
            info[header] = m.group(1)[:200]
    return info


def _parse_mdns(data: bytes) -> dict[str, str] | None:
    try:
        resp = wire.parse_response(data)
    except (ValueError, struct.error, IndexError):
        return None
    services = sorted(set(resp.ptr_targets()))
    return {"services": ", ".join(services)[:400]} if services else {"services": ""}


def _parse_ntp(data: bytes) -> dict[str, str] | None:
    if len(data) < 48:
        return None
    mode = data[0] & 0x07
    if mode != 4:  # 4 = resposta de servidor
        return None
    return {"version": str((data[0] >> 3) & 0x07), "stratum": str(data[1])}


SSDP_SEARCH = (
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
)

UDP_PROBES: dict[int, UDPProbe] = {
    p.port: p
    for p in (
        UDPProbe(53, "dns", lambda: wire.build_query("example.com", wire.TYPE_A), _parse_dns),
        UDPProbe(123, "ntp", lambda: b"\x23" + b"\x00" * 47, _parse_ntp),
        UDPProbe(161, "snmp", lambda: wire.snmp_get("public"), _parse_snmp),
        UDPProbe(1900, "ssdp", lambda: SSDP_SEARCH, _parse_ssdp),
        UDPProbe(
            5353, "mdns",
            lambda: wire.build_query("_services._dns-sd._udp.local", wire.TYPE_PTR, recursion=False),
            _parse_mdns,
        ),
    )
}


async def probe_udp(host: str, port: int, timeout: float, retries: int = 1) -> Service | None:
    probe = UDP_PROBES.get(port)
    if probe is None:
        return None
    # UDP perde pacotes: uma retransmissão evita falso negativo em redes Wi-Fi.
    for _ in range(retries + 1):
        data = await udp_exchange(host, port, probe.payload(), timeout)
        if data is None:
            continue
        info = probe.parse(data)
        if info is None:
            return None
        text_like = probe.name == "ssdp"
        return Service(port=port, transport="udp", name=probe.name, extra=info,
                       banner=_clean_banner(data, 300) if text_like else None)
    return None
