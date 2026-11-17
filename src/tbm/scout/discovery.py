"""Descoberta de dispositivos que não têm porta TCP aberta.

No primeiro scan real, só 3 ou 4 dos 254 IPs responderam ao TCP ping:
celulares, TVs e IoT costumam não escutar em nenhuma porta comum. Três
técnicas complementares, todas sem privilégio de admin:

1. Ping do sistema (ICMP): o executável `ping` já tem permissão para raw
   sockets, então só precisamos chamá-lo em paralelo.
2. Tabela ARP: qualquer IP que respondeu ao ARP está vivo, mesmo com
   firewall bloqueando ICMP e todas as portas fechadas.
3. Multicast mDNS e SSDP: uma única pergunta para o grupo faz *todos* os
   aparelhos que anunciam serviços responderem, com nome e tipo.
"""

from __future__ import annotations

import asyncio
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial

from tbm.asyncutil import gather_limited
from tbm.paths import no_window
from tbm.scout import wire

MDNS_GROUP = ("224.0.0.251", 5353)
SSDP_GROUP = ("239.255.255.250", 1900)

# Tipos de serviço perguntados no mDNS. Muitos aparelhos não respondem ao
# "_services._dns-sd" genérico, só a perguntas sobre o próprio tipo.
MDNS_SERVICE_TYPES = [
    "_services._dns-sd._udp.local",
    "_airplay._tcp.local", "_raop._tcp.local", "_companion-link._tcp.local",
    "_googlecast._tcp.local", "_spotify-connect._tcp.local", "_hap._tcp.local",
    "_ipp._tcp.local", "_printer._tcp.local", "_pdl-datastream._tcp.local",
    "_smb._tcp.local", "_http._tcp.local", "_workstation._tcp.local",
    "_device-info._tcp.local", "_amzn-wplay._tcp.local", "_androidtvremote2._tcp.local",
    "_matter._tcp.local", "_matterc._udp.local",
]

SSDP_DISCOVER = (
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'
)


# ───────────────────────────── rede local ─────────────────────────────


def local_ipv4() -> str | None:
    """IP desta máquina na rede principal.

    `connect()` num socket UDP não envia pacote nenhum: só faz o SO escolher a
    rota e o IP de origem, que lemos com getsockname(). 192.0.2.1 é um endereço
    de documentação (TEST-NET-1), nunca roteado.
    """
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            return s.getsockname()[0]
    except OSError:
        return None


def suggested_target() -> str:
    """A /24 da rede local, para preencher o formulário da interface."""
    import ipaddress

    ip = local_ipv4()
    if ip:
        addr = ipaddress.ip_address(ip)
        if addr.is_private and not addr.is_loopback:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return "192.168.0.0/24"


# ───────────────────────────── ping ─────────────────────────────


def ping_command(ip: str, timeout: float) -> list[str]:
    ms = str(max(200, int(timeout * 1000)))
    if sys.platform == "win32":
        return ["ping", "-n", "1", "-w", ms, ip]
    if sys.platform == "darwin":
        return ["ping", "-c", "1", "-W", ms, ip]
    return ["ping", "-c", "1", "-W", str(max(1, round(timeout))), ip]


def ping_replied(output: bytes) -> bool:
    """Procuramos o TTL na saída, e não o exit code: no Windows, o ping devolve 0
    até para "Destination host unreachable" vindo do roteador."""
    return b"ttl=" in output.lower()


async def ping(ip: str, timeout: float = 1.0) -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            *ping_command(ip, timeout), stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, **no_window(),
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout + 3)
    except (OSError, TimeoutError):
        return False
    return ping_replied(out)


async def ping_sweep(addresses: list[str], timeout: float = 1.0, concurrency: int = 64) -> set[str]:
    results = await gather_limited((partial(ping, ip, timeout) for ip in addresses), concurrency)
    return {ip for ip, ok in zip(addresses, results, strict=True) if ok}


def parse_default_gateway(text: str, platform: str) -> str | None:
    if platform == "linux":  # /proc/net/route: destino 00000000, gateway em hex little-endian
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) > 2 and parts[1] == "00000000" and parts[2] != "00000000":
                raw = bytes.fromhex(parts[2])[::-1]
                return ".".join(str(b) for b in raw)
        return None
    if platform == "win32":  # route print: "0.0.0.0  0.0.0.0  <gateway>  <interface>  <métrica>"
        m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", text, re.M)
        return m.group(1) if m else None
    m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", text)  # macOS/BSD: route -n get default
    return m.group(1) if m else None


async def default_gateway() -> str | None:
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/net/route") as fh:  # noqa: ASYNC230 (arquivo virtual minúsculo)
                return parse_default_gateway(fh.read(), "linux")
        cmd = ["route", "print", "-4", "0.0.0.0"] if sys.platform == "win32" else ["route", "-n", "get", "default"]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, **no_window()
        )
        out, _ = await asyncio.wait_for(proc.communicate(), 5)
    except (OSError, TimeoutError):
        return None
    return parse_default_gateway(out.decode(errors="ignore"), "win32" if sys.platform == "win32" else "bsd")


# ───────────────────────────── multicast ─────────────────────────────


@dataclass
class Announcement:
    """O que um aparelho contou sobre si mesmo via mDNS/SSDP."""

    names: set[str] = field(default_factory=set)  # ex.: "iPhone-de-Ana.local"
    services: set[str] = field(default_factory=set)  # ex.: "_airplay._tcp"
    instances: set[str] = field(default_factory=set)  # ex.: "Sala de Estar._googlecast._tcp.local"
    ssdp_server: str | None = None
    ssdp_location: str | None = None
    ssdp_types: set[str] = field(default_factory=set)

    @property
    def best_name(self) -> str | None:
        for inst in sorted(self.instances):
            label = inst.split("._", 1)[0]
            if label and not re.fullmatch(r"[0-9a-f\-]{16,}", label, re.I):  # ignora UUIDs
                return label
        for n in sorted(self.names):
            return n.removesuffix(".local")
        return None


class _Listener(asyncio.DatagramProtocol):
    def __init__(self, on_packet: Callable[[bytes, str], None]) -> None:
        self.on_packet = on_packet

    def datagram_received(self, data: bytes, addr) -> None:
        self.on_packet(data, addr[0])

    def error_received(self, exc: Exception) -> None:
        pass


def _service_type(name: str) -> str | None:
    m = re.search(r"(_[\w-]+\._(?:tcp|udp))\.local\.?$", name)
    return m.group(1) if m else None


def absorb_mdns(found: dict[str, Announcement], data: bytes, source: str) -> None:
    try:
        resp = wire.parse_response(data)
    except wire.ParseError:
        return
    ann = found.setdefault(source, Announcement())
    for target in resp.ptr_targets():
        if (stype := _service_type(target)) and target.startswith("_"):
            ann.services.add(stype)  # resposta ao _services._dns-sd: o próprio tipo
        elif stype:
            ann.services.add(stype)
            ann.instances.add(target)
    for name, ip in resp.a_records().items():
        # O registro A diz o nome do aparelho; atribuímos ao IP do registro
        # (normalmente igual à origem do pacote).
        found.setdefault(ip, Announcement()).names.add(name)


def absorb_ssdp(found: dict[str, Announcement], data: bytes, source: str) -> None:
    text = data.decode("latin-1", "replace")
    if not text.startswith("HTTP/1.1 200") and not text.startswith("NOTIFY"):
        return
    ann = found.setdefault(source, Announcement())
    for header, attr in (("server", "ssdp_server"), ("location", "ssdp_location")):
        if m := re.search(rf"^{header}:\s*(.+?)\s*$", text, re.I | re.M):
            setattr(ann, attr, m.group(1)[:200])
    if m := re.search(r"^st:\s*(.+?)\s*$", text, re.I | re.M):
        ann.ssdp_types.add(m.group(1)[:120])


async def multicast_discover(wait: float = 3.0) -> dict[str, Announcement]:
    """Pergunta ao grupo mDNS e ao SSDP e coleta respostas por `wait` segundos."""
    loop = asyncio.get_running_loop()
    found: dict[str, Announcement] = {}
    transports = []
    try:
        mdns_t, _ = await loop.create_datagram_endpoint(
            lambda: _Listener(lambda d, s: absorb_mdns(found, d, s)), local_addr=("0.0.0.0", 0)
        )
        transports.append(mdns_t)
        ssdp_t, _ = await loop.create_datagram_endpoint(
            lambda: _Listener(lambda d, s: absorb_ssdp(found, d, s)), local_addr=("0.0.0.0", 0)
        )
        transports.append(ssdp_t)
    except OSError:
        for t in transports:
            t.close()
        return found

    query = wire.build_multi_query(MDNS_SERVICE_TYPES, wire.TYPE_PTR, unicast_response=True)
    for attempt in range(2):  # multicast perde pacotes; mandamos duas vezes
        try:
            mdns_t.sendto(query, MDNS_GROUP)
            ssdp_t.sendto(SSDP_DISCOVER, SSDP_GROUP)
        except OSError:
            break
        await asyncio.sleep(wait / 2 if attempt == 0 else 0)
    await asyncio.sleep(wait / 2)
    for t in transports:
        t.close()
    return found
