"""Dois ataques clássicos de rede local, detectados de forma passiva.

- Wi-Fi falso ("evil twin"): uma rede com o MESMO nome da sua, mas aberta
  (sem senha). Quem se conectar a ela por engano entrega todo o tráfego ao
  atacante. Lemos a lista de redes visíveis pelo próprio sistema.

- DHCP intruso ("rogue DHCP"): um segundo servidor DHCP na rede pode entregar
  um gateway ou DNS falso e interceptar tudo. Mandamos um DHCPDISCOVER e
  contamos quantos servidores diferentes respondem.

Nada de login nem de injeção: só leitura do que já está no ar.
"""

from __future__ import annotations

import asyncio
import re
import secrets
import socket
import struct
import sys
from dataclasses import dataclass

from tbm.paths import no_window


@dataclass
class WifiNetwork:
    ssid: str
    open: bool  # sem criptografia


def parse_netsh_networks(text: str) -> list[WifiNetwork]:
    """`netsh wlan show networks` (Windows), em português ou inglês."""
    nets, ssid = [], None
    for line in text.splitlines():
        if m := re.match(r"\s*SSID\s+\d+\s*:\s*(.*)", line):
            ssid = m.group(1).strip()
        elif ssid is not None and re.search(r"(Autentica|Authentication)", line):
            auth = line.split(":", 1)[1].strip().lower() if ":" in line else ""
            nets.append(WifiNetwork(ssid, auth in ("aberta", "aberto", "open", "none")))
            ssid = None
    return nets


async def visible_networks() -> list[WifiNetwork]:
    if sys.platform != "win32":
        return []  # Linux/macOS exigem nmcli/airport com permissões extras; deixamos de fora
    try:
        proc = await asyncio.create_subprocess_exec(
            "netsh", "wlan", "show", "networks", stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, **no_window())
        out, _ = await asyncio.wait_for(proc.communicate(), 15)
    except (OSError, TimeoutError):
        return []
    text = out.decode("utf-8", "replace")
    if "�" in text:
        text = out.decode("cp850", "replace")
    return parse_netsh_networks(text)


def evil_twin(current_ssid: str | None, networks: list[WifiNetwork]) -> list[str]:
    """SSIDs iguais ao seu que aparecem SEM criptografia (um gêmeo aberto)."""
    if not current_ssid:
        return []
    return sorted({n.ssid for n in networks if n.ssid == current_ssid and n.open})


# ───────────────────────────── DHCP ─────────────────────────────


def build_discover(mac: bytes, xid: bytes) -> bytes:
    """DHCPDISCOVER mínimo (RFC 2131). mac: 6 bytes; xid: 4 bytes aleatórios."""
    pkt = struct.pack("!BBBB4sHH4s4s4s4s16s192s4s",
                      1, 1, 6, 0, xid, 0, 0x8000, b"\0" * 4, b"\0" * 4, b"\0" * 4, b"\0" * 4,
                      mac + b"\0" * 10, b"\0" * 192, bytes.fromhex("63825363"))
    pkt += bytes([53, 1, 1])  # option 53 = DHCPDISCOVER
    pkt += bytes([55, 3, 1, 3, 6])  # parameter request list
    pkt += b"\xff"  # end
    return pkt


def server_ids(responses: list[bytes], xid: bytes) -> set[str]:
    """IPs dos servidores DHCP que responderam (option 54 ou campo siaddr)."""
    servers: set[str] = set()
    for data in responses:
        if len(data) < 240 or data[:1] != b"\x02" or data[4:8] != xid:
            continue
        opts, i = data[240:], 0
        found = None
        while i < len(opts):
            code = opts[i]
            if code == 0xFF or code == 0:
                i += 1
                continue
            length = opts[i + 1]
            if code == 54 and length == 4:  # server identifier
                found = socket.inet_ntoa(opts[i + 2:i + 6])
            i += 2 + length
        servers.add(found or socket.inet_ntoa(data[20:24]))
    return servers


async def discover_dhcp_servers(timeout: float = 3.0) -> set[str] | None:
    """Conta servidores DHCP na rede. None = não deu para testar (precisa da porta 68/bind)."""
    loop = asyncio.get_running_loop()
    xid = secrets.token_bytes(4)
    mac = secrets.token_bytes(6)
    responses: list[bytes] = []

    class _Proto(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: object) -> None:
            responses.append(data)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("0.0.0.0", 68))  # porta de cliente DHCP; costuma exigir privilégio
        sock.setblocking(False)
    except OSError:
        return None
    try:
        transport, _ = await loop.create_datagram_endpoint(_Proto, sock=sock)
        try:
            transport.sendto(build_discover(mac, xid), ("255.255.255.255", 67))
            await asyncio.sleep(timeout)
        finally:
            transport.close()
    except OSError:
        return None
    return server_ids(responses, xid)
