"""IPv6: o furo que o NAT escondia.

No IPv4 de casa, o NAT do roteador funciona como um muro: ninguém da internet
alcança um aparelho da rede sem um redirecionamento de porta. No IPv6 não há
NAT. Cada aparelho recebe um endereço *global*, roteável na internet, e a
única proteção é o firewall IPv6 do roteador. Alguns modems de operadora vêm
com ele desligado.

Daqui não dá para testar o firewall (precisaria de um ponto de vista de fora),
mas dá para saber o que estaria exposto se ele estiver desligado:

1. quais aparelhos têm endereço IPv6 global (tabela de vizinhos NDP do sistema
   e registros AAAA anunciados via mDNS);
2. quais portas abertas no IPv4 também respondem no IPv6 global.

Os endereços vêm da própria rede local (NDP/mDNS), então as conexões ficam no
mesmo enlace: não saímos para a internet.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import sys

from tbm.paths import no_window
from tbm.scout.arp import normalize_mac

_V6_RE = re.compile(r"(?<![\w:])([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?:%\S+)?")
_MAC_RE = re.compile(r"\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b")
_IGNORED = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


def is_global_v6(address: str) -> bool:
    try:
        ip = ipaddress.IPv6Address(address.split("%")[0])
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


def parse_neighbors(text: str) -> dict[str, set[str]]:
    """MAC → IPv6 globais, a partir de `netsh interface ipv6 show neighbors`,
    `ip -6 neigh` ou `ndp -an` (o formato muda, mas cada linha tem um IPv6 e um MAC)."""
    out: dict[str, set[str]] = {}
    for line in text.splitlines():
        mac_m = _MAC_RE.search(line)
        if not mac_m:
            continue
        mac = normalize_mac(mac_m.group(1))
        if mac in _IGNORED or mac.startswith("33:33") or int(mac[:2], 16) & 0x01:
            continue
        for m in _V6_RE.finditer(line):
            candidate = m.group(1)
            if candidate.count(":") >= 2 and is_global_v6(candidate):
                out.setdefault(mac, set()).add(str(ipaddress.IPv6Address(candidate)))
    return out


def local_global_addresses() -> list[str]:
    """IPv6 globais desta máquina: a prova de que a rede tem IPv6 roteável."""
    import socket

    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)
    except OSError:
        return []
    return sorted({a for i in infos if is_global_v6(a := str(i[4][0]).split("%")[0])})


def neighbor_command() -> list[str]:
    if sys.platform == "win32":
        return ["netsh", "interface", "ipv6", "show", "neighbors"]
    if sys.platform == "darwin":
        return ["ndp", "-an"]
    return ["ip", "-6", "neigh", "show"]


async def read_neighbors() -> dict[str, set[str]]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *neighbor_command(), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, **no_window()
        )
        out, _ = await asyncio.wait_for(proc.communicate(), 10)
    except (OSError, TimeoutError):
        return {}
    return parse_neighbors(out.decode("utf-8", errors="ignore"))


async def open_on_v6(address: str, ports: list[int], timeout: float = 1.0) -> list[int]:
    """Quais destas portas aceitam conexão TCP no endereço IPv6."""

    async def one(port: int) -> int | None:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout)
        except (OSError, TimeoutError):
            return None
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return port

    results = await asyncio.gather(*(one(p) for p in ports))
    return sorted(p for p in results if p is not None)
