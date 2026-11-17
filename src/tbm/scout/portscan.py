"""TCP connect scan assíncrono e descoberta de hosts.

Usamos connect() completo em vez de SYN scan: não precisa de privilégio de
admin nem de driver de captura (Npcap), e funciona igual em Windows/Linux/macOS.
O custo é ser mais "barulhento" nos logs do alvo, o que numa ferramenta
defensiva é até desejável.
"""

from __future__ import annotations

import asyncio
import socket
from contextlib import suppress
from enum import Enum
from functools import partial

from tbm.asyncutil import RateLimiter, gather_limited


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"  # recebemos RST: a porta está fechada, mas o host está vivo
    FILTERED = "filtered"  # timeout/sem resposta: firewall ou host inexistente


async def probe(host: str, port: int, timeout: float) -> PortState:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except ConnectionRefusedError:
        return PortState.CLOSED
    except (TimeoutError, OSError):
        return PortState.FILTERED
    writer.close()
    with suppress(Exception):
        await writer.wait_closed()
    return PortState.OPEN


async def guarded_probe(
    sem: asyncio.Semaphore, host: str, port: int, timeout: float, limiter: RateLimiter | None = None
) -> PortState:
    async with sem:
        if limiter is not None:  # modo --gentle: limita conexões por segundo
            await limiter.acquire()
        return await probe(host, port, timeout)


async def scan_ports(
    host: str,
    ports: list[int],
    *,
    timeout: float,
    sem: asyncio.Semaphore,
    on_done=None,
    limiter: RateLimiter | None = None,
) -> list[int]:
    async def one(port: int) -> int | None:
        state = await guarded_probe(sem, host, port, timeout, limiter)
        if on_done:
            on_done()
        return port if state is PortState.OPEN else None

    # O semáforo global limita sockets; este limite só evita criar
    # 65535 corrotinas por host quando o usuário pede --ports all.
    results = await gather_limited((partial(one, p) for p in ports), limit=1024)
    return [p for p in results if p is not None]


DISCOVERY_PORTS = (80, 443, 22, 445, 139, 135, 3389, 53, 8080, 62078, 5357, 7000)


async def is_alive(
    host: str, timeout: float, sem: asyncio.Semaphore, limiter: RateLimiter | None = None
) -> bool:
    """Host está vivo se *qualquer* porta responder, mesmo com RST.

    É a mesma ideia do 'TCP ping' do nmap. Cancelamos o resto das sondas assim
    que uma responde. O ping ICMP e a tabela ARP complementam (scout/discovery.py).
    """
    tasks = [asyncio.create_task(guarded_probe(sem, host, p, timeout, limiter)) for p in DISCOVERY_PORTS]
    try:
        for next_done in asyncio.as_completed(tasks):
            if await next_done in (PortState.OPEN, PortState.CLOSED):
                return True
        return False
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def reverse_dns(ip: str, timeout: float = 1.5) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        name, _ = await asyncio.wait_for(loop.getnameinfo((ip, 0), socket.NI_NAMEREQD), timeout)
    except (TimeoutError, OSError):
        return None
    return name if name != ip else None
