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

from tbm.asyncutil import AdaptiveSemaphore, RateLimiter, gather_limited


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"  # recebemos RST: a porta está fechada, mas o host está vivo
    FILTERED = "filtered"  # timeout/sem resposta: firewall ou host inexistente
    ERROR = "error"  # o *nosso* sistema recusou o socket (sem buffers/portas): não diz nada do alvo


# Falta de recurso local: EMFILE/ENFILE (24/23), ENOBUFS (105/55), EADDRNOTAVAIL (99/49),
# WSAENOBUFS (10055), WSAEADDRINUSE (10048, portas efêmeras esgotadas), WSAEMFILE (10024).
RESOURCE_ERRNOS = {23, 24, 49, 55, 99, 105, 10024, 10048, 10055}


async def probe(host: str, port: int, timeout: float) -> PortState:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except ConnectionRefusedError:
        return PortState.CLOSED
    except TimeoutError:
        return PortState.FILTERED
    except OSError as exc:
        codes = {exc.errno, getattr(exc, "winerror", None)}
        return PortState.ERROR if codes & RESOURCE_ERRNOS else PortState.FILTERED
    writer.close()
    with suppress(Exception):
        await writer.wait_closed()
    return PortState.OPEN


async def guarded_probe(
    sem: asyncio.Semaphore, host: str, port: int, timeout: float, limiter: RateLimiter | None = None
) -> PortState:
    for attempt in range(2):
        async with sem:
            if limiter is not None:  # modo --gentle: limita conexões por segundo
                await limiter.acquire()
            state = await probe(host, port, timeout)
        if state is not PortState.ERROR:
            return state
        if isinstance(sem, AdaptiveSemaphore):
            sem.report_error()  # muitas seguidas: o paralelismo cai pela metade
        if attempt == 0:
            await asyncio.sleep(0.2)  # uma nova tentativa, já com menos sockets abertos
    return PortState.FILTERED


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


# Descoberta rápida (redes grandes): as portas que mais respondem, mesmo com RST.
FAST_DISCOVERY_PORTS = (80, 443, 22, 445)


async def is_alive(
    host: str, timeout: float, sem: asyncio.Semaphore, limiter: RateLimiter | None = None,
    ports: tuple[int, ...] = DISCOVERY_PORTS,
) -> bool:
    """Host está vivo se *qualquer* porta responder, mesmo com RST.

    É a mesma ideia do 'TCP ping' do nmap. Cancelamos o resto das sondas assim
    que uma responde. O ping ICMP e a tabela ARP complementam (scout/discovery.py).
    """
    tasks = [asyncio.create_task(guarded_probe(sem, host, p, timeout, limiter)) for p in ports]
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
    return None if name == ip or is_alias_name(name) else name


# Nomes que vêm do arquivo hosts local, não do aparelho: o Docker Desktop põe
# "host.docker.internal" apontando para o IP do próprio PC, e o DNS reverso
# devolve isso no lugar do nome real.
_ALIAS_SUFFIXES = (".docker.internal", ".docker.localhost")
_ALIAS_NAMES = {"localhost", "kubernetes.docker.internal"}


def is_alias_name(name: str) -> bool:
    lower = name.lower().rstrip(".")
    return lower in _ALIAS_NAMES or lower.endswith(_ALIAS_SUFFIXES)
