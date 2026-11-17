"""Orquestrador do Scout: descoberta, varredura de portas e fingerprint."""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass

from tbm.asyncutil import gather_limited
from tbm.models import Host, Service
from tbm.progress import NullProgress, ProgressHook
from tbm.scope import Target
from tbm.scout.banner import grab_service
from tbm.scout.ports import SERVICE_NAMES
from tbm.scout.portscan import is_alive, reverse_dns, scan_ports

PHASE_DISCOVERY = "Scout · descoberta de hosts"
PHASE_PORTS = "Scout · varredura de portas"
PHASE_SERVICES = "Scout · identificação de serviços"


@dataclass
class ScoutOptions:
    ports: list[int]
    timeout: float = 1.0
    concurrency: int = 400  # sockets simultâneos no total
    host_parallelism: int = 32  # hosts varridos ao mesmo tempo
    discovery: bool = True
    banners: bool = True
    legacy_tls: bool = True
    reverse_dns: bool = True


class Scout:
    def __init__(self, options: ScoutOptions, progress: ProgressHook | None = None) -> None:
        self.o = options
        self.p = progress or NullProgress()

    async def run(self, targets: list[Target]) -> list[Host]:
        sem = asyncio.Semaphore(self.o.concurrency)
        alive = await self._discover(targets, sem) if self.o.discovery else targets

        self.p.start(PHASE_PORTS, len(alive) * len(self.o.ports))
        self.p.start(PHASE_SERVICES, 0)
        hosts = await gather_limited(
            (lambda t=t: self._scan_host(t, sem) for t in alive), self.o.host_parallelism
        )
        found = [h for h in hosts if h is not None]
        return sorted(found, key=lambda h: ipaddress.ip_address(h.address))

    async def _discover(self, targets: list[Target], sem: asyncio.Semaphore) -> list[Target]:
        # Um único alvo explícito: o usuário quer escanear, não perguntar se existe.
        if len(targets) == 1:
            return targets
        self.p.start(PHASE_DISCOVERY, len(targets))

        async def check(t: Target) -> Target | None:
            alive = await is_alive(t.address, self.o.timeout, sem)
            self.p.advance(PHASE_DISCOVERY)
            return t if alive else None

        results = await gather_limited((lambda t=t: check(t) for t in targets), limit=128)
        alive = [t for t in results if t]
        self.p.log(f"{len(alive)}/{len(targets)} hosts responderam")
        return alive

    async def _scan_host(self, target: Target, sem: asyncio.Semaphore) -> Host | None:
        open_ports = await scan_ports(
            target.address,
            self.o.ports,
            timeout=self.o.timeout,
            sem=sem,
            on_done=lambda: self.p.advance(PHASE_PORTS),
        )
        if not open_ports and not self.o.discovery:
            return None

        hostname = target.hostname
        if hostname is None and self.o.reverse_dns:
            hostname = await reverse_dns(target.address)

        services: list[Service]
        if self.o.banners and open_ports:
            self.p.start(PHASE_SERVICES, len(open_ports))  # soma ao total já existente

            async def grab(port: int) -> Service:
                async with sem:
                    svc = await grab_service(
                        target.address,
                        port,
                        hostname=target.hostname,
                        timeout=max(self.o.timeout, 2.0),
                        legacy_tls=self.o.legacy_tls,
                    )
                self.p.advance(PHASE_SERVICES)
                return svc

            services = list(await asyncio.gather(*(grab(p) for p in open_ports)))
        else:
            services = [Service(port=p, name=SERVICE_NAMES.get(p)) for p in open_ports]

        return Host(address=target.address, hostname=hostname, services=services)
