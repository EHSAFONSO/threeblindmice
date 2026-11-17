"""Orquestrador do Scout: descoberta, varredura TCP/UDP, fingerprint e identificação."""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass, field
from functools import partial

from tbm.asyncutil import RateLimiter, gather_limited
from tbm.models import Host, Service
from tbm.progress import NullProgress, ProgressHook
from tbm.scope import Target
from tbm.scout.arp import OUIDatabase, read_arp_table
from tbm.scout.banner import grab_service
from tbm.scout.classify import classify
from tbm.scout.discovery import Announcement, default_gateway, multicast_discover, ping_sweep
from tbm.scout.ports import SERVICE_NAMES
from tbm.scout.portscan import is_alive, reverse_dns, scan_ports
from tbm.scout.udp import UDP_PROBES, probe_udp

PHASE_DISCOVERY = "Scout · descoberta de hosts"
PHASE_PORTS = "Scout · varredura de portas"
PHASE_SERVICES = "Scout · identificação de serviços"
PHASE_UDP = "Scout · sondas UDP"


@dataclass
class ScoutOptions:
    ports: list[int]
    timeout: float = 1.0
    concurrency: int = 400  # sockets simultâneos no total
    host_parallelism: int = 32  # hosts varridos ao mesmo tempo
    discovery: bool = True
    ping: bool = True  # ping ICMP do sistema na descoberta
    multicast: bool = True  # mDNS/SSDP para o grupo na descoberta
    banners: bool = True
    legacy_tls: bool = True
    reverse_dns: bool = True
    udp: bool = False
    udp_ports: list[int] = field(default_factory=lambda: sorted(UDP_PROBES))
    mac_lookup: bool = True
    rate: float | None = None  # conexões TCP por segundo (None = sem limite)

    @classmethod
    def gentle(cls, ports: list[int], **kw) -> ScoutOptions:
        """Para redes com IoT frágil: câmeras e lâmpadas baratas travam sob 400 conexões."""
        return cls(ports=ports, concurrency=16, host_parallelism=4, rate=50.0, **kw)


@dataclass
class DiscoveryReport:
    found_by: dict[str, set[str]] = field(default_factory=dict)  # ip → {"tcp","ping","arp","mdns","ssdp"}
    announcements: dict[str, Announcement] = field(default_factory=dict)
    gateway: str | None = None


class Scout:
    def __init__(self, options: ScoutOptions, progress: ProgressHook | None = None) -> None:
        self.o = options
        self.p = progress or NullProgress()
        self.limiter = RateLimiter(int(options.rate), 1.0) if options.rate else None
        self.report = DiscoveryReport()

    async def run(self, targets: list[Target]) -> list[Host]:
        sem = asyncio.Semaphore(self.o.concurrency)
        alive = await self._discover(targets, sem) if self.o.discovery else targets

        self.p.start(PHASE_PORTS, len(alive) * len(self.o.ports))
        self.p.start(PHASE_SERVICES, 0)
        if self.o.udp:
            self.p.start(PHASE_UDP, len(alive) * len(self.o.udp_ports))
        hosts = await gather_limited(
            (partial(self._scan_host, t, sem) for t in alive), self.o.host_parallelism
        )
        found = [h for h in hosts if h is not None]
        if self.o.mac_lookup and found:
            await self._attach_macs(found)
        self._identify(found)
        return sorted(found, key=lambda h: ipaddress.ip_address(h.address))

    # ───────────────────────── descoberta ─────────────────────────

    async def _discover(self, targets: list[Target], sem: asyncio.Semaphore) -> list[Target]:
        # Um único alvo explícito: o usuário quer escanear, não perguntar se existe.
        if len(targets) == 1:
            return targets
        by_ip = {t.address: t for t in targets}
        self.p.start(PHASE_DISCOVERY, len(targets))

        async def tcp_check(t: Target) -> str | None:
            ok = await is_alive(t.address, self.o.timeout, sem, self.limiter)
            self.p.advance(PHASE_DISCOVERY)
            return t.address if ok else None

        async def no_ping() -> set[str]:
            return set()

        async def no_multicast() -> dict[str, Announcement]:
            return {}

        tcp_results, pinged, announced, gateway = await asyncio.gather(
            gather_limited((partial(tcp_check, t) for t in targets), limit=128),
            ping_sweep(list(by_ip), self.o.timeout) if self.o.ping else no_ping(),
            multicast_discover() if self.o.multicast else no_multicast(),
            default_gateway(),
        )
        # A tabela ARP é lida depois: as sondas acima é que a preenchem.
        arp = await read_arp_table() if self.o.mac_lookup else {}

        methods: dict[str, set[str]] = {}

        def mark(ips, how: str) -> None:
            for ip in ips:
                if ip in by_ip:  # só o que está nos alvos (e portanto no escopo)
                    methods.setdefault(ip, set()).add(how)

        mark((ip for ip in tcp_results if ip), "tcp")
        mark(pinged, "ping")
        mark(arp, "arp")
        for ip, ann in announced.items():
            mark([ip], "mdns" if ann.services or ann.names else "ssdp")

        self.report = DiscoveryReport(
            found_by=methods,
            announcements={ip: a for ip, a in announced.items() if ip in by_ip},
            gateway=gateway if gateway in by_ip else None,
        )
        alive = [by_ip[ip] for ip in sorted(methods, key=ipaddress.ip_address)]
        self.p.log(f"{len(alive)}/{len(targets)} hosts encontrados "
                   f"(tcp {sum('tcp' in m for m in methods.values())}, "
                   f"ping {sum('ping' in m for m in methods.values())}, "
                   f"arp {sum('arp' in m for m in methods.values())}, "
                   f"mdns/ssdp {len(self.report.announcements)})")
        return alive

    # ───────────────────────── identificação ─────────────────────────

    async def _attach_macs(self, hosts: list[Host]) -> None:
        table = await read_arp_table()
        if not table:
            return
        oui = OUIDatabase()
        for h in hosts:
            if mac := table.get(h.address):
                h.mac = mac
                h.vendor = oui.lookup(mac)

    def _identify(self, hosts: list[Host]) -> None:
        for h in hosts:
            if how := self.report.found_by.get(h.address):
                h.discovery["found_by"] = ",".join(sorted(how))
            if ann := self.report.announcements.get(h.address):
                h.device_name = ann.best_name
                if ann.names:
                    h.discovery["mdns_names"] = ",".join(sorted(ann.names))
                if ann.services:
                    h.discovery["mdns_services"] = ",".join(sorted(ann.services))
                if ann.ssdp_server:
                    h.discovery["ssdp_server"] = ann.ssdp_server
                if ann.ssdp_location:
                    h.discovery["ssdp_location"] = ann.ssdp_location
                if ann.ssdp_types:
                    h.discovery["ssdp_types"] = ",".join(sorted(ann.ssdp_types))[:300]
            title = next((s.extra["title"] for s in h.services if s.extra.get("title")), None)
            if title:
                h.discovery["http_title"] = title
            h.device_type = classify(h, is_gateway=h.address == self.report.gateway)

    # ───────────────────────── varredura ─────────────────────────

    async def _udp(self, address: str, sem: asyncio.Semaphore) -> list[Service]:
        async def one(port: int) -> Service | None:
            async with sem:
                svc = await probe_udp(address, port, max(self.o.timeout, 1.5))
            self.p.advance(PHASE_UDP)
            return svc

        results = await asyncio.gather(*(one(p) for p in self.o.udp_ports))
        return [s for s in results if s]

    async def _scan_host(self, target: Target, sem: asyncio.Semaphore) -> Host | None:
        tcp_task = scan_ports(
            target.address,
            self.o.ports,
            timeout=self.o.timeout,
            sem=sem,
            on_done=lambda: self.p.advance(PHASE_PORTS),
            limiter=self.limiter,
        )
        if self.o.udp:
            open_ports, udp_services = await asyncio.gather(tcp_task, self._udp(target.address, sem))
        else:
            open_ports, udp_services = await tcp_task, []

        if not open_ports and not udp_services and not self.o.discovery:
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

        return Host(address=target.address, hostname=hostname, services=services + udp_services)
