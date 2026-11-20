"""Orquestrador do Scout: descoberta, varredura TCP/UDP, fingerprint e identificação."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path

from tbm.asyncutil import AdaptiveSemaphore, RateLimiter, gather_limited
from tbm.models import Host, Service
from tbm.progress import NullProgress, ProgressHook, report_found
from tbm.scope import Target
from tbm.scout.arp import OUIDatabase, read_arp_table
from tbm.scout.banner import grab_service
from tbm.scout.classify import classify
from tbm.scout.discovery import Announcement, default_gateway, local_ipv4, multicast_discover, ping_sweep
from tbm.scout.ipv6 import is_global_v6, local_global_addresses, open_on_v6, read_neighbors
from tbm.scout.model import enrich as enrich_model
from tbm.scout.names import local_name
from tbm.scout.ports import SERVICE_NAMES
from tbm.scout.portscan import DISCOVERY_PORTS, FAST_DISCOVERY_PORTS, is_alive, reverse_dns, scan_ports
from tbm.scout.udp import UDP_PROBES, probe_udp

PHASE_DISCOVERY = "Scout · descoberta de hosts"
PHASE_PORTS = "Scout · varredura de portas"
PHASE_SERVICES = "Scout · identificação de serviços"
PHASE_UDP = "Scout · sondas UDP"

# Acima disto (/22), a descoberta "auto" vira a rápida: sem um ping do sistema por IP.
LARGE_NETWORK = 1024
# Teto de pings na descoberta rápida (um processo do sistema cada): ~1 min com 64 em paralelo.
MAX_FAST_PINGS = 4096


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
    local_names: bool = True  # NetBIOS/LLMNR quando o DNS reverso não tem nome
    ipv6: bool = True  # endereços IPv6 globais e portas abertas também no IPv6
    # auto: "thorough" até /22 e "fast" acima. fast = TCP em 4 portas + ARP + multicast, e ping
    # só nos blocos /24 em que algo respondeu; o timeout passa a seguir o RTT medido.
    discovery_mode: str = "auto"
    checkpoint: Path | None = None  # arquivo de checkpoint (redes grandes); None = sem checkpoint
    resume: bool = False  # reaproveita o checkpoint, se os alvos e as portas forem os mesmos

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
        self.errors: list[str] = []  # falhas de enriquecedores (vão para ScanResult.errors)
        self.timeout = options.timeout  # timeout de conexão efetivo (pode cair com o RTT medido)
        self.mode = "thorough"
        self.timings: dict[str, float] = {}  # segundos por fase (vão para ScanResult.timings)
        self.semaphore: AdaptiveSemaphore | None = None

    async def run(self, targets: list[Target]) -> list[Host]:
        sem = self.semaphore = AdaptiveSemaphore(self.o.concurrency)
        try:
            return await self._run(targets, sem)
        finally:
            sem.close()
            if sem.shrinks:
                self.p.log(f"paralelismo reduzido para {sem.limit} sockets (o sistema estava recusando conexões)")

    async def _run(self, targets: list[Target], sem: AdaptiveSemaphore) -> list[Host]:
        from tbm.scout.checkpoint import Checkpoint, fingerprint

        by_ip = {t.address: t for t in targets}
        ck = None
        resumed = False
        if self.o.checkpoint is not None:
            key = fingerprint(list(by_ip), self.o.ports, self.o.udp)
            ck, resumed = Checkpoint.open(self.o.checkpoint, key, resume=self.o.resume)

        start = time.monotonic()
        if resumed and ck is not None and ck.discovery is not None:
            disc = ck.discovery
            self.report = DiscoveryReport(found_by={ip: set(m) for ip, m in disc["found_by"].items()},
                                          announcements=ck.announcements(), gateway=disc["gateway"])
            self.timeout = disc["timeout"]
            alive = [by_ip[ip] for ip in disc["alive"] if ip in by_ip]
            self.p.log(f"retomando o scan anterior: {len(ck.scanned)}/{len(alive)} aparelhos já varridos")
        else:
            resumed = False
            alive = await self._discover(targets, sem) if self.o.discovery else targets
            if ck is not None:
                ck.save_discovery([t.address for t in alive], self.report.found_by, self.report.gateway,
                                  self.report.announcements, self.timeout)
        self.timings["discovery"] = round(time.monotonic() - start, 2)

        start = time.monotonic()
        previous = ck.hosts() if resumed and ck is not None else []
        done = ck.scanned if resumed and ck is not None else set()
        pending = [t for t in alive if t.address not in done]
        self.p.start(PHASE_PORTS, len(pending) * len(self.o.ports))
        self.p.start(PHASE_SERVICES, 0)
        if self.o.udp:
            self.p.start(PHASE_UDP, len(pending) * len(self.o.udp_ports))
        found = list(previous)
        # Com checkpoint, um bloco /24 por vez (o arquivo é gravado a cada bloco); sem, tudo junto.
        for chunk in (self._blocks(pending) if ck is not None else [pending]):
            hosts = await gather_limited(
                (partial(self._scan_host, t, sem) for t in chunk), self.o.host_parallelism
            )
            new = [h for h in hosts if h is not None]
            found += new
            if ck is not None:
                ck.add([t.address for t in chunk], new)
        self.timings["ports"] = round(time.monotonic() - start, 2)

        start = time.monotonic()
        if self.o.mac_lookup and found:
            await self._attach_macs(found)
        self._identify(found)
        if self.o.banners and found:
            await enrich_model(found)  # fabricante/modelo/firmware anunciados (UPnP, SNMP)
        if self.o.ipv6 and found:
            await self._attach_ipv6(found)
        if found:
            await self._run_enrichers(found)
        for h in found:  # segunda passada: agora com tipo e portas
            report_found(self.p, h.address, name=h.name, type=h.device_type,
                         ports=len(h.services), gateway=h.address == self.report.gateway)
        self.timings["identify"] = round(time.monotonic() - start, 2)
        if ck is not None:
            ck.finish()  # terminou: não há o que retomar
        return sorted(found, key=lambda h: ipaddress.ip_address(h.address))

    @staticmethod
    def _blocks(targets: list[Target]) -> list[list[Target]]:
        """Agrupa por bloco /24 (IPv4) na ordem em que vieram."""
        groups: dict[str, list[Target]] = {}
        for t in targets:
            key = t.address.rsplit(".", 1)[0] if t.address.count(".") == 3 else t.address
            groups.setdefault(key, []).append(t)
        return list(groups.values())

    async def _run_enrichers(self, hosts: list[Host]) -> None:
        """Enriquecedores de plugins (tbm.discovery): cada um isolado, com erro anotado no scan."""
        from tbm.plugins import load_plugins
        from tbm.scout.extend import ENRICHERS

        load_plugins()
        for eid, cls in ENRICHERS.items():
            before = list(hosts)
            try:
                await cls().enrich(hosts, self.o)
            except Exception as exc:  # noqa: BLE001 (um plugin quebrado não derruba o scan)
                self.errors.append(f"{eid}: {exc.__class__.__name__}: {exc}")
            if [h.address for h in hosts] != [h.address for h in before]:
                # aparelhos são decididos pelo escopo, não por plugin: desfaz qualquer inclusão/remoção
                self.errors.append(f"{eid}: alterou a lista de aparelhos (ignorado)")
                hosts[:] = before

    # ───────────────────────── descoberta ─────────────────────────

    async def _discover(self, targets: list[Target], sem: asyncio.Semaphore) -> list[Target]:
        # Um único alvo explícito: o usuário quer escanear, não perguntar se existe.
        if len(targets) == 1:
            return targets
        by_ip = {t.address: t for t in targets}
        fast = self.o.discovery_mode == "fast" or (self.o.discovery_mode == "auto" and len(targets) > LARGE_NETWORK)
        self.mode = "fast" if fast else "thorough"
        self.p.start(PHASE_DISCOVERY, len(targets))
        rtts: list[float] = []
        probe_ports = FAST_DISCOVERY_PORTS if fast else DISCOVERY_PORTS

        async def tcp_check(t: Target) -> str | None:
            began = time.monotonic()
            ok = await is_alive(t.address, self.o.timeout, sem, self.limiter, ports=probe_ports)
            self.p.advance(PHASE_DISCOVERY)
            if ok:
                rtts.append(time.monotonic() - began)
            return t.address if ok else None

        async def no_ping() -> set[str]:
            return set()

        async def no_multicast() -> dict[str, Announcement]:
            return {}

        # Rede grande: um processo de ping por IP (65 mil numa /16) custa mais que o resto do scan.
        # O ping fica para depois, só nos blocos /24 em que algo já respondeu.
        tcp_results, pinged, announced, gateway = await asyncio.gather(
            gather_limited((partial(tcp_check, t) for t in targets), limit=512 if fast else 128),
            ping_sweep(list(by_ip), self.o.timeout) if self.o.ping and not fast else no_ping(),
            multicast_discover() if self.o.multicast else no_multicast(),
            default_gateway(),
        )
        # A tabela ARP é lida depois: as sondas acima é que a preenchem.
        arp = await read_arp_table() if self.o.mac_lookup else {}
        if fast:
            from collections import Counter

            from tbm.scout.discovery import local_networks

            hits = {ip for ip in tcp_results if ip} | set(arp) | set(announced)
            per_block = Counter(ip.rsplit(".", 1)[0] for ip in hits if ip in by_ip)
            blocks = set(per_block)
            # Na rede local, a própria tentativa de conexão já fez o sistema resolver o ARP de quem
            # está vivo (mesmo com tudo filtrado): o ping só acrescenta algo em blocos roteados.
            local = {n.rsplit(".", 1)[0] for n in local_networks()} if self.o.mac_lookup else set()
            ranked = sorted(blocks - local, key=lambda b: -per_block[b])
            by_block: dict[str, list[str]] = {}
            for ip in by_ip:
                by_block.setdefault(ip.rsplit(".", 1)[0], []).append(ip)
            candidates = [ip for b in ranked for ip in by_block[b] if ip not in hits]
            if len(candidates) > MAX_FAST_PINGS:
                self.p.log(f"ping limitado aos {MAX_FAST_PINGS} endereços dos blocos com mais respostas "
                           f"(de {len(candidates)}); o resto fica com TCP, ARP e multicast")
                candidates = candidates[:MAX_FAST_PINGS]
            if self.o.ping and candidates:
                pinged = await ping_sweep(candidates, self.o.timeout)
                if self.o.mac_lookup:
                    arp = {**arp, **await read_arp_table()}
            if len(rtts) >= 8:  # timeout de conexão pelo RTT medido (nunca acima do pedido)
                p90 = sorted(rtts)[int(len(rtts) * 0.9) - 1]
                self.timeout = max(0.3, min(self.o.timeout, round(4 * p90, 2)))
            self.p.log(f"rede grande ({len(targets)} endereços): descoberta rápida, ping em "
                       f"{len(blocks)} bloco(s) /24 com resposta, timeout {self.timeout:.2f}s")

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
        for target in alive:
            announced_by = self.report.announcements.get(target.address)
            report_found(self.p, target.address, name=announced_by.best_name if announced_by else None,
                         gateway=target.address == self.report.gateway)
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

    async def _attach_ipv6(self, hosts: list[Host]) -> None:
        neighbors = await read_neighbors() if self.o.mac_lookup else {}
        me = local_ipv4()
        mine = await asyncio.to_thread(local_global_addresses)
        for h in hosts:
            addresses = set(neighbors.get(h.mac or "", set()))
            if h.address == me:
                addresses |= set(mine)
            if ann := self.report.announcements.get(h.address):
                addresses |= {a for a in ann.ipv6 if is_global_v6(a)}
            h.ipv6 = sorted(addresses)

        async def probe(h: Host) -> None:
            # Conectar de si para si mesmo não passa pelo firewall: daria "aberta" sempre.
            # Este computador só registra os endereços (prova de que a rede tem IPv6 global).
            if h.address == me:
                return
            tcp = sorted({s.port for s in h.services if s.transport == "tcp"})[:32]
            if h.ipv6 and tcp:
                h.ipv6_services = await open_on_v6(h.ipv6[0], tcp, max(self.o.timeout, 1.0))

        await asyncio.gather(*(probe(h) for h in hosts))

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
            timeout=self.timeout,
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
        name_via = None
        if hostname is None and self.o.reverse_dns:
            hostname = await reverse_dns(target.address)
            name_via = "dns" if hostname else None
        if hostname is None and self.o.local_names:
            if found_name := await local_name(target.address, max(self.o.timeout, 1.0)):
                hostname, name_via = found_name

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

        host = Host(address=target.address, hostname=hostname, services=services + udp_services)
        if name_via:
            host.discovery["name_via"] = name_via
        return host
