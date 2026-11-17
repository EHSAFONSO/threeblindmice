"""Comparação entre dois scans: o que apareceu, o que sumiu, o que persiste.

Os hosts são casados pela *identidade* (MAC, ou nome anunciado), não pelo IP.
Antes, quando o DHCP trocava o IP de um celular, o diff dizia que um aparelho
"sumiu" e outro "apareceu". Agora ele diz que o aparelho mudou de IP.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tbm.models import Finding, Host, PortKey, ScanResult


@dataclass
class ScanDiff:
    previous_id: str | None
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)
    persisting_findings: list[Finding] = field(default_factory=list)
    new_hosts: list[Host] = field(default_factory=list)
    gone_hosts: list[Host] = field(default_factory=list)
    ip_changes: list[tuple[Host, str, str]] = field(default_factory=list)  # (host novo, IP antigo, IP novo)
    opened_ports: list[PortKey] = field(default_factory=list)
    closed_ports: list[PortKey] = field(default_factory=list)
    # Mesmo IP com MAC diferente: troca de aparelho, DHCP... ou ARP spoofing.
    mac_changes: list[tuple[str, str | None, str | None]] = field(default_factory=list)
    score_delta: int | None = None
    # O que é inédito no histórico recente (ver mark_novelty). None = não calculado.
    novel_hosts: list[Host] | None = None
    novel_ports: list[PortKey] | None = None

    @property
    def alert_hosts(self) -> list[Host]:
        return self.new_hosts if self.novel_hosts is None else self.novel_hosts

    @property
    def alert_ports(self) -> list[PortKey]:
        return self.opened_ports if self.novel_ports is None else self.novel_ports

    @property
    def has_changes(self) -> bool:
        return any((self.new_findings, self.resolved_findings, self.new_hosts, self.gone_hosts,
                    self.opened_ports, self.closed_ports, self.mac_changes, self.ip_changes))


def _ports(host: Host) -> set[tuple[int, str]]:
    return {(s.port, s.transport) for s in host.services}


def mark_novelty(diff: ScanDiff, new: ScanResult, history: list[ScanResult]) -> ScanDiff:
    """Separa o que mudou desde o último scan do que é *inédito* no histórico recente.

    O relatório mostra toda mudança. O alerta só deve tocar para o inédito.
    No teste real, a porta 62078 de um iPhone abria e fechava conforme o
    aparelho dormia, e cada vez que reabria gerava um alerta de "porta nova".
    Celulares que saem e voltam para casa causariam o mesmo com "dispositivo novo".
    """
    seen_devices = {h.identity for s in history for h in s.hosts}
    seen_ports = {(h.identity, svc.port, svc.transport) for s in history for h in s.hosts for svc in h.services}
    by_ip = {h.address: h for h in new.hosts}
    diff.novel_hosts = [h for h in diff.new_hosts if h.identity not in seen_devices]
    diff.novel_ports = [
        p for p in diff.opened_ports
        if p[0] not in by_ip or (by_ip[p[0]].identity, p[1], p[2]) not in seen_ports
    ]
    return diff


def legacy_key(f: Finding) -> str:
    """Chave antiga (por IP), usada só na transição para fingerprints por dispositivo."""
    return f"{f.check_id}|{f.host}|{f.port}|{f.key}"


def diff_scans(old: ScanResult | None, new: ScanResult) -> ScanDiff:
    if old is None:
        return ScanDiff(previous_id=None, new_findings=list(new.findings))

    # Migração: scans gravados antes da v0.3 não têm `device` nos achados, então os
    # fingerprints mudaram. Comparar direto marcaria tudo como novo e resolvido
    # (uma enxurrada de alertas falsos depois do upgrade). Nesse caso, os dois lados
    # usam a chave antiga, por IP, uma única vez.
    legacy = any(f.device is None and f.host != "local" for f in old.findings) and any(
        f.device for f in new.findings)

    # MAC intermitente: se a leitura da tabela ARP falhar num scan (timeout, rede
    # lenta), o mesmo aparelho aparece com identidade "ip:…" num lado e "mac:…" no
    # outro. No teste real, isso gerou "+14 novos, -13 resolvidos" sem nada ter
    # mudado. Mesmo IP, com MAC em só um dos lados, conta como o mesmo aparelho.
    old_by_ip = {h.address: h for h in old.hosts}
    new_by_ip = {h.address: h for h in new.hosts}
    alias: dict[str, str] = {}  # identidade antiga → nova
    for ip in old_by_ip.keys() & new_by_ip.keys():
        o, n = old_by_ip[ip], new_by_ip[ip]
        if o.identity != n.identity and (not o.mac or not n.mac):
            alias[o.identity] = n.identity

    def key(f: Finding, side_old: bool) -> str:
        if legacy:
            return legacy_key(f)
        device = f.device or f.host
        if side_old:
            device = alias.get(device, device)
        return f"{f.check_id}|{device}|{f.port}|{f.key}"

    old_f = {key(f, True): f for f in old.findings}
    new_f = {key(f, False): f for f in new.findings}
    old_by_id = {alias.get(h.identity, h.identity): h for h in old.hosts}
    new_by_id = {h.identity: h for h in new.hosts}
    common = old_by_id.keys() & new_by_id.keys()

    # Só faz sentido dizer que uma porta abriu ou fechou se ela foi testada nos dois scans.
    if old.ports_scanned and new.ports_scanned:
        tcp = set(old.ports_scanned) & set(new.ports_scanned)
    else:
        tcp = {p for _, p, t in old.open_ports | new.open_ports if t == "tcp"}

    def comparable(port: int, transport: str) -> bool:
        # UDP fica de fora: silêncio em UDP é ambíguo (pacote perdido, aparelho em
        # repouso). No teste real, o mDNS de um dispositivo Matter "fechou" e "abriu"
        # entre scans seguidos, o que no `watch` viraria alerta falso. O que importa
        # em UDP já alerta pelos achados (ex.: SNMP 'public' é um achado HIGH novo).
        return transport == "tcp" and port in tcp

    opened: list[PortKey] = []
    closed: list[PortKey] = []
    ip_changes: list[tuple[Host, str, str]] = []
    for ident in common:
        o, n = old_by_id[ident], new_by_id[ident]
        if o.address != n.address:
            ip_changes.append((n, o.address, n.address))
        opened += [(n.address, p, t) for p, t in _ports(n) - _ports(o) if comparable(p, t)]
        closed += [(n.address, p, t) for p, t in _ports(o) - _ports(n) if comparable(p, t)]

    mac_changes = sorted(
        (ip, old_by_ip[ip].mac, new_by_ip[ip].mac)
        for ip in old_by_ip.keys() & new_by_ip.keys()
        if old_by_ip[ip].mac and new_by_ip[ip].mac and old_by_ip[ip].mac != new_by_ip[ip].mac
    )

    delta = None
    if old.score is not None and new.score is not None:
        delta = new.score - old.score

    return ScanDiff(
        previous_id=old.scan_id,
        new_findings=sorted((f for k, f in new_f.items() if k not in old_f), key=Finding.sort_key),
        resolved_findings=sorted((f for k, f in old_f.items() if k not in new_f), key=Finding.sort_key),
        persisting_findings=sorted((f for k, f in new_f.items() if k in old_f), key=Finding.sort_key),
        new_hosts=sorted((new_by_id[i] for i in new_by_id.keys() - old_by_id.keys()), key=lambda h: h.address),
        gone_hosts=sorted((old_by_id[i] for i in old_by_id.keys() - new_by_id.keys()), key=lambda h: h.address),
        ip_changes=sorted(ip_changes, key=lambda c: c[2]),
        opened_ports=sorted(opened),
        closed_ports=sorted(closed),
        mac_changes=mac_changes,
        score_delta=delta,
    )
