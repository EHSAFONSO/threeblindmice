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

    @property
    def has_changes(self) -> bool:
        return any((self.new_findings, self.resolved_findings, self.new_hosts, self.gone_hosts,
                    self.opened_ports, self.closed_ports, self.mac_changes, self.ip_changes))


def _ports(host: Host) -> set[tuple[int, str]]:
    return {(s.port, s.transport) for s in host.services}


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
    key = legacy_key if legacy else (lambda f: f.fingerprint)
    old_f = {key(f): f for f in old.findings}
    new_f = {key(f): f for f in new.findings}
    old_by_id = {h.identity: h for h in old.hosts}
    new_by_id = {h.identity: h for h in new.hosts}
    common = old_by_id.keys() & new_by_id.keys()

    # Só faz sentido dizer que uma porta abriu ou fechou se ela foi testada nos dois scans.
    if old.ports_scanned and new.ports_scanned:
        tcp = set(old.ports_scanned) & set(new.ports_scanned)
    else:
        tcp = {p for _, p, t in old.open_ports | new.open_ports if t == "tcp"}
    udp = set(old.udp_ports_scanned) & set(new.udp_ports_scanned)

    def comparable(port: int, transport: str) -> bool:
        return port in (udp if transport == "udp" else tcp)

    opened: list[PortKey] = []
    closed: list[PortKey] = []
    ip_changes: list[tuple[Host, str, str]] = []
    for ident in common:
        o, n = old_by_id[ident], new_by_id[ident]
        if o.address != n.address:
            ip_changes.append((n, o.address, n.address))
        opened += [(n.address, p, t) for p, t in _ports(n) - _ports(o) if comparable(p, t)]
        closed += [(n.address, p, t) for p, t in _ports(o) - _ports(n) if comparable(p, t)]

    old_by_ip = {h.address: h for h in old.hosts}
    new_by_ip = {h.address: h for h in new.hosts}
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
