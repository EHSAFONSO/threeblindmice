"""Comparação entre dois scans: o que apareceu, o que sumiu, o que persiste."""

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
    opened_ports: list[PortKey] = field(default_factory=list)
    closed_ports: list[PortKey] = field(default_factory=list)
    # Mesmo IP com MAC diferente: troca de aparelho, DHCP... ou ARP spoofing.
    mac_changes: list[tuple[str, str, str]] = field(default_factory=list)
    score_delta: int | None = None

    @property
    def has_changes(self) -> bool:
        return any((self.new_findings, self.resolved_findings, self.new_hosts, self.gone_hosts,
                    self.opened_ports, self.closed_ports, self.mac_changes))


def _comparable(port: PortKey, common_hosts: set[str], tcp: set[int], udp: set[int]) -> bool:
    host, number, transport = port
    return host in common_hosts and number in (udp if transport == "udp" else tcp)


def diff_scans(old: ScanResult | None, new: ScanResult) -> ScanDiff:
    if old is None:
        return ScanDiff(previous_id=None, new_findings=list(new.findings))

    old_f = {f.fingerprint: f for f in old.findings}
    new_f = {f.fingerprint: f for f in new.findings}
    old_hosts = {h.address: h for h in old.hosts}
    new_hosts = {h.address: h for h in new.hosts}
    common = old_hosts.keys() & new_hosts.keys()

    # Só faz sentido dizer que uma porta abriu ou fechou se ela foi testada nos dois scans.
    if old.ports_scanned and new.ports_scanned:
        tcp = set(old.ports_scanned) & set(new.ports_scanned)
    else:
        tcp = {p for _, p, t in old.open_ports | new.open_ports if t == "tcp"}
    udp = set(old.udp_ports_scanned) & set(new.udp_ports_scanned)

    delta = None
    if old.score is not None and new.score is not None:
        delta = new.score - old.score

    return ScanDiff(
        previous_id=old.scan_id,
        new_findings=sorted((f for k, f in new_f.items() if k not in old_f), key=Finding.sort_key),
        resolved_findings=sorted((f for k, f in old_f.items() if k not in new_f), key=Finding.sort_key),
        persisting_findings=sorted((f for k, f in new_f.items() if k in old_f), key=Finding.sort_key),
        new_hosts=[new_hosts[a] for a in sorted(new_hosts.keys() - old_hosts.keys())],
        gone_hosts=[old_hosts[a] for a in sorted(old_hosts.keys() - new_hosts.keys())],
        opened_ports=sorted(p for p in new.open_ports - old.open_ports if _comparable(p, common, tcp, udp)),
        closed_ports=sorted(p for p in old.open_ports - new.open_ports if _comparable(p, common, tcp, udp)),
        mac_changes=sorted(
            (a, old_hosts[a].mac, new_hosts[a].mac)  # type: ignore[misc]
            for a in common
            if old_hosts[a].mac and new_hosts[a].mac and old_hosts[a].mac != new_hosts[a].mac
        ),
        score_delta=delta,
    )
