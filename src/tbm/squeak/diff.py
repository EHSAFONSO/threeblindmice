"""Comparação entre dois scans: o que apareceu, o que sumiu, o que persiste."""

from __future__ import annotations

from dataclasses import dataclass, field

from tbm.models import Finding, ScanResult


@dataclass
class ScanDiff:
    previous_id: str | None
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)
    persisting_findings: list[Finding] = field(default_factory=list)
    new_hosts: list[str] = field(default_factory=list)
    gone_hosts: list[str] = field(default_factory=list)
    opened_ports: list[tuple[str, int]] = field(default_factory=list)
    closed_ports: list[tuple[str, int]] = field(default_factory=list)
    score_delta: int | None = None

    @property
    def has_changes(self) -> bool:
        return any((self.new_findings, self.resolved_findings, self.new_hosts, self.gone_hosts,
                    self.opened_ports, self.closed_ports))


def diff_scans(old: ScanResult | None, new: ScanResult) -> ScanDiff:
    if old is None:
        return ScanDiff(previous_id=None, new_findings=list(new.findings))

    old_f = {f.fingerprint: f for f in old.findings}
    new_f = {f.fingerprint: f for f in new.findings}
    old_hosts = {h.address for h in old.hosts}
    new_hosts = {h.address for h in new.hosts}

    # Só faz sentido dizer que uma porta abriu/fechou se ela foi testada nos dois scans.
    if old.ports_scanned and new.ports_scanned:
        both = set(old.ports_scanned) & set(new.ports_scanned)
    else:
        both = {p for _, p in old.open_ports | new.open_ports}
    common_hosts = old_hosts & new_hosts

    delta = None
    if old.score is not None and new.score is not None:
        delta = new.score - old.score

    return ScanDiff(
        previous_id=old.scan_id,
        new_findings=sorted((f for k, f in new_f.items() if k not in old_f), key=Finding.sort_key),
        resolved_findings=sorted(
            (f for k, f in old_f.items() if k not in new_f), key=Finding.sort_key
        ),
        persisting_findings=sorted((f for k, f in new_f.items() if k in old_f), key=Finding.sort_key),
        new_hosts=sorted(new_hosts - old_hosts),
        gone_hosts=sorted(old_hosts - new_hosts),
        # Só comparamos portas de hosts presentes nos dois scans; um host que
        # sumiu já aparece em gone_hosts.
        opened_ports=sorted(
            (h, p) for h, p in new.open_ports - old.open_ports if h in common_hosts and p in both
        ),
        closed_ports=sorted(
            (h, p) for h, p in old.open_ports - new.open_ports if h in common_hosts and p in both
        ),
        score_delta=delta,
    )
