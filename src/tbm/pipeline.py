"""Encadeia Scout → Sniffer → nota → histórico. A CLI e quem usa o tbm como biblioteca chamam isto."""

from __future__ import annotations

from dataclasses import dataclass

from tbm.models import ScanResult, utcnow
from tbm.progress import ProgressHook
from tbm.scope import Scope, Target
from tbm.scout import Scout, ScoutOptions
from tbm.sniffer import Sniffer, SnifferOptions
from tbm.squeak import HistoryStore, ScanDiff, diff_scans, redact
from tbm.squeak.acceptance import apply_acceptances
from tbm.squeak.diff import mark_novelty
from tbm.squeak.scoring import grade_for, score_findings

# Quantos scans anteriores contam para decidir se um dispositivo/porta é inédito.
NOVELTY_WINDOW = 10


def finalize(result: ScanResult) -> ScanResult:
    result.finished_at = utcnow()
    result.score = score_findings(result.findings)
    result.grade = grade_for(result.score)
    return result


async def run_sniffer(
    result: ScanResult, options: SnifferOptions, progress: ProgressHook | None = None
) -> ScanResult:
    findings, errors = await Sniffer(options, progress).run(result)
    result.findings = findings
    result.errors += errors
    return finalize(result)


async def run_full_scan(
    *,
    targets: list[Target],
    specs: list[str],
    scope_source: str,
    label: str,
    scout_options: ScoutOptions,
    sniffer_options: SnifferOptions,
    progress: ProgressHook | None = None,
) -> ScanResult:
    result = ScanResult(
        label=label,
        targets=specs,
        scope=scope_source,
        ports_scanned=scout_options.ports,
        udp_ports_scanned=scout_options.udp_ports if scout_options.udp else [],
    )
    if targets:
        scout = Scout(scout_options, progress)
        result.hosts = await scout.run(targets)
        result.gateway = scout.report.gateway
    return await run_sniffer(result, sniffer_options, progress)


@dataclass
class ScanJob:
    """Tudo o que define um scan repetível (usado por `tbm scan` e `tbm watch`)."""

    specs: list[str]
    scope: Scope
    label: str
    scout_options: ScoutOptions
    sniffer_options: SnifferOptions
    save: bool = True
    no_evidence: bool = False


async def execute(job: ScanJob, store: HistoryStore, progress: ProgressHook | None = None
                  ) -> tuple[ScanResult, ScanDiff]:
    # Resolvemos de novo a cada execução: no watch, um hostname pode mudar de IP,
    # e o novo IP também precisa passar pelo escopo.
    targets = job.scope.resolve(job.specs)
    job.sniffer_options.scope = job.scope
    result = await run_full_scan(
        targets=targets, specs=job.specs, scope_source=job.scope.source, label=job.label,
        scout_options=job.scout_options, sniffer_options=job.sniffer_options, progress=progress,
    )
    store._hydrate(result)  # nomes e aprovações do cadastro de aparelhos
    if apply_acceptances(result, store.acceptances()):
        finalize(result)  # recalcula a nota sem os riscos aceitos
    if job.no_evidence:
        result = redact(result)
    diff = diff_scans(store.latest(job.label, exclude=result.scan_id), result)
    recent = [s for r in store.list(job.label, NOVELTY_WINDOW)
              if r["scan_id"] != result.scan_id and (s := store.get(r["scan_id"])) is not None]
    mark_novelty(diff, result, recent)
    if job.save:
        store.save(result)
        record_events(store, result, diff)
        remember_network(store, result)
    return result, diff


def remember_network(store: HistoryStore, result: ScanResult) -> None:
    """Associa o roteador (MAC) ao rótulo: na próxima vez, a interface sabe em que rede você está."""
    gw = result.host(result.gateway) if result.gateway else None
    if gw is not None and gw.mac:
        store.set_meta(f"net:{gw.mac}", result.label)


async def current_network_label(store: HistoryStore) -> str | None:
    """Rótulo da rede em que este computador está agora (pelo MAC do roteador), se já foi escaneada."""
    from tbm.scout.arp import read_arp_table
    from tbm.scout.discovery import default_gateway

    gw = await default_gateway()
    if not gw:
        return None
    mac = (await read_arp_table()).get(gw)
    return store.meta(f"net:{mac}") if mac else None


def record_events(store: HistoryStore, result: ScanResult, diff: ScanDiff) -> None:
    """Notificações da interface: o que este scan trouxe de novo."""
    label = result.label
    store.add_event("scan_done", {"grade": result.grade, "score": result.score, "delta": diff.score_delta},
                    label=label, link=f"/?label={label}")
    for h in diff.alert_hosts:
        if not h.trusted:
            store.add_event("unknown_device", {"name": h.name or h.device_type or h.address, "address": h.address},
                            label=label, link=f"/device/{label}/{h.address}")
    if diff.resolved_findings:
        store.add_event("resolved", {"n": len(diff.resolved_findings)}, label=label, link=f"/findings/{label}")
