"""Encadeia Scout → Sniffer → nota → histórico. A CLI e quem usa o tbm como biblioteca chamam isto."""

from __future__ import annotations

import time
from dataclasses import dataclass, replace

from tbm.log import get_logger
from tbm.models import ScanResult, utcnow
from tbm.progress import ProgressHook
from tbm.scope import Scope, Target
from tbm.scout import Scout, ScoutOptions
from tbm.scout.engine import LARGE_NETWORK
from tbm.sniffer import Sniffer, SnifferOptions
from tbm.squeak import HistoryStore, ScanDiff, diff_scans, redact
from tbm.squeak.acceptance import apply_acceptances
from tbm.squeak.diff import mark_novelty
from tbm.squeak.scoring import grade_for, score_findings

log = get_logger(__name__)

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
    start = time.monotonic()
    findings, errors = await Sniffer(options, progress).run(result)
    result.timings["checks"] = round(time.monotonic() - start, 2)
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
        result.errors += scout.errors
        result.timings.update(scout.timings)
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
    scout_options = job.scout_options
    if scout_options.checkpoint is None and (scout_options.resume or len(targets) > LARGE_NETWORK):
        # rede grande: grava o progresso por bloco /24 (`tbm scan --resume` continua daqui)
        from tbm.scout.checkpoint import checkpoint_path

        scout_options = replace(scout_options, checkpoint=checkpoint_path(job.label))
    result = await run_full_scan(
        targets=targets, specs=job.specs, scope_source=job.scope.source, label=job.label,
        scout_options=scout_options, sniffer_options=job.sniffer_options, progress=progress,
    )
    store._hydrate(result)  # nomes e aprovações do cadastro de aparelhos
    if apply_acceptances(result, store.acceptances()):
        finalize(result)  # recalcula a nota sem os riscos aceitos
    if job.no_evidence:
        result = redact(result)
    diff = diff_scans(store.latest(job.label, exclude=result.scan_id), result)
    recent = store.light(job.label, NOVELTY_WINDOW, exclude=result.scan_id)
    mark_novelty(diff, result, recent)
    if job.save:
        store.save(result)
        record_events(store, result, diff)
        remember_network(store, result)
    log.info("scan %s rótulo=%s aparelhos=%d achados=%d nota=%s tempos=%s erros=%d", result.scan_id, result.label,
             len(result.hosts), len(result.findings), result.score, result.timings, len(result.errors))
    for e in result.errors:
        log.debug("erro no scan %s: %s", result.scan_id, e)  # pode citar IP: só em DEBUG
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
