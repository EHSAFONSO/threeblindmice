"""Encadeia Scout → Sniffer → nota → histórico. A CLI e quem usa o tbm como biblioteca chamam isto."""

from __future__ import annotations

from dataclasses import dataclass

from tbm.models import ScanResult, utcnow
from tbm.progress import ProgressHook
from tbm.scope import Scope, Target
from tbm.scout import Scout, ScoutOptions
from tbm.sniffer import Sniffer, SnifferOptions
from tbm.squeak import HistoryStore, ScanDiff, diff_scans, redact
from tbm.squeak.scoring import grade_for, score_findings


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
        result.hosts = await Scout(scout_options, progress).run(targets)
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
    if job.no_evidence:
        result = redact(result)
    diff = diff_scans(store.latest(job.label, exclude=result.scan_id), result)
    if job.save:
        store.save(result)
    return result, diff
