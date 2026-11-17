"""Encadeia Scout → Sniffer → nota. A CLI e quem usar o tbm como biblioteca chamam isto."""

from __future__ import annotations

from tbm.models import ScanResult, utcnow
from tbm.progress import ProgressHook
from tbm.scope import Target
from tbm.scout import Scout, ScoutOptions
from tbm.sniffer import Sniffer, SnifferOptions
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
    result = ScanResult(label=label, targets=specs, scope=scope_source,
                        ports_scanned=scout_options.ports)
    if targets:
        result.hosts = await Scout(scout_options, progress).run(targets)
    return await run_sniffer(result, sniffer_options, progress)
