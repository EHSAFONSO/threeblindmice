"""Monitoramento contínuo: watch e o agendador do sistema (schedule)."""

from __future__ import annotations

import asyncio
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer

from tbm import __version__, schedule
from tbm.cli.common import (
    BANNER,
    GRADE_STYLE,
    ActiveOpt,
    ExternalOpt,
    GentleOpt,
    LabelOpt,
    MinSevOpt,
    NoCveOpt,
    NoEvidenceOpt,
    NotifyOpt,
    PortsOpt,
    ScopeOpt,
    TargetsArg,
    UdpOpt,
    _fail,
    _notify,
    _scope,
    _scout_options,
    _sniffer_options,
    app,
    console,
    err,
    parse_interval,
)
from tbm.config import notify_target
from tbm.models import Severity
from tbm.pipeline import ScanJob, execute
from tbm.scope import Scope, ScopeError
from tbm.squeak import HistoryStore, write_report


@app.command()
def watch(
    targets: TargetsArg,
    every: Annotated[str, typer.Option("--every", "-e", help="Intervalo entre scans: 30m, 6h, 1d.")] = "6h",
    ports: PortsOpt = "common",
    scope: ScopeOpt = None,
    label: LabelOpt = "default",
    udp: UdpOpt = False,
    active: ActiveOpt = False,
    no_cve: NoCveOpt = False,
    external: ExternalOpt = False,
    notify: NotifyOpt = None,
    min_severity: MinSevOpt = Severity.MEDIUM,
    no_evidence: NoEvidenceOpt = False,
    gentle: GentleOpt = False,
    runs: Annotated[int, typer.Option(help="Para depois de N execuções (0 = infinito).")] = 0,
) -> None:
    """Scan periódico neste terminal. Para rodar em segundo plano, use [cyan]tbm schedule install[/]."""
    try:
        interval = parse_interval(every)
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    sc = _scope(scope)
    sc.resolve(targets)  # falha cedo se o escopo estiver errado
    webhook = notify or notify_target()[0]
    job = ScanJob(
        specs=targets, scope=sc, label=label, no_evidence=no_evidence,
        scout_options=_scout_options(ports, 1.0, 400, False, udp, gentle=gentle),
        sniffer_options=_sniffer_options(active, no_cve, None, [], 15, sc, external=external),
    )
    store = HistoryStore()
    console.print(BANNER.format(v=__version__))
    console.print(f"Vigiando [bold]{', '.join(targets)}[/] a cada {every} · rótulo [cyan]{label}[/] · "
                  f"alertas: {'webhook' if webhook else '[yellow]nenhum (use --notify)[/]'} · Ctrl+C para sair")
    count = 0
    try:
        while True:
            count += 1
            stamp = datetime.now().strftime("%d/%m %H:%M")
            try:
                result, diff = asyncio.run(execute(job, store))
            except ScopeError as exc:
                raise _fail(str(exc)) from exc
            except Exception as exc:  # noqa: BLE001 (o vigia não pode morrer por um erro transitório)
                err.print(f"[{stamp}] [red]scan falhou:[/] {exc}")
            else:
                changes = (f"[red]+{len(diff.new_findings)}[/] [green]-{len(diff.resolved_findings)}[/] "
                           f"· {len(diff.new_hosts)} dispositivo(s) novo(s)") if diff.previous_id else "primeiro scan"
                console.print(f"[{stamp}] nota [{GRADE_STYLE.get(result.grade or 'F')}]{result.grade}[/] "
                              f"{result.score}/100 · {changes}")
                write_report(result, Path("reports") / f"tbm-{label}-latest.html", diff)
                asyncio.run(_notify(webhook, result, diff, min_severity))
            if runs and count >= runs:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\nVigia encerrado.")


schedule_app = typer.Typer(help="Agenda scans periódicos no agendador do sistema operacional.")


app.add_typer(schedule_app, name="schedule")


@schedule_app.command("install")
def schedule_install(
    targets: TargetsArg,
    every: Annotated[str, typer.Option("--every", "-e", help="Intervalo: 30m, 6h, 1d.")] = "6h",
    label: LabelOpt = "default",
    notify: NotifyOpt = None,
    udp: UdpOpt = False,
    gentle: GentleOpt = False,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Só mostra o que seria feito.")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Não pede confirmação.")] = False,
) -> None:
    """Registra um `tbm scan` periódico (Agendador de Tarefas, systemd --user ou cron)."""
    try:
        seconds = parse_interval(every)
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    Scope.default().resolve(targets)  # o agendamento usa o escopo padrão (redes privadas)
    extra = [*(["--udp"] if udp else []), *(["--gentle"] if gentle else []),
             *(["--notify", notify] if notify else [])]
    plan = schedule.build_plan(sys.platform, targets, label, seconds, extra)
    console.print(f"[bold]{plan.platform}[/]: {plan.description}")
    for path, content in plan.files.items():
        console.print(f"[dim]arquivo {path}:[/]\n{content}", markup=False)
    for cmd in plan.commands:
        console.print("$ " + " ".join(cmd), markup=False, highlight=False)
    for w in plan.warnings:
        err.print(f"[yellow]atenção:[/] {w}")
    if plan.manual:
        console.print(plan.manual, markup=False)
    if dry_run or not plan.commands:
        return
    if not yes and not typer.confirm("Criar o agendamento?"):
        raise typer.Exit(1)
    try:
        schedule.execute(plan)
    except RuntimeError as exc:
        raise _fail(str(exc)) from exc
    console.print("[green]Agendado.[/] Remova com [cyan]tbm schedule remove -l " + label + "[/]")


@schedule_app.command("remove")
def schedule_remove(
    label: LabelOpt = "default",
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
) -> None:
    """Remove o agendamento de um rótulo."""
    plan = schedule.remove_plan(sys.platform, label)
    for cmd in plan.commands:
        console.print("$ " + " ".join(cmd), markup=False, highlight=False)
    if plan.manual:
        console.print(plan.manual, markup=False)
    if plan.commands and (yes or typer.confirm("Remover?")):
        try:
            schedule.execute(plan)
        except RuntimeError as exc:
            raise _fail(str(exc)) from exc
        console.print("[green]Removido.[/]")
