"""Comandos de varredura: scan, scout, sniff e secrets."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from tbm import __version__
from tbm.cli.common import (
    BANNER,
    SEV_STYLE,
    ActiveOpt,
    ConcOpt,
    DisableOpt,
    ExternalOpt,
    GentleOpt,
    LabelOpt,
    MaxCvesOpt,
    MinSevOpt,
    NoBackportOpt,
    NoCveOpt,
    NoDiscOpt,
    NoEpssOpt,
    NoEvidenceOpt,
    NoMacOpt,
    NoMcastOpt,
    NoPingOpt,
    NotifyOpt,
    PortsOpt,
    RateOpt,
    RichProgress,
    ScopeOpt,
    SecretsOpt,
    TargetsArg,
    TimeoutOpt,
    UdpOpt,
    VerboseOpt,
    _exit_code,
    _fail,
    _notify,
    _progress,
    _run,
    _scope,
    _scout_options,
    _sniffer_options,
    app,
    console,
    print_findings,
    print_hosts,
    print_summary,
)
from tbm.config import notify_target
from tbm.models import Finding, ScanResult, Severity
from tbm.pipeline import ScanJob, execute, finalize, run_sniffer
from tbm.scope import ScopeError
from tbm.scout import Scout
from tbm.sniffer.secrets import scan_paths
from tbm.squeak import HistoryStore, write_report

# ───────────────────────────── comandos ─────────────────────────────


@app.command()
def scan(
    targets: TargetsArg,
    ports: PortsOpt = "common",
    scope: ScopeOpt = None,
    label: LabelOpt = "default",
    timeout: TimeoutOpt = 1.0,
    concurrency: ConcOpt = 400,
    no_discovery: NoDiscOpt = False,
    udp: UdpOpt = False,
    no_mac: NoMacOpt = False,
    active: ActiveOpt = False,
    no_cve: NoCveOpt = False,
    no_epss: NoEpssOpt = False,
    no_backport: NoBackportOpt = False,
    external: ExternalOpt = False,
    secrets: SecretsOpt = None,
    disable: DisableOpt = [],  # noqa: B006 (typer exige lista literal)
    max_cves: MaxCvesOpt = 15,
    report: Annotated[Path | None, typer.Option("--report", "-o", help="Caminho do relatório (.html, .json ou .sarif).")] = None,
    notify: NotifyOpt = None,
    min_severity: MinSevOpt = Severity.MEDIUM,
    fail_on: Annotated[Severity | None, typer.Option(help="Sai com código 1 se houver achado com esta severidade ou maior (bom para CI).")] = None,
    no_save: Annotated[bool, typer.Option("--no-save", help="Não grava no histórico.")] = False,
    no_evidence: NoEvidenceOpt = False,
    gentle: GentleOpt = False,
    rate: RateOpt = None,
    no_ping: NoPingOpt = False,
    no_multicast: NoMcastOpt = False,
    verbose: VerboseOpt = False,
) -> None:
    """[bold]Os três juntos:[/] Scout → Sniffer → Squeak (nota, diff, relatório, alerta)."""
    console.print(BANNER.format(v=__version__))
    sc = _scope(scope)
    job = ScanJob(
        specs=targets, scope=sc, label=label, save=not no_save, no_evidence=no_evidence,
        scout_options=_scout_options(ports, timeout, concurrency, no_discovery, udp, no_mac,
                                     gentle, rate, no_ping, no_multicast),
        sniffer_options=_sniffer_options(active, no_cve, secrets, disable, max_cves, sc, no_epss, no_backport,
                                         external),
    )
    console.print(f"[dim]Escopo: {sc.source} · {len(job.scout_options.ports)} porta(s) TCP"
                  f"{' + UDP' if udp else ''} · checks ativos: {'sim' if active else 'não'}"
                  f"{' · modo gentil' if gentle else ''}[/]")

    store = HistoryStore()
    with _progress() as prog:
        result, diff = _run(execute(job, store, RichProgress(prog, verbose)))

    print_hosts(result.hosts)
    print_findings(result.findings)
    print_summary(result, diff)

    out = report or Path("reports") / f"tbm-{label}-{result.started_at:%Y%m%d-%H%M%S}.html"
    write_report(result, out, diff)
    console.print(f"Relatório: [link=file://{out.resolve()}]{out}[/]  ·  scan_id [cyan]{result.scan_id}[/]")
    _run(_notify(notify or notify_target()[0], result, diff, min_severity, store))
    raise typer.Exit(_exit_code(result.findings, fail_on))


@app.command()
def scout(
    targets: TargetsArg,
    ports: PortsOpt = "common",
    scope: ScopeOpt = None,
    timeout: TimeoutOpt = 1.0,
    concurrency: ConcOpt = 400,
    no_discovery: NoDiscOpt = False,
    udp: UdpOpt = False,
    no_mac: NoMacOpt = False,
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("scout.json"),
    verbose: VerboseOpt = False,
) -> None:
    """[bold]Scout:[/] só reconhecimento. Salva um JSON para o Sniffer analisar depois."""
    sc = _scope(scope)
    try:
        resolved = sc.resolve(targets)
    except ScopeError as exc:
        raise _fail(str(exc)) from exc
    opts = _scout_options(ports, timeout, concurrency, no_discovery, udp, no_mac)
    result = ScanResult(targets=targets, scope=sc.source, ports_scanned=opts.ports,
                        udp_ports_scanned=opts.udp_ports if udp else [])
    with _progress() as prog:
        result.hosts = _run(Scout(opts, RichProgress(prog, verbose)).run(resolved))
    print_hosts(result.hosts)
    output.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    console.print(f"Salvo em [bold]{output}[/]. Próximo passo: [cyan]tbm sniff {output}[/]")


@app.command()
def sniff(
    input: Annotated[Path, typer.Argument(help="JSON gerado pelo `tbm scout`.", exists=True, dir_okay=False)],
    scope: ScopeOpt = None,
    active: ActiveOpt = False,
    no_cve: NoCveOpt = False,
    secrets: SecretsOpt = None,
    disable: DisableOpt = [],  # noqa: B006
    max_cves: MaxCvesOpt = 15,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Padrão: sobrescreve o arquivo de entrada.")] = None,
    verbose: VerboseOpt = False,
) -> None:
    """[bold]Sniffer:[/] analisa um resultado do Scout e gera achados.

    Os hosts do JSON são revalidados contra o escopo: um arquivo editado à mão
    não consegue apontar os checks para alvos não autorizados.
    """
    result = ScanResult.model_validate_json(input.read_text(encoding="utf-8"))
    sc = _scope(scope)
    opts = _sniffer_options(active, no_cve, secrets, disable, max_cves, sc)
    with _progress() as prog:
        result = _run(run_sniffer(result, opts, RichProgress(prog, verbose)))
    print_findings(result.findings)
    print_summary(result)
    out = output or input
    out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    console.print(f"Salvo em [bold]{out}[/]. Relatório: [cyan]tbm report-file {out} -o relatorio.html[/]")


@app.command("secrets")
def secrets_cmd(
    paths: Annotated[list[Path], typer.Argument(exists=True, help="Diretórios ou arquivos a varrer.")],
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Exporta .sarif (GitHub), .json ou .html.")] = None,
    fail: Annotated[bool, typer.Option("--fail/--no-fail", help="Sai com código 1 se encontrar algo (para pre-commit/CI).")] = True,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Só imprime se encontrar algo.")] = False,
) -> None:
    """Procura credenciais vazadas em código e configs (sem rede).

    Falsos positivos: comente [cyan]tbm:allow[/] na linha ou liste caminhos no [cyan].tbmignore[/].
    """
    findings = sorted(scan_paths(paths), key=Finding.sort_key)
    if output:
        result = finalize(ScanResult(label="secrets", targets=[str(p) for p in paths], findings=findings))
        write_report(result, output)
        if not quiet:
            console.print(f"Exportado para [bold]{output}[/]")
    if not findings:
        if not quiet:
            console.print("[bold green]Nenhum segredo encontrado.[/]")
        raise typer.Exit(0)
    table = Table(title=f"Segredos ({len(findings)})", header_style="bold", expand=True)
    table.add_column("Sev.", no_wrap=True)
    table.add_column("Tipo")
    table.add_column("Onde (valor mascarado)", ratio=3)
    for f in findings:
        table.add_row(f"[{SEV_STYLE[f.severity]}] {f.severity.value.upper()} [/]",
                      f.title.split(" em ")[0], f.evidence)
    console.print(table)
    console.print("[dim]Falso positivo? Adicione 'tbm:allow' num comentário da linha ou o caminho no .tbmignore.[/]")
    raise typer.Exit(1 if fail else 0)
