"""CLI `tbm`: o ponto de entrada dos três mice."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from tbm import __version__
from tbm.models import Finding, Host, ScanResult, Severity
from tbm.pipeline import finalize, run_full_scan, run_sniffer
from tbm.scope import Scope, ScopeError
from tbm.scout import Scout, ScoutOptions, parse_ports
from tbm.sniffer import REGISTRY, SnifferOptions
from tbm.sniffer.secrets import scan_path
from tbm.squeak import HistoryStore, ScanDiff, diff_scans, send_webhook, tbm_home, write_report

app = typer.Typer(
    name="tbm",
    help="threeblindmice: [bold]Scout[/] (recon) · [bold]Sniffer[/] (análise) · "
    "[bold]Squeak[/] (relatórios).\n\nUse somente em sistemas que você tem autorização para testar.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()
err = Console(stderr=True)

BANNER = r"""[bold magenta]
   ()-()    ()-()    ()-()
    \"/      \"/      \"/      threeblindmice v{v}
     `        `        `      scout · sniffer · squeak
[/]"""

SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
GRADE_STYLE = {"A": "bold green", "B": "green", "C": "yellow", "D": "bold red", "F": "bold white on red"}


# ───────────────────────────── infraestrutura ─────────────────────────────


class RichProgress:
    """Adapta o ProgressHook dos engines para barras do Rich."""

    def __init__(self, progress: Progress, verbose: bool = False) -> None:
        self.progress = progress
        self.verbose = verbose
        self.tasks: dict[str, int] = {}

    def start(self, phase: str, total: int) -> None:
        if phase in self.tasks:  # chamadas repetidas somam ao total
            task_id = self.tasks[phase]
            current = next(t for t in self.progress.tasks if t.id == task_id).total or 0
            self.progress.update(task_id, total=current + total)
        else:
            self.tasks[phase] = self.progress.add_task(phase, total=total)

    def advance(self, phase: str, amount: int = 1) -> None:
        if phase in self.tasks:
            self.progress.advance(self.tasks[phase], amount)

    def log(self, message: str) -> None:
        if self.verbose or "\n" not in message:
            self.progress.console.log(message)


def _progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


def _fail(message: str, code: int = 2) -> typer.Exit:
    err.print(f"[bold red]erro:[/] {message}")
    return typer.Exit(code)


def _scope(scope_file: Path | None) -> Scope:
    try:
        return Scope.from_file(scope_file) if scope_file else Scope.default()
    except ScopeError as exc:
        raise _fail(str(exc)) from exc


def _run(coro):
    try:
        return asyncio.run(coro)
    except KeyboardInterrupt:
        raise _fail("interrompido pelo usuário", 130) from None


def _sniffer_options(active: bool, no_cve: bool, secrets: Path | None, disable: list[str],
                     max_cves: int) -> SnifferOptions:
    return SnifferOptions(
        active=active,
        cve=not no_cve,
        secrets_path=secrets,
        disabled=set(disable),
        max_cves_per_service=max_cves,
        nvd_api_key=os.environ.get("NVD_API_KEY"),
        cache_dir=tbm_home() / "cache" / "nvd",
    )


# ───────────────────────────── renderização ─────────────────────────────


def print_hosts(hosts: list[Host]) -> None:
    if not hosts:
        console.print("[dim]Nenhum host encontrado.[/]")
        return
    table = Table(title="Inventário", header_style="bold", expand=True)
    table.add_column("Host")
    table.add_column("Porta", justify="right")
    table.add_column("Serviço")
    table.add_column("Produto")
    table.add_column("TLS")
    for h in hosts:
        if not h.services:
            table.add_row(h.display, "-", "[dim]sem portas abertas[/]", "", "")
        for i, s in enumerate(h.services):
            tls = ""
            if s.tls:
                tls = s.tls.protocol or "tls"
                if s.tls.not_after:
                    tls += f" · até {s.tls.not_after:%Y-%m-%d}"
            table.add_row(h.display if i == 0 else "", str(s.port), s.name or "?",
                          " ".join(x for x in (s.product, s.version) if x), tls)
        table.add_section()
    console.print(table)


def print_findings(findings: list[Finding], limit: int = 50) -> None:
    if not findings:
        console.print("[bold green]Nenhum achado.[/]")
        return
    table = Table(title=f"Achados ({len(findings)})", header_style="bold", expand=True)
    table.add_column("Sev.", no_wrap=True)
    table.add_column("Achado", ratio=3)
    table.add_column("Local", no_wrap=True)
    for f in findings[:limit]:
        table.add_row(f"[{SEV_STYLE[f.severity]}] {f.severity.value.upper()} [/]", f.title, f.location)
    console.print(table)
    if len(findings) > limit:
        console.print(f"[dim]… mais {len(findings) - limit} achados no relatório.[/]")


def print_summary(result: ScanResult, diff: ScanDiff | None = None) -> None:
    counts = " · ".join(
        f"[{SEV_STYLE[s]}]{n} {s.value}[/]" for s, n in result.severity_counts().items() if n
    ) or "[green]nenhum achado[/]"
    delta = ""
    if diff and diff.score_delta:
        color = "green" if diff.score_delta > 0 else "red"
        delta = f" [{color}]({diff.score_delta:+d})[/]"
    lines = [
        f"Nota: [{GRADE_STYLE.get(result.grade or 'F')}] {result.grade} [/] "
        f"{result.score}/100{delta}",
        f"Hosts: {len(result.hosts)} · portas abertas: {len(result.open_ports)}",
        f"Achados: {counts}",
    ]
    if diff and diff.previous_id:
        lines.append(
            f"Desde [cyan]{diff.previous_id}[/]: [red]+{len(diff.new_findings)}[/] novos, "
            f"[green]-{len(diff.resolved_findings)}[/] resolvidos, "
            f"{len(diff.new_hosts)} hosts novos, {len(diff.opened_ports)} portas novas"
        )
    if result.errors:
        lines.append(f"[yellow]{len(result.errors)} erro(s) em checks; veja o relatório.[/]")
    console.print(Panel("\n".join(lines), title=f"Squeak · {result.label}", expand=False))


def _exit_code(findings: list[Finding], fail_on: Severity | None) -> int:
    if fail_on and any(f.severity.rank >= fail_on.rank for f in findings):
        return 1
    return 0


# ───────────────────────────── opções comuns ─────────────────────────────

TargetsArg = Annotated[list[str], typer.Argument(help="IPs, CIDRs (10.0.0.0/24), faixas (10.0.0.1-50) ou hostnames.")]
PortsOpt = Annotated[str, typer.Option("--ports", "-p", help="common | web | all | 22,80 | 1-1024")]
ScopeOpt = Annotated[Path | None, typer.Option("--scope", "-s", help="scope.yaml com os alvos autorizados.", exists=True, dir_okay=False)]
TimeoutOpt = Annotated[float, typer.Option(help="Timeout por conexão, em segundos.")]
ConcOpt = Annotated[int, typer.Option(help="Máximo de sockets simultâneos.")]
NoDiscOpt = Annotated[bool, typer.Option("--no-discovery", "-Pn", help="Não testa se o host está vivo; escaneia todos.")]
ActiveOpt = Annotated[bool, typer.Option("--active", help="Checks ativos: FTP anônimo, caminhos sensíveis, APIs abertas.")]
NoCveOpt = Annotated[bool, typer.Option("--no-cve", help="Não consulta o NVD.")]
SecretsOpt = Annotated[Path | None, typer.Option("--secrets", help="Também procura segredos neste diretório.", exists=True)]
DisableOpt = Annotated[list[str], typer.Option("--disable", "-x", help="Desativa um check ou grupo (ex.: http, cve.nvd).")]
MaxCvesOpt = Annotated[int, typer.Option(help="Máximo de CVEs por serviço.")]
VerboseOpt = Annotated[bool, typer.Option("--verbose", "-v")]


def _scout_options(ports: str, timeout: float, concurrency: int, no_discovery: bool) -> ScoutOptions:
    try:
        port_list = parse_ports(ports)
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    return ScoutOptions(ports=port_list, timeout=timeout, concurrency=concurrency,
                        discovery=not no_discovery)


# ───────────────────────────── comandos ─────────────────────────────


@app.command()
def scan(
    targets: TargetsArg,
    ports: PortsOpt = "common",
    scope: ScopeOpt = None,
    label: Annotated[str, typer.Option("--label", "-l", help="Nome do ambiente; o diff é feito contra o último scan com o mesmo rótulo.")] = "default",
    timeout: TimeoutOpt = 1.0,
    concurrency: ConcOpt = 400,
    no_discovery: NoDiscOpt = False,
    active: ActiveOpt = False,
    no_cve: NoCveOpt = False,
    secrets: SecretsOpt = None,
    disable: DisableOpt = [],  # noqa: B006 (typer exige lista literal)
    max_cves: MaxCvesOpt = 15,
    report: Annotated[Path | None, typer.Option("--report", "-o", help="Caminho do relatório (.html ou .json).")] = None,
    notify: Annotated[str | None, typer.Option(help="URL de webhook (Discord, Slack ou genérico). Também lê TBM_WEBHOOK.")] = None,
    min_severity: Annotated[Severity, typer.Option(help="Severidade mínima para alertar.")] = Severity.MEDIUM,
    fail_on: Annotated[Severity | None, typer.Option(help="Sai com código 1 se houver achado com esta severidade ou maior (bom para CI).")] = None,
    no_save: Annotated[bool, typer.Option("--no-save", help="Não grava no histórico.")] = False,
    verbose: VerboseOpt = False,
) -> None:
    """[bold]Os três juntos:[/] Scout → Sniffer → Squeak (nota, diff, relatório, alerta)."""
    console.print(BANNER.format(v=__version__))
    sc = _scope(scope)
    try:
        resolved = sc.resolve(targets)
    except ScopeError as exc:
        raise _fail(str(exc)) from exc
    scout_opts = _scout_options(ports, timeout, concurrency, no_discovery)
    sniff_opts = _sniffer_options(active, no_cve, secrets, disable, max_cves)
    console.print(f"[dim]Escopo: {sc.source} · {len(resolved)} alvo(s) · "
                  f"{len(scout_opts.ports)} porta(s) · checks ativos: {'sim' if active else 'não'}[/]")

    with _progress() as prog:
        result = _run(run_full_scan(
            targets=resolved, specs=targets, scope_source=sc.source, label=label,
            scout_options=scout_opts, sniffer_options=sniff_opts,
            progress=RichProgress(prog, verbose),
        ))

    store = HistoryStore()
    diff = diff_scans(store.latest(label, exclude=result.scan_id), result)
    if not no_save:
        store.save(result)

    print_hosts(result.hosts)
    print_findings(result.findings)
    print_summary(result, diff)

    out = report or Path("reports") / f"tbm-{label}-{result.started_at:%Y%m%d-%H%M%S}.html"
    write_report(result, out, diff)
    console.print(f"Relatório: [link=file://{out.resolve()}]{out}[/]  ·  scan_id [cyan]{result.scan_id}[/]")

    webhook = notify or os.environ.get("TBM_WEBHOOK")
    if webhook:
        try:
            sent = _run(send_webhook(webhook, result, diff, min_severity))
            console.print("Alerta enviado." if sent else "[dim]Nada novo para alertar.[/]")
        except Exception as exc:  # noqa: BLE001
            err.print(f"[yellow]falha ao enviar webhook: {exc}[/]")

    raise typer.Exit(_exit_code(result.findings, fail_on))


@app.command()
def scout(
    targets: TargetsArg,
    ports: PortsOpt = "common",
    scope: ScopeOpt = None,
    timeout: TimeoutOpt = 1.0,
    concurrency: ConcOpt = 400,
    no_discovery: NoDiscOpt = False,
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("scout.json"),
    verbose: VerboseOpt = False,
) -> None:
    """[bold]Scout:[/] só reconhecimento. Salva um JSON para o Sniffer analisar depois."""
    sc = _scope(scope)
    try:
        resolved = sc.resolve(targets)
    except ScopeError as exc:
        raise _fail(str(exc)) from exc
    opts = _scout_options(ports, timeout, concurrency, no_discovery)
    result = ScanResult(targets=targets, scope=sc.source, ports_scanned=opts.ports)
    with _progress() as prog:
        result.hosts = _run(Scout(opts, RichProgress(prog, verbose)).run(resolved))
    print_hosts(result.hosts)
    output.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    console.print(f"Salvo em [bold]{output}[/]. Próximo passo: [cyan]tbm sniff {output}[/]")


@app.command()
def sniff(
    input: Annotated[Path, typer.Argument(help="JSON gerado pelo `tbm scout`.", exists=True, dir_okay=False)],
    active: ActiveOpt = False,
    no_cve: NoCveOpt = False,
    secrets: SecretsOpt = None,
    disable: DisableOpt = [],  # noqa: B006
    max_cves: MaxCvesOpt = 15,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Padrão: sobrescreve o arquivo de entrada.")] = None,
    verbose: VerboseOpt = False,
) -> None:
    """[bold]Sniffer:[/] analisa um resultado do Scout e gera achados."""
    result = ScanResult.model_validate_json(input.read_text(encoding="utf-8"))
    opts = _sniffer_options(active, no_cve, secrets, disable, max_cves)
    with _progress() as prog:
        result = _run(run_sniffer(result, opts, RichProgress(prog, verbose)))
    print_findings(result.findings)
    print_summary(result)
    out = output or input
    out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    console.print(f"Salvo em [bold]{out}[/]. Relatório: [cyan]tbm report-file {out} -o relatorio.html[/]")


@app.command("secrets")
def secrets_cmd(
    path: Annotated[Path, typer.Argument(exists=True, help="Diretório ou arquivo a varrer.")],
    fail: Annotated[bool, typer.Option("--fail/--no-fail", help="Sai com código 1 se encontrar algo (para pre-commit/CI).")] = True,
) -> None:
    """Procura credenciais vazadas em código e configs (sem rede)."""
    findings = sorted(scan_path(path), key=Finding.sort_key)
    if not findings:
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
    raise typer.Exit(1 if fail else 0)


@app.command()
def history(
    label: Annotated[str | None, typer.Option("--label", "-l")] = None,
    limit: int = 20,
) -> None:
    """Lista os scans gravados."""
    rows = HistoryStore().list(label, limit)
    if not rows:
        console.print("[dim]Histórico vazio.[/]")
        return
    table = Table(header_style="bold")
    for col in ("scan_id", "rótulo", "quando", "nota", "hosts", "achados"):
        table.add_column(col)
    for r in rows:
        grade = r["grade"] or "-"
        table.add_row(r["scan_id"], r["label"], r["started_at"][:19].replace("T", " "),
                      f"[{GRADE_STYLE.get(grade, '')}]{grade}[/] {r['score']}",
                      str(r["hosts"]), str(r["findings"]))
    console.print(table)


def _load(store: HistoryStore, scan_id: str) -> ScanResult:
    try:
        result = store.get(scan_id)
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    if result is None:
        raise _fail(f"scan não encontrado: {scan_id}")
    return result


@app.command()
def diff(old: str, new: str) -> None:
    """Compara dois scans do histórico."""
    store = HistoryStore()
    a, b = _load(store, old), _load(store, new)
    d = diff_scans(a, b)
    print_summary(b, d)
    if d.new_findings:
        console.print("[bold red]Novos[/]")
        print_findings(d.new_findings)
    if d.resolved_findings:
        console.print("[bold green]Resolvidos[/]")
        print_findings(d.resolved_findings)


@app.command()
def report(
    scan_id: str,
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("relatorio.html"),
) -> None:
    """Gera o relatório de um scan do histórico (com diff contra o anterior)."""
    store = HistoryStore()
    result = _load(store, scan_id)
    previous = store.latest(result.label, exclude=result.scan_id)
    if previous and previous.started_at > result.started_at:
        previous = None
    write_report(result, output, diff_scans(previous, result))
    console.print(f"Relatório salvo em [bold]{output}[/]")


@app.command("report-file")
def report_file(
    input: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("relatorio.html"),
) -> None:
    """Gera o relatório a partir de um JSON (saída do scout/sniff)."""
    result = ScanResult.model_validate_json(input.read_text(encoding="utf-8"))
    if result.score is None:
        finalize(result)
    write_report(result, output)
    console.print(f"Relatório salvo em [bold]{output}[/]")


@app.command()
def checks() -> None:
    """Lista os checks disponíveis no Sniffer."""
    table = Table(header_style="bold")
    table.add_column("id")
    table.add_column("descrição")
    table.add_column("modo")
    for cid, cls in sorted(REGISTRY.items()):
        mode = "[yellow]ativo (--active)[/]" if cls.active_only else "passivo"
        if cid == "secrets.local":
            mode = "com --secrets"
        table.add_row(cid, cls.name, mode)
    console.print(table)


@app.callback(invoke_without_command=True)
def main(
    version: Annotated[bool, typer.Option("--version", help="Mostra a versão.")] = False,
) -> None:
    if version:
        console.print(f"threeblindmice {__version__}")
        raise typer.Exit()
    if sys.platform == "win32":
        # Evita "Event loop is closed" ruidoso no Proactor ao sair.
        import warnings

        warnings.filterwarnings("ignore", category=ResourceWarning)
