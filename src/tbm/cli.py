"""CLI `tbm`: o ponto de entrada dos três mice."""

from __future__ import annotations

import asyncio
import os
import re
import sys
import time
from datetime import date, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from tbm import __version__, schedule
from tbm.config import config_path, notify_target, persist_notify
from tbm.models import Finding, Host, ScanResult, Severity
from tbm.paths import cache_dir
from tbm.pipeline import ScanJob, execute, finalize, run_sniffer
from tbm.scope import Scope, ScopeError
from tbm.scout import Scout, ScoutOptions, parse_ports
from tbm.scout.arp import OUIDatabase, download_oui
from tbm.sniffer import REGISTRY, SnifferOptions
from tbm.sniffer.secrets import scan_paths
from tbm.squeak import HistoryStore, ScanDiff, diff_scans, send_webhook, write_report
from tbm.squeak.acceptance import is_active
from tbm.squeak.letter import build_letter
from tbm.squeak.notify import port_label, send_test
from tbm.squeak.telegram import TelegramError, bot_username, find_chats, looks_like_token

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
        self.tasks: dict[str, TaskID] = {}

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
    except ScopeError as exc:
        raise _fail(str(exc)) from exc


def _sniffer_options(active: bool, no_cve: bool, secrets: Path | None, disable: list[str],
                     max_cves: int, scope: Scope, no_epss: bool = False,
                     no_backport: bool = False) -> SnifferOptions:
    return SnifferOptions(
        active=active,
        cve=not no_cve,
        epss=not no_epss,
        backport=not no_backport,
        secrets_path=secrets,
        disabled=set(disable),
        max_cves_per_service=max_cves,
        nvd_api_key=os.environ.get("NVD_API_KEY"),
        cache_dir=cache_dir("intel"),
        scope=scope,
    )


def _scout_options(ports: str, timeout: float, concurrency: int, no_discovery: bool,
                   udp: bool = False, no_mac: bool = False, gentle: bool = False,
                   rate: float | None = None, no_ping: bool = False,
                   no_multicast: bool = False) -> ScoutOptions:
    try:
        port_list = parse_ports(ports)
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    common: dict[str, Any] = dict(timeout=timeout, discovery=not no_discovery, udp=udp,
                                  mac_lookup=not no_mac, ping=not no_ping, multicast=not no_multicast)
    if gentle:
        opts = ScoutOptions.gentle(port_list, **common)
    else:
        opts = ScoutOptions(ports=port_list, concurrency=concurrency, **common)
    if rate:
        opts.rate = rate
    return opts


def parse_interval(text: str) -> int:
    m = re.fullmatch(r"(\d+)\s*([smhd])", text.strip().lower())
    if not m:
        raise ValueError(f"intervalo inválido: {text!r} (use 30m, 6h, 1d)")
    seconds = int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    if seconds < 60:
        raise ValueError("intervalo mínimo: 1 minuto")
    return seconds


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
        label = h.display + (f"\n[dim]{h.mac}[/]" if h.mac else "")
        if not h.services:
            table.add_row(label, "-", "[dim]sem portas abertas[/]", "", "")
        for i, s in enumerate(h.services):
            tls = ""
            if s.tls:
                tls = s.tls.protocol or "tls"
                if s.tls.not_after:
                    tls += f" · até {s.tls.not_after:%Y-%m-%d}"
            port = f"{s.port}/udp" if s.transport == "udp" else str(s.port)
            table.add_row(label if i == 0 else "", port, s.name or "?",
                          " ".join(x for x in (s.product, s.version) if x), tls)
        table.add_section()
    console.print(table)


def print_findings(findings: list[Finding], limit: int = 50, title: str = "Achados") -> None:
    if not findings:
        console.print("[bold green]Nenhum achado.[/]")
        return
    table = Table(title=f"{title} ({len(findings)})", header_style="bold", expand=True)
    table.add_column("Sev.", no_wrap=True)
    table.add_column("Achado", ratio=3)
    table.add_column("Local", no_wrap=True)
    table.add_column("id", no_wrap=True, style="dim")
    for f in findings[:limit]:
        badge = f"[{SEV_STYLE[f.severity]}] {f.severity.value.upper()} [/]"
        if f.kev:
            badge += " [bold red]KEV[/]"
        if f.accepted:
            badge = f"[dim]{f.severity.value.upper()} aceito[/]"
        table.add_row(badge, f"[dim]{f.title}[/]" if f.accepted else f.title, f.location, f.fingerprint[:8])
    console.print(table)
    if len(findings) > limit:
        console.print(f"[dim]… mais {len(findings) - limit} achados no relatório.[/]")
    if any(not f.accepted for f in findings[:limit]):
        console.print("[dim]Risco que você não pode corrigir? tbm accept <id> -l <rótulo> -r \"motivo\"[/]")


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
            f"{len(diff.new_hosts)} dispositivo(s) novo(s), {len(diff.opened_ports)} porta(s) nova(s)"
        )
        lines += [f"  [yellow]+ {h.display}[/]" for h in diff.new_hosts[:5]]
        lines += [f"  [dim]↔ {h.device_name or h.mac}: {a} → {b}[/]" for h, a, b in diff.ip_changes[:5]]
        lines += [f"  [bold red]⚠ MAC de {ip} mudou: {o} → {n}[/]" for ip, o, n in diff.mac_changes]
    accepted = sum(1 for f in result.findings if f.accepted)
    if accepted:
        lines.append(f"[dim]{accepted} risco(s) aceito(s) fora da nota (tbm accepted)[/]")
    if result.errors:
        lines.append(f"[yellow]{len(result.errors)} erro(s) em checks; veja o relatório.[/]")
    console.print(Panel("\n".join(lines), title=f"Squeak · {result.label}", expand=False))


def _exit_code(findings: list[Finding], fail_on: Severity | None) -> int:
    if fail_on and any(f.severity.rank >= fail_on.rank and not f.accepted for f in findings):
        return 1
    return 0


async def _notify(webhook: str | None, result: ScanResult, diff: ScanDiff, min_severity: Severity) -> None:
    if not webhook:
        return
    try:
        sent = await send_webhook(webhook, result, diff, min_severity)
        console.print("Alerta enviado." if sent else "[dim]Nada novo para alertar.[/]")
    except Exception as exc:  # noqa: BLE001
        err.print(f"[yellow]falha ao enviar webhook: {exc}[/]")


# ───────────────────────────── opções comuns ─────────────────────────────

TargetsArg = Annotated[list[str], typer.Argument(help="IPs, CIDRs (10.0.0.0/24), faixas (10.0.0.1-50) ou hostnames.")]
PortsOpt = Annotated[str, typer.Option("--ports", "-p", help="common | web | all | 22,80 | 1-1024")]
ScopeOpt = Annotated[Path | None, typer.Option("--scope", "-s", help="scope.yaml com os alvos autorizados.", exists=True, dir_okay=False)]
LabelOpt = Annotated[str, typer.Option("--label", "-l", help="Nome do ambiente; o diff é feito contra o último scan com o mesmo rótulo.")]
TimeoutOpt = Annotated[float, typer.Option(help="Timeout por conexão, em segundos.")]
ConcOpt = Annotated[int, typer.Option(help="Máximo de sockets simultâneos.")]
NoDiscOpt = Annotated[bool, typer.Option("--no-discovery", "-Pn", help="Não testa se o host está vivo; escaneia todos.")]
UdpOpt = Annotated[bool, typer.Option("--udp", help="Sondas UDP: DNS, NTP, SNMP, SSDP, mDNS.")]
NoMacOpt = Annotated[bool, typer.Option("--no-mac", help="Não lê a tabela ARP (MAC e fabricante).")]
ActiveOpt = Annotated[bool, typer.Option("--active", help="Checks ativos: FTP anônimo, auth SSH, caminhos sensíveis, APIs abertas.")]
NoCveOpt = Annotated[bool, typer.Option("--no-cve", help="Não consulta o NVD.")]
NoEpssOpt = Annotated[bool, typer.Option("--no-epss", help="Não consulta o EPSS (FIRST.org).")]
NoBackportOpt = Annotated[bool, typer.Option("--no-backport", help="Não consulta o tracker da distro.")]
SecretsOpt = Annotated[Path | None, typer.Option("--secrets", help="Também procura segredos neste diretório.", exists=True)]
DisableOpt = Annotated[list[str], typer.Option("--disable", "-x", help="Desativa um check ou grupo (ex.: http, cve.nvd).")]
MaxCvesOpt = Annotated[int, typer.Option(help="Máximo de CVEs por serviço.")]
NotifyOpt = Annotated[str | None, typer.Option(help="Destino do alerta: URL do Discord/Slack, tg://<token>/<chat>, ntfy://<tópico> ou webhook JSON. Padrão: o destino configurado (TBM_WEBHOOK ou tbm gui → Alertas).")]
GentleOpt = Annotated[bool, typer.Option("--gentle", help="Modo cuidadoso para IoT frágil: 16 sockets, 50 conexões/s.")]
RateOpt = Annotated[float | None, typer.Option("--rate", help="Máximo de conexões TCP por segundo.")]
NoPingOpt = Annotated[bool, typer.Option("--no-ping", help="Descoberta sem ping ICMP.")]
NoMcastOpt = Annotated[bool, typer.Option("--no-multicast", help="Descoberta sem mDNS/SSDP por multicast.")]
MinSevOpt = Annotated[Severity, typer.Option(help="Severidade mínima para alertar.")]
NoEvidenceOpt = Annotated[bool, typer.Option("--no-evidence", help="Não grava banners e trechos de evidência (histórico e relatório).")]
VerboseOpt = Annotated[bool, typer.Option("--verbose", "-v")]


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
        sniffer_options=_sniffer_options(active, no_cve, secrets, disable, max_cves, sc, no_epss, no_backport),
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
    _run(_notify(notify or notify_target()[0], result, diff, min_severity))
    raise typer.Exit(_exit_code(result.findings, fail_on))


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
        sniffer_options=_sniffer_options(active, no_cve, None, [], 15, sc),
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
    if d.opened_ports or d.closed_ports:
        console.print("Portas abertas: " + (", ".join(port_label(p) for p in d.opened_ports) or "—"))
        console.print("Portas fechadas: " + (", ".join(port_label(p) for p in d.closed_ports) or "—"))
    if d.new_findings:
        print_findings(d.new_findings, title="[bold red]Novos[/]")
    if d.resolved_findings:
        print_findings(d.resolved_findings, title="[bold green]Resolvidos[/]")


@app.command()
def report(
    scan_id: str,
    output: Annotated[Path, typer.Option("--output", "-o", help=".html, .json ou .sarif")] = Path("relatorio.html"),
) -> None:
    """Gera o relatório de um scan do histórico (com diff contra o anterior)."""
    store = HistoryStore()
    result = _load(store, scan_id)
    previous = store.latest(result.label, exclude=result.scan_id, before=result.started_at.isoformat())
    write_report(result, output, diff_scans(previous, result))
    console.print(f"Relatório salvo em [bold]{output}[/]")


@app.command("report-file")
def report_file(
    input: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o", help=".html, .json ou .sarif")] = Path("relatorio.html"),
) -> None:
    """Gera o relatório a partir de um JSON (saída do scout/sniff)."""
    result = ScanResult.model_validate_json(input.read_text(encoding="utf-8"))
    if result.score is None:
        finalize(result)
    write_report(result, output)
    console.print(f"Relatório salvo em [bold]{output}[/]")


@app.command()
def dashboard(
    host: Annotated[str, typer.Option(help="Interface de escuta. Mantenha 127.0.0.1: o histórico é sensível.")] = "127.0.0.1",
    port: int = 8765,
) -> None:
    """Dashboard web com a evolução da nota e o histórico de scans."""
    try:
        import uvicorn

        from tbm.dashboard import create_app
    except ImportError as exc:
        raise _fail('dependências do dashboard ausentes: pip install -e ".[web]"') from exc
    if host not in ("127.0.0.1", "localhost", "::1"):
        err.print(f"[bold yellow]atenção:[/] escutando em {host}. O dashboard não tem autenticação "
                  "e mostra o inventário da sua rede.")
    console.print(f"Dashboard em [bold]http://{host}:{port}[/] (Ctrl+C para sair)")
    uvicorn.run(create_app(HistoryStore()), host=host, port=port, log_level="warning")


@app.command()
def accept(
    finding_id: Annotated[str, typer.Argument(help="id do achado (coluna 'id', 8+ caracteres) ou fingerprint completo.")],
    reason: Annotated[str, typer.Option("--reason", "-r", help="Por que o risco é aceito.")],
    label: LabelOpt = "default",
    until: Annotated[str | None, typer.Option(help="Validade AAAA-MM-DD. Depois disso o achado volta a contar.")] = None,
) -> None:
    """Aceita um risco: o achado continua no relatório, mas sai da nota e dos alertas."""
    store = HistoryStore()
    latest = store.latest(label)
    if latest is None:
        raise _fail(f"nenhum scan com o rótulo '{label}'")
    matches = [f for f in latest.findings if f.fingerprint.startswith(finding_id)]
    if len(matches) != 1:
        raise _fail(f"{'nenhum' if not matches else len(matches)} achado(s) com id '{finding_id}' "
                    f"no último scan de '{label}'")
    if until:
        try:
            date.fromisoformat(until)
        except ValueError as exc:
            raise _fail("use --until no formato AAAA-MM-DD") from exc
    f = matches[0]
    store.accept(f.fingerprint, reason, until=until, label=label, title=f.title, location=f.location)
    console.print(f"Aceito: [bold]{f.title}[/] ({f.location}){f' até {until}' if until else ''}. "
                  "Vale a partir do próximo scan.")


@app.command()
def accepted() -> None:
    """Lista os riscos aceitos."""
    rows = list(HistoryStore().acceptances().values())
    if not rows:
        console.print("[dim]Nenhum risco aceito.[/]")
        return
    table = Table(header_style="bold")
    for col in ("id", "achado", "local", "motivo", "até", "status"):
        table.add_column(col)
    for r in rows:
        status = "[green]ativo[/]" if is_active(r) else "[yellow]expirado[/]"
        table.add_row(r["fingerprint"][:8], r["title"] or "?", r["location"] or "?", r["reason"],
                      r["until"] or "—", status)
    console.print(table)


@app.command()
def unaccept(finding_id: str) -> None:
    """Desfaz uma aceitação de risco."""
    n = HistoryStore().unaccept(finding_id)
    console.print(f"{n} aceitação(ões) removida(s)." if n else "[yellow]nada encontrado[/]")


@app.command()
def letter(
    host: Annotated[str, typer.Argument(help="IP do equipamento (ex.: o modem da operadora).")],
    label: LabelOpt = "default",
    name: Annotated[str | None, typer.Option(help="Seu nome, para a assinatura.")] = None,
    min_severity: MinSevOpt = Severity.MEDIUM,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Escreve um chamado pronto para o provedor/fabricante com os achados de um equipamento."""
    latest = HistoryStore().latest(label)
    if latest is None:
        raise _fail(f"nenhum scan com o rótulo '{label}'")
    target = latest.host(host)
    if target is None:
        raise _fail(f"{host} não aparece no último scan de '{label}'")
    text = build_letter(latest, target, name=name, min_severity=min_severity)
    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"Carta salva em [bold]{output}[/]")
    else:
        console.print(text, markup=False, highlight=False)


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


@app.command("notify-test")
def notify_test(notify: NotifyOpt = None) -> None:
    """Envia uma mensagem de teste para o destino de alertas configurado."""
    target = notify or notify_target()[0]
    if not target:
        raise _fail("nenhum destino configurado: use tbm telegram-setup, a página Alertas do tbm gui ou --notify")
    try:
        status = _run(send_test(target))
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise _fail(f"falha ao enviar: {exc}") from exc
    # Nunca imprimimos o destino: no Telegram, a URL contém o token do bot.
    if 200 <= status < 300:
        console.print("[green]Mensagem de teste enviada.[/] Confira no app.")
    else:
        hint = {401: "token inválido", 400: "chat_id errado ou você ainda não falou com o bot",
                404: "token ou URL inválidos", 403: "o bot foi bloqueado ou removido do chat"}.get(status, "")
        raise _fail(f"o destino respondeu HTTP {status}{f' ({hint})' if hint else ''}")


@app.command("telegram-setup")
def telegram_setup(
    save: Annotated[bool | None, typer.Option("--save/--no-save", help="Grava o destino sem perguntar (ou não grava).")] = None,
) -> None:
    """Conecta o Telegram: valida o token, acha o chat_id, envia um teste e salva o destino dos alertas."""
    console.print("Crie o bot com o [bold]@BotFather[/] (/newbot) e copie o token.\n"
                  "[dim]O token não aparece na tela enquanto você digita ou cola.[/]")
    token = typer.prompt("Token do bot", hide_input=True).strip()
    if not looks_like_token(token):
        raise _fail("isso não parece um token de bot (formato 123456789:AAH…). Copie de novo do @BotFather.")
    try:
        username = _run(bot_username(token))
    except TelegramError as exc:
        raise _fail(str(exc)) from exc
    console.print(f"Bot encontrado: [bold]@{username}[/]")

    chats = []
    for attempt in range(4):
        try:
            chats = _run(find_chats(token))
        except TelegramError as exc:
            raise _fail(str(exc)) from exc
        if chats:
            break
        if attempt == 3:
            raise _fail(f"nenhuma conversa encontrada. Abra https://t.me/{username}, toque em Iniciar "
                        "e rode o comando de novo.")
        typer.prompt(f"Abra https://t.me/{username} no Telegram, toque em Iniciar (ou mande 'oi') "
                     "e pressione Enter aqui", default="", show_default=False)

    chat = chats[0]
    if len(chats) > 1:
        for i, c in enumerate(chats, 1):
            console.print(f"  {i}. {c.title} [dim]({c.kind}, id {c.id})[/]")
        choice = typer.prompt("Qual conversa deve receber os alertas?", default=1, type=int)
        if not 1 <= choice <= len(chats):
            raise _fail("opção inválida")
        chat = chats[choice - 1]
    console.print(f"Conversa: [bold]{chat.title}[/] [dim]({chat.kind}, id {chat.id})[/]")

    url = f"tg://{token}/{chat.id}"
    status = _run(send_test(url))
    if not 200 <= status < 300:
        raise _fail(f"o Telegram recusou a mensagem de teste (HTTP {status}). O bot foi bloqueado?")
    console.print("[green]Mensagem de teste enviada.[/] Confira no Telegram.")

    if save is None:
        save = typer.confirm("Salvar como destino dos alertas (usado pelos scans, pela interface e pelo agendador)?",
                             default=True)
    if not save:
        console.print("[dim]Nada foi salvo. Use --notify tg://<token>/" + str(chat.id) + " nos comandos.[/]")
        return
    # Grava em TBM_HOME/config.json (só o seu usuário lê). O token não aparece na tela.
    notes = persist_notify(url)
    console.print(f"[green]Salvo[/] em {config_path()}.")
    for n in notes:
        console.print(f"[dim]{n}[/]")


@app.command()
def gui(
    port: Annotated[int, typer.Option(help="Porta local da interface.")] = 8770,
    no_browser: Annotated[bool, typer.Option("--no-browser", help="Não abre o navegador.")] = False,
) -> None:
    """[bold]Interface gráfica[/] no navegador: novo scan, achados, dispositivos e funcionalidades."""
    try:
        import uvicorn

        from tbm.dashboard import create_app
        from tbm.dashboard.security import GuiSettings
    except ImportError as exc:
        raise _fail('dependências da interface ausentes: pip install "threeblindmice[web]"') from exc
    import threading
    import webbrowser

    # Sempre 127.0.0.1 e sem opção de mudar: a interface dispara scans (ver dashboard/security.py).
    settings = GuiSettings(port=port)
    url = settings.login_url()
    console.print(BANNER.format(v=__version__))
    console.print(f"Interface em [bold]{url}[/]")
    console.print("[dim]O link tem um token de sessão: não compartilhe. Ctrl+C para encerrar.[/]")
    if not no_browser:
        threading.Timer(1.2, webbrowser.open, args=(url,)).start()
    uvicorn.run(create_app(HistoryStore(), gui=settings), host="127.0.0.1", port=port, log_level="warning")


@app.command("app")
def desktop_app(
    no_tray: Annotated[bool, typer.Option("--no-tray", help="Sem ícone na bandeja: fechar a janela encerra o app.")] = False,
    smoke: Annotated[bool, typer.Option("--smoke", hidden=True)] = False,
) -> None:
    """[bold]Aplicativo de desktop:[/] a interface numa janela própria, com ícone na bandeja."""
    try:
        import webview  # noqa: F401

        from tbm.desktop.app import DesktopApp
    except ImportError as exc:
        raise _fail('dependências do app ausentes: pip install "threeblindmice[desktop]"') from exc
    runner = DesktopApp(tray_enabled=not no_tray, smoke=smoke)
    code = runner.run()
    if smoke:
        console.print(runner.smoke_result)
    raise typer.Exit(code)


shortcut_app = typer.Typer(help="Atalho para abrir o app sem terminal (menu Iniciar / lançador).")
app.add_typer(shortcut_app, name="shortcut")


@shortcut_app.command("install")
def shortcut_install(
    desktop: Annotated[bool, typer.Option("--desktop", help="Também cria um atalho na Área de Trabalho.")] = False,
) -> None:
    """Cria o atalho "threeblindmice" no menu Iniciar (Windows) ou no lançador (Linux)."""
    from tbm.desktop import shortcut

    icon = None
    try:
        from tbm.desktop.icon import ensure_ico

        icon = ensure_ico()
    except ImportError:
        pass  # sem Pillow: atalho com o ícone padrão do Python
    plan = shortcut.build_plan(sys.platform, desktop=desktop, icon=icon)
    if not plan.supported:
        raise _fail(plan.message)
    try:
        shortcut.install(plan)
    except RuntimeError as exc:
        raise _fail(str(exc)) from exc
    for p in plan.paths:
        console.print(f"[green]Atalho criado:[/] {p}")


@shortcut_app.command("remove")
def shortcut_remove() -> None:
    """Remove os atalhos criados pelo `tbm shortcut install`."""
    from tbm.desktop import shortcut

    removed = shortcut.remove(sys.platform)
    console.print("\n".join(f"Removido: {p}" for p in removed) or "[dim]Nenhum atalho encontrado.[/]")


@app.command("update-oui")
def update_oui() -> None:
    """Baixa a base de fabricantes de placas de rede (IEEE OUI, ~3 MB)."""
    with console.status("Baixando oui.csv do IEEE…"):
        try:
            n = _run(download_oui())
        except Exception as exc:  # noqa: BLE001
            raise _fail(f"falha ao baixar: {exc}") from exc
    console.print(f"[green]{n} fabricantes[/] salvos em {OUIDatabase().path}")


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
