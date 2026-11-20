"""Base da CLI: o app Typer, consoles, progresso, renderização e opções comuns."""

from __future__ import annotations

import asyncio
import os
import re
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

from tbm.config import quiet_hours
from tbm.models import Finding, Host, ScanResult, Severity
from tbm.paths import cache_dir
from tbm.scope import Scope, ScopeError
from tbm.scout import ScoutOptions, parse_ports
from tbm.sniffer import SnifferOptions
from tbm.squeak import HistoryStore, ScanDiff, send_webhook

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
                     no_backport: bool = False, external: bool = False) -> SnifferOptions:
    return SnifferOptions(
        active=active,
        external=external,
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


async def _notify(webhook: str | None, result: ScanResult, diff: ScanDiff, min_severity: Severity,
                  store: HistoryStore | None = None) -> None:
    if not webhook:
        return
    try:
        sent = await send_webhook(webhook, result, diff, min_severity, quiet=quiet_hours())
        console.print("Alerta enviado." if sent else "[dim]Nada novo para alertar.[/]")
    except Exception as exc:  # noqa: BLE001
        err.print(f"[yellow]falha ao enviar webhook: {exc}[/]")
    if store is not None:
        from tbm.squeak import summary

        try:
            if await summary.maybe_send(store, result.label, webhook):
                console.print("Resumo semanal enviado.")
        except Exception as exc:  # noqa: BLE001 (o resumo nunca derruba o scan)
            err.print(f"[yellow]falha ao enviar o resumo semanal: {exc}[/]")


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
ExternalOpt = Annotated[bool, typer.Option("--external", help="Verificações externas: o que a internet vê do seu IP (Shodan InternetDB) e DNS sequestrado. Envia o seu IP público para esses serviços.")]
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

