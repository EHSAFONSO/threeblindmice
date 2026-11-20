"""Histórico: listar, limpar, comparar, relatórios e riscos aceitos."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from tbm.cli.common import GRADE_STYLE, LabelOpt, _fail, app, console, print_findings, print_summary
from tbm.models import ScanResult
from tbm.pipeline import finalize
from tbm.squeak import HistoryStore, diff_scans, write_report
from tbm.squeak.acceptance import is_active
from tbm.squeak.notify import port_label

history_app = typer.Typer(help="Lista os scans gravados (e limpa os antigos com `prune`).")


app.add_typer(history_app, name="history")


@history_app.command("prune")
def history_prune(
    keep_days: Annotated[int, typer.Option(help="Guarda todos os scans destes últimos dias.")] = 30,
    weekly_days: Annotated[int, typer.Option(help="Até aqui, 1 scan por semana; depois, 1 por mês.")] = 365,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Só mostra quantos sairiam.")] = False,
    vacuum: Annotated[bool, typer.Option("--vacuum", help="Compacta o arquivo depois (pode demorar).")] = False,
) -> None:
    """Apaga scans antigos do histórico. O mais recente de cada rótulo nunca sai."""
    store = HistoryStore()
    gone = store.prune(keep_days=keep_days, weekly_until_days=weekly_days, dry_run=dry_run)
    if dry_run:
        console.print(f"{len(gone)} scan(s) sairiam do histórico.")
        return
    if vacuum and gone:
        store.vacuum()
    console.print(f"[green]{len(gone)} scan(s) antigo(s) apagado(s).[/]")


@history_app.callback(invoke_without_command=True)
def history(
    ctx: typer.Context,
    label: Annotated[str | None, typer.Option("--label", "-l")] = None,
    limit: int = 20,
) -> None:
    """Lista os scans gravados."""
    if ctx.invoked_subcommand is not None:
        return
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
