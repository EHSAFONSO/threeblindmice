"""Utilidades: carta ao provedor, atualização, OUI, lista de checks e limpeza do desinstalador."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from tbm import __version__, schedule
from tbm.cli.common import LabelOpt, MinSevOpt, _fail, _run, app, console
from tbm.models import Severity
from tbm.scout.arp import OUIDatabase, download_oui
from tbm.sniffer import REGISTRY
from tbm.squeak import HistoryStore
from tbm.squeak.letter import build_letter


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


@app.command("update")
def update_cmd(
    disable: Annotated[bool, typer.Option("--disable", help="Desliga o aviso de nova versão.")] = False,
    enable: Annotated[bool, typer.Option("--enable", help="Liga o aviso de nova versão.")] = False,
) -> None:
    """Confere se há versão nova no GitHub (só avisa; não baixa nem instala nada)."""
    from tbm import update

    if disable or enable:
        update.set_enabled(enable)
        console.print(f"Aviso de nova versão {'ligado' if enable else 'desligado'}.")
        return
    release = _run(update.check(force=True))
    if release is None:
        console.print(f"Você está na versão mais recente ({__version__}).")
        return
    console.print(f"[bold]Nova versão: {release.version}[/] (você tem {__version__})")
    console.print(release.url)
    if release.sha256:
        console.print(f"SHA-256 de {release.setup_name}: [cyan]{release.sha256}[/]")
        console.print(f"Para provar a origem: [cyan]{release.verify_command}[/]")


@app.command("uninstall-cleanup", hidden=True)
def uninstall_cleanup() -> None:
    """Chamado pelo desinstalador do Windows: remove os vigias desta cópia instalada."""
    from tbm.frozen import is_frozen

    if not is_frozen() or sys.platform != "win32":
        raise _fail("só faz sentido na versão instalada pelo setup.exe")
    for label in schedule.windows_tasks_using(Path(sys.executable).parent):
        try:
            schedule.execute(schedule.remove_plan("win32", label))
            console.print(f"vigia '{label}' removido")
        except RuntimeError as exc:
            console.print(f"[yellow]vigia '{label}': {exc}[/]")


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
