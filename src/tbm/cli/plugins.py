"""Plugins: listar os instalados e autorizar ou bloquear cada pacote."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.table import Table

from tbm.cli.common import _fail, app, console

plugins_app = typer.Typer(help="Plugins de terceiros (checks, destinos de alerta, descoberta). Nada roda sem autorização.")
app.add_typer(plugins_app, name="plugins")

WARNING = ("[yellow]Atenção:[/] um plugin roda código no seu computador, com acesso à sua rede. "
           "Só autorize pacotes que você confia.")


@plugins_app.command("list")
def plugins_list() -> None:
    """Mostra os plugins instalados e quais estão autorizados."""
    from tbm.plugins import available, enabled_packages, load_plugins

    entries = available()
    if not entries:
        console.print("Nenhum plugin instalado. Veja examples/tbm-plugin-exemplo/ para criar um.")
    else:
        table = Table(header_style="bold")
        for col in ("pacote", "versão", "tipo", "nome", "autorizado"):
            table.add_column(col)
        kinds = {"tbm.checks": "check", "tbm.notifiers": "alerta", "tbm.discovery": "descoberta"}
        for e in entries:
            table.add_row(e.package, e.version, kinds.get(e.group, e.group), e.name,
                          "[green]sim[/]" if e.enabled else "[dim]não[/]")
        console.print(table)
    installed = {e.package.lower() for e in entries}
    for pkg in enabled_packages():
        if pkg.lower() not in installed:
            console.print(f"[dim]{pkg}: autorizado, mas não está instalado.[/]")
    for err in load_plugins():
        console.print(f"[red]plugin com erro (ficou de fora):[/] {err}")


@plugins_app.command("enable")
def plugins_enable(
    package: Annotated[str, typer.Argument(help="Nome do pacote (como aparece em `tbm plugins list`).")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Não pergunta.")] = False,
) -> None:
    """Autoriza um pacote de plugins."""
    from tbm.plugins import available, set_enabled

    found = [e for e in available() if e.package.lower() == package.lower()]
    if not found:
        raise _fail(f"'{package}' não está instalado ou não declara plugins do tbm")
    console.print(WARNING)
    for e in found:
        console.print(f"  • {e.group.removeprefix('tbm.')}: {e.name} → {e.value}")
    if not yes and not typer.confirm(f"Autorizar {found[0].package} {found[0].version}?"):
        raise typer.Exit(1)
    set_enabled(found[0].package, True)
    console.print(f"[green]{found[0].package} autorizado.[/] Ele roda a partir do próximo scan.")


@plugins_app.command("disable")
def plugins_disable(package: Annotated[str, typer.Argument(help="Nome do pacote.")]) -> None:
    """Bloqueia um pacote de plugins (ele continua instalado, mas não roda)."""
    from tbm.plugins import enabled_packages, set_enabled

    if package.lower() not in {p.lower() for p in enabled_packages()}:
        console.print(f"{package} já não estava autorizado.")
        return
    set_enabled(package, False)
    console.print(f"{package} bloqueado.")
