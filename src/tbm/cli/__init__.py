"""CLI `tbm`: o ponto de entrada dos três mice."""

from __future__ import annotations

import sys
from typing import Annotated

import typer

from tbm import __version__
from tbm.cli import alerts, history, plugins, scan, tools, ui, watch  # noqa: F401 (registram os comandos)
from tbm.cli.common import (
    _fail,
    app,
    console,
    parse_interval,  # noqa: F401 (API usada nos testes)
)


@app.callback(invoke_without_command=True)
def main(
    version: Annotated[bool, typer.Option("--version", help="Mostra a versão.")] = False,
    log_level: Annotated[str | None, typer.Option(
        "--log-level", help="Detalhe do log técnico em TBM_HOME/logs/tbm.log: debug, info, warning, error.")] = None,
) -> None:
    from tbm.log import configure

    try:
        configure(log_level)
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    if version:
        console.print(f"threeblindmice {__version__}")
        raise typer.Exit()
    if sys.platform == "win32":
        # Evita "Event loop is closed" ruidoso no Proactor ao sair.
        import warnings

        warnings.filterwarnings("ignore", category=ResourceWarning)
