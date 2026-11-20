"""CLI `tbm`: o ponto de entrada dos três mice."""

from __future__ import annotations

import sys
from typing import Annotated

import typer

from tbm import __version__
from tbm.cli import alerts, history, scan, tools, ui, watch  # noqa: F401 (registram os comandos)
from tbm.cli.common import (
    app,
    console,
    parse_interval,  # noqa: F401 (API usada nos testes)
)


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
