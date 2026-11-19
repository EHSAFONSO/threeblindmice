"""O tbm instalado pelo setup.exe do Windows (empacotado com PyInstaller).

No pacote não existe python.exe nem `-m tbm`. Há dois executáveis lado a lado,
que compartilham a mesma pasta `_internal`:

- ``threeblindmice.exe``: sem console. Sem argumentos abre o app; com
  ``--scheduled <rótulo>`` roda o vigia agendado (o papel do pythonw);
- ``tbm.exe``: com console. É a linha de comando de sempre.

Quem monta comandos (o vigia, os atalhos) pergunta aqui em vez de supor Python.
"""

from __future__ import annotations

import sys
from pathlib import Path

GUI_EXE = "threeblindmice.exe"
CLI_EXE = "tbm.exe"
SCHEDULED_FLAG = "--scheduled"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def bundle_exe(name: str) -> Path:
    """Caminho de um dos executáveis do pacote (ao lado do que está rodando)."""
    return Path(sys.executable).with_name(name)


def gui_main(argv: list[str] | None = None) -> int:
    """Ponto de entrada do threeblindmice.exe."""
    args = sys.argv[1:] if argv is None else argv
    if args[:1] == [SCHEDULED_FLAG]:
        from tbm._scheduled import main as scheduled

        return scheduled(args[1:])
    from tbm.cli import app

    result = app(args=["app", *args], prog_name="threeblindmice", standalone_mode=False)
    return result if isinstance(result, int) else 0
