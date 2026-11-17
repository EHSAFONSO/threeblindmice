"""Locais em disco usados pelo tbm (histórico, caches, base OUI)."""

from __future__ import annotations

import os
from contextlib import suppress
from pathlib import Path


def tbm_home() -> Path:
    return Path(os.environ.get("TBM_HOME") or Path.home() / ".threeblindmice")


def private_dir(path: Path) -> Path:
    """Cria o diretório acessível só pelo dono.

    No POSIX, aplica chmod 700. No Windows, o perfil do usuário já tem ACL
    restrita ao dono e o chmod não tem efeito real, então só criamos a pasta.
    """
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        with suppress(OSError):
            path.chmod(0o700)
    return path


def private_file(path: Path) -> None:
    if os.name != "nt" and path.exists():
        with suppress(OSError):
            path.chmod(0o600)


def no_window() -> dict:
    """kwargs para subprocess/asyncio: no Windows, não criar janela de console.

    Rodando sob pythonw (o vigia agendado), o processo não tem console; cada
    `ping`/`arp`/`route` lançado ganharia uma janela própria. No teste real
    foram 254 janelas piscando, e o scan levou 279s em vez de ~22s.
    """
    import subprocess
    import sys

    if sys.platform == "win32":
        return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {}


def cache_dir(name: str) -> Path:
    return private_dir(tbm_home() / "cache" / name)
