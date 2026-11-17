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


def cache_dir(name: str) -> Path:
    return private_dir(tbm_home() / "cache" / name)
