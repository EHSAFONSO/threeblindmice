"""Log técnico do tbm: arquivo rotativo em TBM_HOME/logs/tbm.log.

É o registro para diagnosticar problemas (um check que falhou, um plugin com erro,
o vigia que caiu), separado do que a CLI mostra na tela e do log do scan agendado
(TBM_HOME/logs/<rótulo>.log, que a página Vigia exibe).

Privacidade: em INFO e acima, nada de IP, MAC ou nome de aparelho; só rótulos,
contagens e tempos. O detalhe por aparelho fica em DEBUG (`--log-level debug`).
O arquivo fica com permissão só do dono, como o histórico.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from tbm.paths import private_dir, private_file, tbm_home

LEVELS = ("debug", "info", "warning", "error")
_HANDLER_NAME = "tbm-file"

# Como biblioteca (sem a CLI), o tbm não escreve nada sozinho: quem importa decide.
logging.getLogger("tbm").addHandler(logging.NullHandler())


def log_file() -> Path:
    return private_dir(tbm_home() / "logs") / "tbm.log"


def get_logger(name: str) -> logging.Logger:
    """Logger filho de "tbm" (ex.: get_logger(__name__) dentro do pacote)."""
    return logging.getLogger(name if name.startswith("tbm") else f"tbm.{name}")


def configure(level: str | None = None) -> Path | None:
    """Liga o arquivo de log (idempotente). Nível: argumento, TBM_LOG_LEVEL ou INFO.

    Falhar ao abrir o arquivo (disco cheio, pasta sem permissão) nunca impede o tbm de rodar.
    """
    name = (level or os.environ.get("TBM_LOG_LEVEL") or "info").lower()
    if name not in LEVELS:
        raise ValueError(f"nível de log inválido: {name} (use {', '.join(LEVELS)})")
    root = logging.getLogger("tbm")
    root.setLevel(name.upper())
    root.propagate = False
    path = log_file()
    for h in root.handlers:
        if h.get_name() == _HANDLER_NAME:
            if Path(getattr(h, "baseFilename", "")) == path.resolve():
                return path
            root.removeHandler(h)  # TBM_HOME mudou (testes): troca de arquivo
            h.close()
    try:
        handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    except OSError:
        return None
    handler.set_name(_HANDLER_NAME)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)
    private_file(path)
    return path
