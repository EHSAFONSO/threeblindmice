"""Configuração persistente do tbm (hoje: o destino dos alertas).

Ordem de precedência para o destino de alertas:
1. `--notify` na linha de comando
2. variável de ambiente TBM_WEBHOOK
3. `notify` em TBM_HOME/config.json (o que a interface gráfica grava)

O arquivo fica restrito ao dono (chmod 600 no POSIX; no Windows, o perfil do
usuário já é restrito), porque o destino pode conter segredos: o token do
bot do Telegram, ou a URL de um webhook.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from tbm.paths import no_window, private_dir, private_file, tbm_home

ENV = "TBM_WEBHOOK"


def config_path() -> Path:
    return tbm_home() / "config.json"


def load() -> dict[str, Any]:
    path = config_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save(data: dict[str, Any]) -> None:
    private_dir(tbm_home())
    path = config_path()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    private_file(tmp)
    tmp.replace(path)  # troca atômica: nunca fica um config.json pela metade


def quiet_hours() -> tuple[str, str] | None:
    """Janela de silêncio HH:MM–HH:MM, se configurada (alertas não-críticos ficam retidos)."""
    data = load()
    start, end = str(data.get("quiet_start") or ""), str(data.get("quiet_end") or "")
    import re as _re
    if _re.fullmatch(r"\d{2}:\d{2}", start) and _re.fullmatch(r"\d{2}:\d{2}", end):
        return start, end
    return None


def notify_target() -> tuple[str | None, str]:
    """(destino, origem). Origem: "env", "config" ou "none"."""
    if env := os.environ.get(ENV, "").strip():
        return env, "env"
    if cfg := str(load().get("notify") or "").strip():
        return cfg, "config"
    return None, "none"


def _setx(value: str) -> bool:
    if sys.platform != "win32":
        return False
    return subprocess.run(["setx", ENV, value], capture_output=True, check=False,
                          **no_window()).returncode == 0


def persist_notify(target: str | None) -> list[str]:
    """Grava (ou apaga, com None) o destino. Devolve avisos para mostrar ao usuário.

    Se TBM_WEBHOOK existe no ambiente, ele tem prioridade sobre o arquivo. Para
    os dois não divergirem (a interface gravaria uma coisa e os scans usariam
    outra), no Windows atualizamos a variável também; nos outros sistemas, avisamos.
    """
    data = load()
    if target:
        data["notify"] = target
    else:
        data.pop("notify", None)
    save(data)

    notes: list[str] = []
    if os.environ.get(ENV, "").strip():
        if _setx(target or ""):
            os.environ[ENV] = target or ""
            notes.append("A variável TBM_WEBHOOK também foi atualizada (vale para terminais novos).")
        else:
            notes.append("A variável TBM_WEBHOOK está definida no ambiente e continua tendo prioridade. "
                         "Remova-a do seu ~/.bashrc/~/.zshrc para usar esta configuração.")
    return notes


def describe(target: str | None) -> dict[str, str]:
    """Descrição segura do destino, sem segredos (token, caminho do webhook)."""
    if not target:
        return {"kind": "none", "label": "nenhum destino configurado"}
    from tbm.squeak.notifiers import notifier_for  # o mesmo registro que envia os alertas

    notifier, parsed = notifier_for(target)
    return {"kind": notifier.kind, "label": notifier.describe(parsed)}
