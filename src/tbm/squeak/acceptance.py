"""Aceitação de risco: achados que você conhece e não pode (ou não vai) corrigir.

Exemplo real: o Telnet aberto no modem da operadora. Ele continua aparecendo
no relatório, marcado como aceito, mas sai da nota e dos alertas. Toda
aceitação pode ter prazo: quando vence, o achado volta a contar, para que o
risco seja reavaliado de tempos em tempos.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from datetime import date

from tbm.models import ScanResult


def is_active(row: Mapping | sqlite3.Row, today: date | None = None) -> bool:
    until = row["until"]
    return until is None or date.fromisoformat(until) >= (today or date.today())


def apply_acceptances(result: ScanResult, acceptances: Mapping[str, Mapping | sqlite3.Row],
                      today: date | None = None) -> int:
    """Marca os achados aceitos. Devolve quantos foram marcados."""
    count = 0
    for f in result.findings:
        row = acceptances.get(f.fingerprint)
        if row is None:
            f.accepted, f.acceptance = False, None
            continue
        until = row["until"]
        if is_active(row, today):
            f.accepted = True
            f.acceptance = row["reason"] + (f" (até {until})" if until else "")
            count += 1
        else:
            f.accepted = False
            f.acceptance = f"aceitação expirou em {until}: reavalie ({row['reason']})"
    return count
