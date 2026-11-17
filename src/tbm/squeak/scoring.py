"""Nota de risco de 0 a 100 (100 = sem achados).

Usamos decaimento exponencial em vez de subtração linear: o primeiro achado
crítico derruba muito a nota, o décimo LOW quase não mexe. Assim a nota
nunca fica negativa e continua comparável entre redes de tamanhos diferentes.
"""

from __future__ import annotations

import math
from collections.abc import Iterable

from tbm.models import Finding, Severity

WEIGHTS = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 10.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.0,
}
DECAY = 80.0
GRADES = ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F"))


def penalty(findings: Iterable[Finding]) -> float:
    return sum(WEIGHTS[f.severity] for f in findings)


def score_findings(findings: Iterable[Finding]) -> int:
    return round(100 * math.exp(-penalty(findings) / DECAY))


def grade_for(score: int) -> str:
    return next(g for threshold, g in GRADES if score >= threshold)
