"""Nota de risco de 0 a 100 (100 = sem achados).

Usamos decaimento exponencial em vez de subtração linear: o primeiro achado
crítico derruba muito a nota, o décimo LOW quase não mexe. Assim a nota
nunca fica negativa e continua comparável entre redes de tamanhos diferentes.

O peso de cada achado é ajustado pela probabilidade real de exploração:
CVE no CISA KEV ou com EPSS alto pesa mais; CVE com EPSS < 1% pesa metade.
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


def exploitability_multiplier(f: Finding) -> float:
    if f.kev:
        return 1.5
    if f.epss is None:
        return 1.0
    if f.epss >= 0.5:
        return 1.5
    if f.epss >= 0.1:
        return 1.2
    if f.epss < 0.01:
        return 0.5
    return 1.0


def weight(f: Finding) -> float:
    return WEIGHTS[f.severity] * exploitability_multiplier(f)


def penalty(findings: Iterable[Finding]) -> float:
    return sum(weight(f) for f in findings)


def score_findings(findings: Iterable[Finding]) -> int:
    return round(100 * math.exp(-penalty(findings) / DECAY))


def grade_for(score: int) -> str:
    return next(g for threshold, g in GRADES if score >= threshold)
