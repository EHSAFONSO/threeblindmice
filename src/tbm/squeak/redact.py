"""Remove evidências sensíveis antes de gravar ou compartilhar um resultado.

Com --no-evidence, o histórico e o relatório mantêm o *que* foi achado e
*onde*, mas não os banners, trechos de segredos nem respostas dos serviços.
"""

from __future__ import annotations

from tbm.models import ScanResult

REDACTED = "[omitido: --no-evidence]"
SENSITIVE_EXTRA = {"sysdescr", "server", "location", "services"}


def redact(result: ScanResult) -> ScanResult:
    clean = result.model_copy(deep=True)
    for f in clean.findings:
        if f.evidence:
            f.evidence = REDACTED
    for h in clean.hosts:
        for s in h.services:
            s.banner = None
            for key in SENSITIVE_EXTRA & s.extra.keys():
                s.extra[key] = REDACTED
    return clean
