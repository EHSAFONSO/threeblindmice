"""Calibração central da severidade pelo contexto de rede (LAN x internet).

O mesmo achado tem risco diferente conforme quem consegue alcançá-lo:
- "senha via HTTP" na LAN exige que o atacante já esteja no seu Wi-Fi;
- SMB na LAN é normal num PC Windows, mas na internet é porta de entrada
  para worms (WannaCry).

Os checks emitem a severidade "padrão" e esta tabela ajusta. A regra fica num
lugar só, em vez de um `if is_public` espalhado em cada check.
"""

from __future__ import annotations

from tbm.models import Finding, Severity
from tbm.scope import is_public

L, M, H, C = Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL

# (check_id, porta ou key ou None=qualquer) → (severidade na LAN, severidade na internet)
POLICY: dict[tuple[str, object], tuple[Severity, Severity]] = {
    ("http.cleartext-login", None): (M, H),
    ("service.exposed", 21): (L, M),       # FTP
    ("service.exposed", 139): (L, H),      # NetBIOS
    ("service.exposed", 445): (M, C),      # SMB na internet: wormable
    ("service.exposed", 3389): (M, H),     # RDP: força bruta constante na internet
    ("service.exposed", 5900): (M, H),     # VNC
    ("service.exposed", 7547): (M, H),     # TR-069
    ("service.exposed", 1883): (M, H),     # MQTT
    ("service.exposed", 873): (M, H),      # rsync
    ("service.exposed", 2049): (M, H),     # NFS
    **{("service.exposed", p): (M, H) for p in (1433, 3306, 5432, 5984, 6379, 9200, 27017)},
}

NOTE = {
    False: "Severidade ajustada ao contexto: o serviço está numa rede privada, então "
           "só quem já está nela consegue explorar.",
    True: "Severidade ajustada ao contexto: o serviço está exposto à internet.",
}


def policy_for(f: Finding) -> tuple[Severity, Severity] | None:
    for key in (f.port, f.key or None, None):
        if (rule := POLICY.get((f.check_id, key))) is not None:
            return rule
    return None


def apply_context(findings: list[Finding]) -> None:
    for f in findings:
        if f.host == "local" or (rule := policy_for(f)) is None:
            continue
        public = is_public(f.host)
        target = rule[1] if public else rule[0]
        if target is f.severity:
            continue
        f.severity = target
        if NOTE[public] not in f.description:
            f.description = (f.description + "\n\n" + NOTE[public]).strip()
