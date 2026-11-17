"""Texto pronto para enviar ao provedor (ou fabricante) sobre um equipamento.

Muitos achados em redes domésticas estão em aparelhos que você não controla:
o modem/ONT da operadora. O caminho é abrir um chamado. Este módulo escreve
esse chamado com dados técnicos objetivos, sem exagero.
"""

from __future__ import annotations

import re
from datetime import date

from tbm.models import Finding, Host, ScanResult, Severity

SEV_PT = {
    Severity.CRITICAL: "crítica",
    Severity.HIGH: "alta",
    Severity.MEDIUM: "média",
    Severity.LOW: "baixa",
    Severity.INFO: "informativa",
}


def _ask(f: Finding) -> str:
    """Traduz o achado num pedido concreto."""
    title = f.title.lower()
    if "telnet" in title:
        return "desativar o serviço Telnet (porta 23), que transmite credenciais sem criptografia"
    if f.check_id == "cve.nvd" or "cve-" in title:
        return f"atualizar o firmware para corrigir {f.key or f.title}"
    if "tr-069" in title:
        return "restringir o acesso à interface TR-069 (porta 7547) apenas ao servidor de gerência do provedor"
    if f.check_id.startswith("ssh."):
        return "atualizar o servidor SSH ou desativar os algoritmos fracos indicados"
    if "upnp" in title:
        return "desativar o UPnP ou disponibilizar a opção para o cliente"
    if "senha via http" in title:
        return "habilitar HTTPS na interface de administração"
    return f"avaliar e corrigir: {f.title}"


def build_letter(result: ScanResult, host: Host, *, name: str | None = None,
                 min_severity: Severity = Severity.MEDIUM) -> str:
    items = [f for f in result.findings
             if f.host == host.address and f.severity.rank >= min_severity.rank]
    if not items:
        return f"Nenhum achado de severidade {SEV_PT[min_severity]} ou maior em {host.address}."
    # O scan é gravado em UTC; a carta é lida por gente, então usamos o fuso local.
    when = (result.finished_at or result.started_at).astimezone().date()
    equip = " · ".join(x for x in (host.device_type, host.vendor, host.device_name) if x) or "equipamento"
    lines = [
        "Assunto: Vulnerabilidades de segurança no equipamento instalado na minha residência",
        "",
        "Prezados,",
        "",
        f"Em {when:%d/%m/%Y}, realizei uma verificação de segurança na minha rede doméstica e "
        f"identifiquei problemas no equipamento fornecido por vocês ({equip}, IP local "
        f"{host.address}{f', MAC {host.mac}' if host.mac else ''}).",
        "",
        "Achados:",
    ]
    for f in sorted(items, key=Finding.sort_key):
        extra = []
        if f.cvss is not None:
            extra.append(f"CVSS {f.cvss}")
        if f.epss is not None:
            extra.append(f"probabilidade de exploração (EPSS) {f.epss:.0%}")
        title = re.sub(r"\s*·\s*EPSS \d+%$", "", f.title)  # o EPSS já vai nos detalhes
        if f.kev:
            extra.append("explorada ativamente segundo a CISA")
        lines.append(f"- [{SEV_PT[f.severity]}] {title}" + (f" ({'; '.join(extra)})" if extra else ""))
        if f.evidence:
            lines.append(f"  Evidência: {f.evidence[:200]}")
    asks = list(dict.fromkeys(_ask(f) for f in items))
    lines += ["", "Solicito:"] + [f"{i}. {a[0].upper() + a[1:]}." for i, a in enumerate(asks, 1)]
    lines += [
        "",
        "Peço também a confirmação de quando o equipamento recebeu a última atualização de "
        "firmware e se há previsão de nova versão. Os testes foram não intrusivos e feitos "
        "apenas a partir da minha própria rede.",
        "",
        "Atenciosamente,",
        name or "[seu nome]",
        "",
        f"(Relatório gerado pelo threeblindmice em {date.today():%d/%m/%Y}.)",
    ]
    return "\n".join(lines)
