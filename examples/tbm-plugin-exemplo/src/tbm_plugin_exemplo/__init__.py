"""Plugin de exemplo do threeblindmice.

Mostra os três pontos de extensão, usando só a API pública ``tbm.plugin``:

- um **check** passivo (só olha as portas que o Scout já achou, não manda nada para a rede);
- um **destino de alerta** que grava a mensagem num arquivo local (``arquivo:///caminho.log``);
- um **enriquecedor** de descoberta que marca impressoras pela porta 9100.

Instale (``pip install -e examples/tbm-plugin-exemplo``) e autorize com
``tbm plugins enable tbm-plugin-exemplo``. Sem autorização, nada disso roda.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import unquote, urlparse

from tbm.plugin import (
    API_VERSION,
    Check,
    CheckContext,
    Delivery,
    Enricher,
    Finding,
    FixKind,
    Notifier,
    Severity,
    add_translations,
    register_fix_kind,
)

TBM_API = API_VERSION  # a versão da API para a qual o plugin foi escrito


class TelnetEscondido(Check):
    """Telnet em porta alternativa: câmeras e DVRs baratos costumam deixar um na 2323."""

    TBM_API = 1
    id = "exemplo.telnet-2323"
    name = "Telnet na porta 2323"
    what = "Procura Telnet escondido na porta 2323."
    why = "Câmeras e gravadores baratos costumam vir com um Telnet de fábrica nessa porta."

    async def run(self, ctx: CheckContext) -> list[Finding]:
        return [
            Finding(check_id=self.id, title="Telnet na porta 2323", severity=Severity.HIGH, host=host.address,
                    port=svc.port, description="Acesso de terminal sem criptografia numa porta alternativa.",
                    remediation="Desative o Telnet nas configurações do aparelho ou atualize o firmware.")
            for host, svc in ctx.services(lambda s: s.port == 2323)
        ]


# Tipo de correção próprio: os achados do check acima viram a ação "Fechar o Telnet escondido em …"
register_fix_kind(
    FixKind("telnet-2323", "Fechar o Telnet escondido em {dev}",
            "Um Telnet de fábrica numa porta alternativa dá acesso ao aparelho sem senha forte."),
    classifier=lambda f: "telnet-2323" if f.check_id == TelnetEscondido.id else None,
)
add_translations("en", {
    "Telnet na porta 2323": "Telnet on port 2323",
    "Procura Telnet escondido na porta 2323.": "Looks for Telnet hidden on port 2323.",
    "Fechar o Telnet escondido em {dev}": "Close the hidden Telnet on {dev}",
})


def _file_path(target: str) -> Path:
    """arquivo:///C:/tbm/alertas.log → C:/tbm/alertas.log; arquivo:///var/log/tbm.log → /var/log/tbm.log"""
    raw = unquote(urlparse(target).path)
    if len(raw) > 2 and raw[0] == "/" and raw[2] == ":":  # letra de unidade do Windows
        raw = raw[1:]
    return Path(raw)


class AlertaEmArquivo(Notifier):
    """Destino ``arquivo:///C:/tbm/alertas.log``: acrescenta cada alerta ao arquivo."""

    TBM_API = 1
    kind = "arquivo"

    def matches(self, p) -> bool:
        return p.scheme == "arquivo"

    def describe(self, p) -> str:
        return f"Arquivo · {Path(unquote(p.path)).name or '?'}"  # só o nome, não a pasta

    def delivery(self, target, text, *, title, priority, extra) -> Delivery:
        raise ValueError("este destino grava em arquivo, não usa HTTP")

    async def send(self, target, text, *, title="threeblindmice", priority="default", extra=None,
                   transport=None, check=True) -> int:
        path = _file_path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(f"[{priority}] {title}\n{text}\n\n")
        return 200


class MarcaImpressoras(Enricher):
    """Porta 9100 aberta e tipo desconhecido: provavelmente uma impressora (JetDirect)."""

    TBM_API = 1
    id = "exemplo.impressora"
    name = "Impressoras pela porta 9100"

    async def enrich(self, hosts, options) -> None:
        for h in hosts:
            if not h.device_type and any(s.port == 9100 for s in h.services):
                h.device_type = "impressora"
                h.discovery["exemplo"] = "porta 9100 (JetDirect)"
