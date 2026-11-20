"""API pública e estável para plugins do tbm (versão em ``API_VERSION``).

Tudo que um plugin precisa vem daqui; o resto do pacote ``tbm`` pode mudar sem aviso.
Exemplo mínimo (veja examples/tbm-plugin-exemplo/)::

    from tbm.plugin import Check, CheckContext, Finding, Severity

    class TelnetNaPorta2323(Check):
        id = "exemplo.telnet-2323"
        name = "Telnet na porta 2323"
        what = "Procura Telnet escondido na porta 2323."
        why = "Câmeras baratas costumam deixar um Telnet de fábrica nessa porta."

        async def run(self, ctx: CheckContext) -> list[Finding]:
            return [Finding(check_id=self.id, title="Telnet na porta 2323", severity=Severity.HIGH,
                            host=h.address, port=s.port)
                    for h, s in ctx.services(lambda s: s.port == 2323)]

e no ``pyproject.toml`` do plugin::

    [project.entry-points."tbm.checks"]
    telnet-2323 = "meu_plugin:TelnetNaPorta2323"

O check só roda depois de ``tbm plugins enable <pacote>``.
"""

from __future__ import annotations

from tbm.models import Finding, Host, ScanResult, Service, Severity
from tbm.plugins import API_VERSION
from tbm.scout.extend import Enricher, register_enricher
from tbm.sniffer.base import Check, CheckContext, SnifferOptions, register, url_for
from tbm.squeak.actions import CLASSIFIERS, KINDS, FixKind
from tbm.squeak.notifiers import Delivery, Notifier, register_notifier

__all__ = [
    "API_VERSION", "Check", "CheckContext", "Delivery", "Enricher", "Finding", "FixKind", "Host", "Notifier",
    "ScanResult", "Service", "Severity", "SnifferOptions", "add_translations", "register", "register_classifier",
    "register_enricher", "register_fix_kind", "register_notifier", "url_for",
]


def register_fix_kind(kind: FixKind, classifier=None) -> FixKind:
    """Um tipo de correção novo ("Desativar X em {dev}"), opcionalmente com o classificador
    que decide quais achados caem nele (função: Finding → chave do tipo, ou None)."""
    KINDS[kind.key] = kind
    if classifier is not None:
        register_classifier(classifier)
    return kind


def register_classifier(fn) -> None:
    CLASSIFIERS.append(fn)


def add_translations(lang: str, pairs: dict[str, str]) -> None:
    """Traduções dos textos do plugin (chave = texto em português). Hoje só há "en"."""
    if lang != "en":
        raise ValueError("idioma sem catálogo de tradução: use 'en'")
    from tbm.locale_en import EN

    for pt, en in pairs.items():
        EN.setdefault(pt, en)  # nunca sobrescreve a tradução do próprio tbm
