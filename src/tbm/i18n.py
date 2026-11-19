"""Idioma da interface: português (padrão) e inglês.

O texto-fonte é o português, marcado com `_()` nos templates e no código:
`{{ _("Novo scan") }}` ou `_("{n} dispositivo(s)", n=3)`. A tradução fica em
`tbm/locale_en.py`; o que não tiver tradução aparece em português (e o teste
tests/test_i18n.py falha, para ninguém esquecer).

O idioma vale por requisição (ContextVar): o middleware da interface lê o
cookie `tbm-lang` ou, na falta dele, o Accept-Language do navegador.

Fora da interface (CLI, relatórios, achados dos checks), o texto continua em
português.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

LANGS = {"pt": "Português", "en": "English"}
DEFAULT = "pt"
COOKIE = "tbm-lang"

_current: ContextVar[str] = ContextVar("tbm_lang", default=DEFAULT)


def get_lang() -> str:
    return _current.get()


def normalize(code: str | None) -> str | None:
    code = (code or "").strip().lower()[:2]
    return code if code in LANGS else None


def from_accept_language(header: str | None) -> str:
    """Primeiro idioma suportado na lista do navegador (sem pesos: a ordem já diz)."""
    for part in (header or "").split(","):
        if lang := normalize(part.split(";")[0]):
            return lang
    return DEFAULT


@contextmanager
def use(lang: str) -> Iterator[None]:
    token = _current.set(normalize(lang) or DEFAULT)
    try:
        yield
    finally:
        _current.reset(token)


def gettext(text: str, **values: object) -> str:
    if _current.get() == "en":
        from tbm.locale_en import EN

        text = EN.get(text, text)
    return text.format(**values) if values else text


_ = gettext


def html_lang() -> str:
    return "en" if get_lang() == "en" else "pt-BR"


# Textos que chegam aos templates por variável (menus, passos, legendas, notas do
# mapa): não aparecem como _("...") literal, então ficam listados aqui para o
# teste conferir que todos têm tradução.
EXTRA_KEYS = [
    "Visão geral", "Achados", "Mapa", "Dispositivos", "Alertas", "Vigia", "Funcionalidades",
    "Sua rede", "Primeiro scan", "Descoberta", "Portas", "Serviços", "Análise",
    "crítico", "alto", "médio", "baixo", "sem problemas", "Internet",
    "O roteador principal foi estimado (scans anteriores à v0.7 não registravam o gateway).",
    "Há {n} roteadores/modems na mesma rede. Pode haver NAT duplo (comum quando o modem da operadora fica entre "
    "a internet e o seu roteador); vale conferir com o provedor.",
]


# Tipos de aparelho que o classificador (tbm/scout/classify.py) devolve.
DEVICE_TYPES = [
    "roteador/modem",
    "computador Windows",
    "computador Apple",
    "computador",
    "celular Android",
    "celular Apple",
    "celular/notebook",
    "tablet Apple",
    "dispositivo Apple",
    "impressora",
    "câmera/DVR",
    "caixa de som",
    "caixa de som/AirPlay",
    "caixa de som/tela Google",
    "casa inteligente (HomeKit)",
    "casa inteligente (Matter)",
    "dispositivo embarcado (Linux)",
    "servidor de mídia",
    "TV/Chromecast",
    "TV/streaming",
]
EXTRA_KEYS += DEVICE_TYPES


def device_type(text: str | None) -> str | None:
    return gettext(text) if text else text


def js_catalog() -> dict[str, str]:
    """Textos usados pelo tbm.js (diálogos e avisos), no idioma atual."""
    keys = ["Cancelar", "Confirmar", "Salvar", "Nome do aparelho",
            "Como você chama este aparelho? Deixe vazio para voltar ao nome detectado.",
            "Aparelho aprovado: não vai mais alertar como desconhecido", "Aprovação removida",
            "Falha ao carregar.", "Erro"]
    return {k: gettext(k) for k in keys}
