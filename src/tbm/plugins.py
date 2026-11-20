"""Carregamento de plugins por entry points, só os que você autorizou.

Um plugin é um pacote Python instalado que declara entry points nos grupos:

- ``tbm.checks``    → uma subclasse de ``Check`` (ou um módulo que registra checks com ``@register``);
- ``tbm.notifiers`` → uma subclasse de ``Notifier`` (destino de alerta);
- ``tbm.discovery`` → uma subclasse de ``Enricher`` (completa os aparelhos descobertos).

Plugins executam código com acesso à sua rede. Por isso nada é carregado só por estar
instalado: o pacote precisa estar na lista ``plugins`` do config.json, gerenciada por
``tbm plugins enable|disable``. ``TBM_NO_PLUGINS=1`` desliga todos.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from importlib.metadata import EntryPoint, entry_points
from types import ModuleType

from tbm import config
from tbm.log import get_logger

API_VERSION = 1  # muda só quando tbm.plugin quebrar compatibilidade
GROUPS = ("tbm.checks", "tbm.notifiers", "tbm.discovery")


@dataclass(frozen=True)
class PluginEntry:
    package: str
    version: str
    group: str
    name: str
    value: str
    enabled: bool


# id do check/destino/enriquecedor → "pacote versão" (para a página Funcionalidades e o `tbm checks`)
ORIGINS: dict[str, str] = {}
LOAD_ERRORS: list[str] = []
_loaded = False
_lock = threading.Lock()


def enabled_packages() -> list[str]:
    value = config.load().get("plugins", [])
    return [str(p) for p in value] if isinstance(value, list) else []


def set_enabled(package: str, on: bool) -> list[str]:
    data = config.load()
    current = [p for p in enabled_packages() if p.lower() != package.lower()]
    if on:
        current.append(package)
    data["plugins"] = sorted(current, key=str.lower)
    config.save(data)
    return data["plugins"]


def _entries() -> list[tuple[EntryPoint, str, str]]:
    out = []
    for group in GROUPS:
        for ep in entry_points(group=group):
            dist = ep.dist
            out.append((ep, dist.name if dist else "?", dist.version if dist else "?"))
    return out


def available() -> list[PluginEntry]:
    """Todos os entry points instalados, autorizados ou não."""
    allowed = {p.lower() for p in enabled_packages()}
    return [PluginEntry(pkg, ver, ep.group, ep.name, ep.value, pkg.lower() in allowed)
            for ep, pkg, ver in _entries()]


def _register(obj: object, group: str, origin: str) -> None:
    from tbm.scout.extend import ENRICHERS, Enricher, register_enricher
    from tbm.sniffer.base import REGISTRY, Check, register
    from tbm.squeak.notifiers import NOTIFIERS, Notifier, register_notifier

    if isinstance(obj, ModuleType):
        api = getattr(obj, "TBM_API", API_VERSION)
        if api != API_VERSION:
            raise RuntimeError(f"feito para a API {api} do tbm (esta é a {API_VERSION})")
        return  # importar o módulo já registrou o que ele traz (decoradores)
    if not isinstance(obj, type):
        raise TypeError("o entry point precisa apontar para uma classe ou um módulo")
    api = getattr(obj, "TBM_API", API_VERSION)
    if api != API_VERSION:
        raise RuntimeError(f"feito para a API {api} do tbm (esta é a {API_VERSION})")
    if group == "tbm.checks" and issubclass(obj, Check):
        if REGISTRY.get(obj.id) is not obj:
            register(obj)
        ORIGINS[obj.id] = origin
    elif group == "tbm.notifiers" and issubclass(obj, Notifier):
        if not any(type(n) is obj for n in NOTIFIERS):
            register_notifier(obj)
        ORIGINS[f"notifier:{obj.kind}"] = origin
    elif group == "tbm.discovery" and issubclass(obj, Enricher):
        if ENRICHERS.get(obj.id) is not obj:
            register_enricher(obj)
        ORIGINS[obj.id] = origin
    else:
        raise TypeError(f"{obj.__name__} não é do tipo esperado em {group}")


def load_plugins(*, force: bool = False) -> list[str]:
    """Carrega (uma vez) os plugins autorizados. Devolve os erros de carregamento.

    Um plugin com erro fica de fora e é anotado; os demais e o tbm seguem normalmente.
    """
    global _loaded
    with _lock:
        if _loaded and not force:
            return LOAD_ERRORS
        _loaded = True
        LOAD_ERRORS.clear()
        if os.environ.get("TBM_NO_PLUGINS"):
            return LOAD_ERRORS
        allowed = {p.lower() for p in enabled_packages()}
        if not allowed:
            return LOAD_ERRORS
        from tbm.sniffer.base import REGISTRY

        for ep, pkg, ver in _entries():
            if pkg.lower() not in allowed:
                continue
            origin = f"{pkg} {ver}"
            before = set(REGISTRY)
            try:
                _register(ep.load(), ep.group, origin)
            except Exception as exc:  # noqa: BLE001 (plugin quebrado não derruba o tbm)
                LOAD_ERRORS.append(f"{pkg} ({ep.name}): {exc.__class__.__name__}: {exc}")
                get_logger(__name__).warning("plugin %s (%s) ficou de fora: %s", pkg, ep.name, exc.__class__.__name__,
                                             exc_info=True)
                continue
            get_logger(__name__).info("plugin carregado: %s %s (%s)", pkg, ver, ep.name)
            for cid in set(REGISTRY) - before:  # checks registrados por um módulo-plugin
                ORIGINS.setdefault(cid, origin)
        return LOAD_ERRORS
