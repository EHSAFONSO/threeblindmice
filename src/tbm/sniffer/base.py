"""Infraestrutura de checks do Sniffer: contexto, classe base e registro.

Para criar um check novo: herde de `Check`, defina `id`/`name`, implemente
`run()` e decore com `@register`. O engine descobre sozinho.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

import httpx

from tbm.models import Finding, Host, ScanResult, Service
from tbm.scope import Scope

if TYPE_CHECKING:
    from tbm.sniffer.cve import NVDClient


@dataclass
class SnifferOptions:
    active: bool = False  # checks que interagem além do banner (login anônimo, paths)
    cve: bool = True
    max_cves_per_service: int = 15
    secrets_path: Path | None = None
    disabled: set[str] = field(default_factory=set)
    nvd_api_key: str | None = None
    cache_dir: Path | None = None
    http_timeout: float = 6.0
    epss: bool = True
    backport: bool = True  # consulta o tracker da distro para descartar CVEs já corrigidos
    # Escopo contra o qual os hosts são revalidados antes de qualquer check.
    # None = Scope.default() (somente redes privadas).
    scope: Scope | None = None


@dataclass
class CheckContext:
    scan: ScanResult
    http: httpx.AsyncClient
    options: SnifferOptions
    nvd: NVDClient | None = None

    def services(
        self, predicate: Callable[[Service], bool] = lambda s: True, transport: str = "tcp"
    ) -> Iterator[tuple[Host, Service]]:
        for host in self.scan.hosts:
            for svc in host.services:
                if svc.transport == transport and predicate(svc):
                    yield host, svc


class Check(ABC):
    id: ClassVar[str]
    name: ClassVar[str]
    active_only: ClassVar[bool] = False

    def enabled(self, options: SnifferOptions) -> bool:
        if self.id in options.disabled or self.id.split(".")[0] in options.disabled:
            return False
        return options.active or not self.active_only

    @abstractmethod
    async def run(self, ctx: CheckContext) -> list[Finding]: ...


REGISTRY: dict[str, type[Check]] = {}


def register(cls: type[Check]) -> type[Check]:
    if cls.id in REGISTRY:
        raise ValueError(f"check duplicado: {cls.id}")
    REGISTRY[cls.id] = cls
    return cls


def url_for(host: Host, svc: Service, path: str = "/") -> str:
    scheme = "https" if svc.tls or svc.name == "https" else "http"
    addr = f"[{host.address}]" if ":" in host.address else host.address
    default = (scheme == "http" and svc.port == 80) or (scheme == "https" and svc.port == 443)
    return f"{scheme}://{addr}{'' if default else f':{svc.port}'}{path}"
