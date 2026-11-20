"""Ponto de extensão da descoberta: "enriquecedores" que completam os aparelhos encontrados.

Um enriquecedor recebe os aparelhos já com portas, MAC, nome e tipo, e pode completar
campos (`device_type`, `discovery`, `vendor`…). Ele não acrescenta aparelhos: o que é
escaneado continua decidido só pelo escopo. Um enriquecedor com erro não derruba o scan.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from tbm.models import Host
    from tbm.scout.engine import ScoutOptions


class Enricher(ABC):
    id: ClassVar[str]
    name: ClassVar[str]

    @abstractmethod
    async def enrich(self, hosts: list[Host], options: ScoutOptions) -> None: ...


ENRICHERS: dict[str, type[Enricher]] = {}


def register_enricher(cls: type[Enricher]) -> type[Enricher]:
    if cls.id in ENRICHERS:
        raise ValueError(f"enriquecedor duplicado: {cls.id}")
    ENRICHERS[cls.id] = cls
    return cls
