"""Interface de progresso desacoplada da UI.

Os engines só conhecem `ProgressHook`; a CLI pluga uma implementação com Rich,
a interface gráfica anota números para a página desenhar, e os testes usam
`NullProgress`.
"""

from __future__ import annotations

from typing import Protocol


class ProgressHook(Protocol):
    def start(self, phase: str, total: int) -> None: ...
    def advance(self, phase: str, amount: int = 1) -> None: ...
    def log(self, message: str) -> None: ...


def report_found(progress: object, address: str, **info: object) -> None:
    """Avisa que um dispositivo apareceu, se o hook souber mostrar isso.

    Opcional de propósito: a CLI e os testes não precisam implementar. A
    interface gráfica usa para os aparelhos "surgirem" na tela durante o scan.
    """
    found = getattr(progress, "found", None)
    if callable(found):
        found(address, **info)


class NullProgress:
    def start(self, phase: str, total: int) -> None:
        pass

    def advance(self, phase: str, amount: int = 1) -> None:
        pass

    def log(self, message: str) -> None:
        pass
