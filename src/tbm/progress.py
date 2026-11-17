"""Interface de progresso desacoplada da UI.

Os engines só conhecem `ProgressHook`; a CLI pluga uma implementação com Rich,
os testes usam `NullProgress`.
"""

from __future__ import annotations

from typing import Protocol


class ProgressHook(Protocol):
    def start(self, phase: str, total: int) -> None: ...
    def advance(self, phase: str, amount: int = 1) -> None: ...
    def log(self, message: str) -> None: ...


class NullProgress:
    def start(self, phase: str, total: int) -> None:
        pass

    def advance(self, phase: str, amount: int = 1) -> None:
        pass

    def log(self, message: str) -> None:
        pass
