"""Primitivas assíncronas reutilizadas pelos engines."""

from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import Awaitable, Callable, Iterable
from typing import TypeVar

T = TypeVar("T")


async def gather_limited(factories: Iterable[Callable[[], Awaitable[T]]], limit: int) -> list[T]:
    """Como asyncio.gather, mas com no máximo `limit` corrotinas vivas por vez.

    Recebe *fábricas* (callables), não corrotinas, para não criar milhões de
    objetos de corrotina de uma vez ao escanear um /16 com todas as portas.
    Os workers compartilham o mesmo iterador; como `next()` é síncrono, não há
    corrida no event loop.
    """
    iterator = enumerate(factories)
    results: dict[int, T] = {}

    async def worker() -> None:
        for idx, factory in iterator:
            results[idx] = await factory()

    await asyncio.gather(*(worker() for _ in range(max(1, limit))))
    return [results[i] for i in sorted(results)]


class RateLimiter:
    """Janela deslizante: no máximo `max_calls` a cada `period` segundos."""

    def __init__(self, max_calls: int, period: float) -> None:
        self.max_calls = max_calls
        self.period = period
        self._calls: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                while self._calls and now - self._calls[0] >= self.period:
                    self._calls.popleft()
                if len(self._calls) < self.max_calls:
                    self._calls.append(now)
                    return
                await asyncio.sleep(self.period - (now - self._calls[0]) + 0.05)
