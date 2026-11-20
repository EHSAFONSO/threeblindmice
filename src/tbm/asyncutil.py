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


class AdaptiveSemaphore(asyncio.Semaphore):
    """Semáforo que reduz o próprio limite quando o sistema começa a recusar sockets.

    Roteadores domésticos e o próprio Windows (falta de portas efêmeras, WSAENOBUFS)
    passam a falhar sob centenas de conexões. Cada falha desse tipo é avisada com
    `report_error()`; com muitas numa janela curta, metade das vagas é "estacionada"
    (adquirida e nunca devolvida) até o fim do scan. Nunca desce abaixo de `floor`.
    """

    def __init__(self, value: int, *, floor: int = 16, burst: int = 20, window: float = 2.0) -> None:
        super().__init__(value)
        self.limit = value
        self.floor = min(floor, value)
        self.burst = burst
        self.window = window
        self.shrinks = 0
        self._errors: deque[float] = deque()
        self._parking: list[asyncio.Task[None]] = []

    def report_error(self) -> None:
        now = time.monotonic()
        self._errors.append(now)
        while self._errors and now - self._errors[0] > self.window:
            self._errors.popleft()
        if len(self._errors) >= self.burst and self.limit > self.floor:
            new = max(self.floor, self.limit // 2)
            self._parking.append(asyncio.ensure_future(self._park(self.limit - new)))
            self.limit = new
            self.shrinks += 1
            self._errors.clear()

    async def _park(self, n: int) -> None:
        for _ in range(n):
            await self.acquire()

    def close(self) -> None:
        for t in self._parking:
            t.cancel()


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
