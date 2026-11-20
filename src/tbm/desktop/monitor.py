"""Vigia em tempo real: ouve a rede entre os scans e avisa na hora.

Enquanto o app está aberto (inclusive só na bandeja), uma thread relê a tabela
ARP a cada minuto. Um MAC novo, que não está entre os aparelhos aprovados e nem
apareceu no último scan, vira uma notificação imediata e um evento na central —
sem esperar o próximo scan agendado.

É leve e passivo: só lê a tabela que o sistema já mantém. Não escaneia portas
nem envia nada. O scan completo continua sendo o que classifica e dá nota.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable

from tbm.scout.arp import OUIDatabase, read_arp_table
from tbm.squeak import HistoryStore


class LiveMonitor:
    def __init__(self, store: HistoryStore, on_new: Callable[[str, str], None], interval: float = 60.0) -> None:
        self.store = store
        self.on_new = on_new  # (título, texto) para a notificação da bandeja
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._known: set[str] = set()
        self._alerted: set[str] = set()

    def _baseline(self) -> set[str]:
        """MACs que já conhecemos: aprovados + vistos no último scan de cada rótulo."""
        macs = {row["identity"].removeprefix("mac:") for row in self.store.devices().values()
                if row["identity"].startswith("mac:")}
        for row in self.store.labels():
            for scan in self.store.light(row["label"], 1):  # só os índices, sem abrir o relatório
                macs.update(h.mac for h in scan.hosts if h.mac)
        return macs

    def start(self) -> None:
        self._known = self._baseline()
        self._thread = threading.Thread(target=self._loop, name="tbm-live", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        loop = asyncio.new_event_loop()
        try:
            while not self._stop.wait(self.interval):
                try:
                    self._tick(loop)
                except Exception as exc:  # noqa: BLE001 (o vigia nunca derruba o app)
                    from tbm.log import get_logger

                    log = get_logger(__name__)
                    log.warning("vigia em tempo real: %s", exc.__class__.__name__)
                    log.debug("vigia em tempo real: detalhes", exc_info=True)  # a mensagem pode citar IP
        finally:
            loop.close()

    def _tick(self, loop: asyncio.AbstractEventLoop) -> None:
        table = loop.run_until_complete(read_arp_table())
        oui = OUIDatabase()
        for ip, mac in table.items():
            if mac in self._known or mac in self._alerted:
                continue
            self._alerted.add(mac)
            vendor = oui.lookup(mac) or "fabricante desconhecido"
            self.store.add_event("unknown_device", {"name": vendor, "address": ip}, link="/inventory")
            self.on_new("Aparelho novo na rede",
                        f"{ip} ({vendor}) apareceu agora. Rode um scan para avaliá-lo.")
