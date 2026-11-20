"""Checkpoint do Scout em redes grandes: um scan interrompido continua de onde parou.

O arquivo guarda o resultado da descoberta e os aparelhos já varridos, bloco /24 por
bloco /24. Fica em TBM_HOME/checkpoints/<rótulo>.json, com permissão só do dono (é
o inventário da sua rede), e é apagado quando o Scout termina. Só é reaproveitado se
os alvos e as portas forem os mesmos (`tbm scan --resume`).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

from tbm.models import Host
from tbm.paths import private_dir, private_file, tbm_home
from tbm.scout.discovery import Announcement

VERSION = 1


def checkpoint_path(label: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)[:60] or "default"
    return private_dir(tbm_home() / "checkpoints") / f"{safe}.json"


def fingerprint(addresses: list[str], ports: list[int], udp: bool) -> str:
    raw = ",".join(sorted(addresses)) + "|" + ",".join(map(str, sorted(ports))) + f"|{udp}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


class Checkpoint:
    def __init__(self, path: Path, key: str, data: dict[str, Any] | None = None) -> None:
        self.path = path
        self.key = key
        self.data = data or {"version": VERSION, "key": key, "discovery": None, "scanned": [], "hosts": []}

    @classmethod
    def open(cls, path: Path, key: str, *, resume: bool) -> tuple[Checkpoint, bool]:
        """(checkpoint, retomou?). Sem `resume`, ou com alvos diferentes, começa do zero."""
        if resume and path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = None
            if data and data.get("version") == VERSION and data.get("key") == key:
                return cls(path, key, data), True
        return cls(path, key), False

    # ───────────── descoberta ─────────────

    @property
    def discovery(self) -> dict[str, Any] | None:
        return self.data["discovery"]

    def save_discovery(self, alive: list[str], found_by: dict[str, set[str]], gateway: str | None,
                       announcements: dict[str, Announcement], timeout: float) -> None:
        self.data["discovery"] = {
            "alive": alive, "gateway": gateway, "timeout": timeout,
            "found_by": {ip: sorted(m) for ip, m in found_by.items()},
            "announcements": {ip: {k: sorted(v) if isinstance(v, set) else v for k, v in asdict(a).items()}
                              for ip, a in announcements.items()},
        }
        self._write()

    def announcements(self) -> dict[str, Announcement]:
        out = {}
        for ip, raw in (self.discovery or {}).get("announcements", {}).items():
            fields: dict[str, Any] = {k: set(v) if isinstance(v, list) else v for k, v in raw.items()}
            out[ip] = Announcement(**fields)
        return out

    # ───────────── varredura ─────────────

    @property
    def scanned(self) -> set[str]:
        return set(self.data["scanned"])

    def hosts(self) -> list[Host]:
        return [Host.model_validate(h) for h in self.data["hosts"]]

    def add(self, addresses: list[str], hosts: list[Host]) -> None:
        self.data["scanned"] += addresses
        self.data["hosts"] += [h.model_dump(mode="json") for h in hosts]
        self._write()

    def finish(self) -> None:
        self.path.unlink(missing_ok=True)

    def _write(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data), encoding="utf-8")
        private_file(tmp)
        os.replace(tmp, self.path)
