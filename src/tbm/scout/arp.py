"""Endereço MAC (via tabela ARP do sistema) e fabricante (via base OUI do IEEE).

Depois que o Scout conversa com um host da rede local, o SO já guardou o MAC
dele na tabela ARP. Basta ler essa tabela, sem raw sockets e sem admin.
Isso só funciona para hosts no mesmo segmento L2: atrás de um roteador, o
MAC que aparece é o do roteador, então nem tentamos.
"""

from __future__ import annotations

import asyncio
import csv
import io
import re
import sys
from pathlib import Path

import httpx

from tbm import USER_AGENT
from tbm.paths import tbm_home

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_MAC_RE = re.compile(r"\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b")
_IGNORED_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}


def normalize_mac(raw: str) -> str:
    return ":".join(part.zfill(2) for part in re.split(r"[:-]", raw.lower()))


def is_randomized(mac: str) -> bool:
    """Bit 'locally administered': celulares modernos usam MAC aleatório por rede."""
    return bool(int(mac[:2], 16) & 0x02)


def is_multicast(mac: str) -> bool:
    return bool(int(mac[:2], 16) & 0x01)


def parse_arp_output(text: str) -> dict[str, str]:
    """Interpreta `arp -a` (Windows/macOS/BSD) ou /proc/net/arp (Linux)."""
    table: dict[str, str] = {}
    for line in text.splitlines():
        ip_m, mac_m = _IP_RE.search(line), _MAC_RE.search(line)
        if not ip_m or not mac_m:
            continue
        mac = normalize_mac(mac_m.group(1))
        if mac in _IGNORED_MACS or is_multicast(mac):
            continue
        table[ip_m.group(1)] = mac
    return table


async def read_arp_table() -> dict[str, str]:
    proc_arp = Path("/proc/net/arp")
    if await asyncio.to_thread(proc_arp.exists):
        return parse_arp_output(await asyncio.to_thread(proc_arp.read_text))
    cmd = ["arp", "-a"] if sys.platform == "win32" else ["arp", "-an"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        out, _ = await asyncio.wait_for(proc.communicate(), 10)
    except (OSError, TimeoutError):
        return {}
    return parse_arp_output(out.decode("utf-8", errors="ignore"))


class OUIDatabase:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or tbm_home() / "oui.csv"
        self._db: dict[str, str] | None = None

    @property
    def available(self) -> bool:
        return self.path.exists()

    def _load(self) -> dict[str, str]:
        if self._db is None:
            self._db = {}
            if self.available:
                with self.path.open(encoding="utf-8", errors="replace", newline="") as fh:
                    for row in csv.DictReader(fh):
                        assignment = (row.get("Assignment") or "").upper()
                        if len(assignment) == 6:
                            self._db[assignment] = (row.get("Organization Name") or "").strip()
        return self._db

    def lookup(self, mac: str) -> str | None:
        if is_randomized(mac):
            return "MAC aleatório (privacidade)"
        return self._load().get(mac.replace(":", "")[:6].upper())


async def download_oui(dest: Path | None = None) -> int:
    """Baixa a base oficial do IEEE (~3 MB) e devolve o número de fabricantes."""
    dest = dest or tbm_home() / "oui.csv"
    async with httpx.AsyncClient(timeout=120, headers={"User-Agent": USER_AGENT},
                                 follow_redirects=True) as client:
        resp = await client.get(OUI_URL)
        resp.raise_for_status()
    rows = list(csv.DictReader(io.StringIO(resp.text)))
    if not rows or "Assignment" not in rows[0]:
        raise ValueError("formato inesperado do oui.csv")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(resp.text, encoding="utf-8")
    return len(rows)
