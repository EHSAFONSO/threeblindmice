"""Filtro de backport: descarta CVEs que a distro já corrigiu sem mudar a versão.

O banner "OpenSSH_8.2p1 Ubuntu-4ubuntu0.9" diz *duas* coisas: a versão
upstream (8.2p1, que o NVD considera vulnerável a dezenas de CVEs) e a revisão
do pacote Ubuntu (4ubuntu0.9), que pode já ter as correções. Para cada CVE,
consultamos o tracker do Ubuntu e comparamos a versão do pacote instalado com
a versão em que a correção saiu, usando a mesma regra de ordenação do dpkg.

Debian: o banner também carrega a revisão, mas o tracker do Debian só
oferece um JSON único de ~70 MB. Nesse caso, apenas indicamos onde confirmar.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

UBUNTU_CVE_URL = "https://ubuntu.com/security/cves/{cve}.json"

# Pacotes cujo banner carrega a revisão da distro.
_BANNERS = (
    (re.compile(r"OpenSSH_([\w.]+)\s+Ubuntu-(\S+)"), "ubuntu", "openssh", 1),
    (re.compile(r"OpenSSH_([\w.]+)\s+Debian-(\S+)"), "debian", "openssh", 1),
)


@dataclass(frozen=True)
class DistroPackage:
    distro: str
    package: str
    version: str  # formato dpkg completo: epoch:upstream-revisão

    @property
    def upstream(self) -> str:
        return split_version(self.version)[1]


def distro_package(banner: str | None) -> DistroPackage | None:
    if not banner:
        return None
    for pattern, distro, package, epoch in _BANNERS:
        if m := pattern.search(banner):
            return DistroPackage(distro, package, f"{epoch}:{m.group(1)}-{m.group(2)}")
    return None


# ───────────────────── comparação de versões dpkg ─────────────────────


def split_version(v: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    upstream, revision = (v.rsplit("-", 1) + [""])[:2] if "-" in v else (v, "")
    return epoch, upstream, revision


def _order(c: str) -> int:
    if not c or c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    """Port direto do verrevcmp() do dpkg: '~' vem antes de tudo, letras antes de símbolos."""
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and j < len(b) and a[i].isdigit() and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def compare_versions(a: str, b: str) -> int:
    """<0 se a<b, 0 se iguais, >0 se a>b (semântica do `dpkg --compare-versions`)."""
    ea, ua, ra = split_version(a)
    eb, ub, rb = split_version(b)
    if ea != eb:
        return ea - eb
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


# ───────────────────────── tracker do Ubuntu ─────────────────────────


def ubuntu_fixed(payload: dict, pkg: DistroPackage) -> bool | None:
    """True = corrigido na versão instalada; False = vulnerável; None = não dá para afirmar."""
    for package in payload.get("packages", []):
        if package.get("name") != pkg.package:
            continue
        for status in package.get("statuses", []):
            state, fixed = status.get("status"), status.get("description") or ""
            if state == "released" and fixed:
                # A versão upstream identifica a release (focal = 8.2p1, jammy = 8.9p1...)
                if split_version(fixed)[1] != pkg.upstream:
                    continue
                return compare_versions(pkg.version, fixed) >= 0
            if state == "not-affected" and pkg.upstream in fixed:
                return True
    return None


class BackportResolver:
    def __init__(self, http: httpx.AsyncClient, cache_dir: Path | None = None, ttl: float = 86_400):
        self.http = http
        self.cache_dir = cache_dir / "ubuntu" if cache_dir else None
        self.ttl = ttl
        self._sem = asyncio.Semaphore(4)

    async def _ubuntu_payload(self, cve: str) -> dict | None:
        cache = self.cache_dir / f"{cve}.json" if self.cache_dir else None
        if cache and cache.exists() and time.time() - cache.stat().st_mtime < self.ttl:
            try:
                return json.loads(cache.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                pass
        async with self._sem:
            try:
                resp = await self.http.get(UBUNTU_CVE_URL.format(cve=cve), timeout=30,
                                           follow_redirects=True)
            except httpx.HTTPError:
                return None
        if resp.status_code != 200:
            return None
        try:
            payload = resp.json()
        except ValueError:
            return None
        if cache:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(payload), encoding="utf-8")
        return payload

    async def is_fixed(self, cve: str, pkg: DistroPackage) -> bool | None:
        if pkg.distro != "ubuntu":
            return None
        payload = await self._ubuntu_payload(cve)
        return ubuntu_fixed(payload, pkg) if payload else None
