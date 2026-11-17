"""EPSS (Exploit Prediction Scoring System), da FIRST.org.

O CVSS mede o estrago possível; o EPSS estima a probabilidade de a falha ser
explorada nos próximos 30 dias, com base em telemetria real. A maioria dos
CVEs com CVSS alto tem EPSS < 1%. Combinado com o CISA KEV, é o que separa o
"urgente" do "teórico".
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import httpx

EPSS_URL = "https://api.first.org/data/v1/epss"
BATCH = 100


class EPSSClient:
    def __init__(self, http: httpx.AsyncClient, cache_dir: Path | None = None, ttl: float = 86_400):
        self.http = http
        self.cache_file = cache_dir / "epss.json" if cache_dir else None
        self.ttl = ttl
        self._scores: dict[str, tuple[float, float]] = self._load()

    def _load(self) -> dict[str, tuple[float, float]]:
        if not self.cache_file or not self.cache_file.exists():
            return {}
        try:
            raw = json.loads(self.cache_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        now = time.time()
        return {k: (v[0], v[1]) for k, v in raw.items() if now - v[1] < self.ttl}

    def _save(self) -> None:
        if self.cache_file:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(self._scores), encoding="utf-8")

    async def scores(self, cve_ids: list[str]) -> dict[str, float]:
        missing = [c for c in dict.fromkeys(cve_ids) if c not in self._scores]
        now = time.time()
        for i in range(0, len(missing), BATCH):
            chunk = missing[i: i + BATCH]
            try:
                resp = await self.http.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=30)
                resp.raise_for_status()
                data = resp.json().get("data", [])
            except (httpx.HTTPError, ValueError):
                continue  # EPSS é enriquecimento: falhar aqui não pode derrubar o check
            for row in data:
                self._scores[row["cve"]] = (float(row["epss"]), now)
            # CVE sem EPSS (muito novo ou rejeitado) também é cacheado, como 0
            for cve in chunk:
                self._scores.setdefault(cve, (0.0, now))
        if missing:
            self._save()
        return {c: self._scores[c][0] for c in cve_ids if c in self._scores}
