"""Orquestrador do Sniffer: roda os checks registrados em paralelo."""

from __future__ import annotations

import asyncio
import traceback

import httpx

from tbm import USER_AGENT
from tbm.models import Finding, ScanResult
from tbm.progress import NullProgress, ProgressHook
from tbm.scope import Scope
from tbm.sniffer import (  # noqa: F401 (importar registra os checks)
    cve,
    http_checks,
    secrets,
    service_checks,
    smb_checks,
    ssh_checks,
    tls_checks,
    udp_checks,
)
from tbm.sniffer.base import REGISTRY, Check, CheckContext, SnifferOptions
from tbm.sniffer.cve import NVDClient

PHASE = "Sniffer · checks"


class Sniffer:
    def __init__(self, options: SnifferOptions, progress: ProgressHook | None = None) -> None:
        self.o = options
        self.p = progress or NullProgress()

    def checks(self) -> list[Check]:
        return [c for cls in REGISTRY.values() if (c := cls()).enabled(self.o)]

    async def run(self, scan: ScanResult) -> tuple[list[Finding], list[str]]:
        # Defesa em profundidade: mesmo que o ScanResult venha de um JSON editado
        # à mão, nenhum check (principalmente os ativos) toca host fora do escopo.
        (self.o.scope or Scope.default()).enforce(h.address for h in scan.hosts)

        checks = self.checks()
        self.p.start(PHASE, len(checks))
        errors: list[str] = []

        async with httpx.AsyncClient(
            verify=False,  # noqa: S501 (queremos inspecionar certificados ruins)
            timeout=self.o.http_timeout,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
            limits=httpx.Limits(max_connections=64),
        ) as http:
            nvd = (
                NVDClient(http, api_key=self.o.nvd_api_key, cache_dir=self.o.cache_dir)
                if self.o.cve
                else None
            )
            ctx = CheckContext(scan=scan, http=http, options=self.o, nvd=nvd)

            async def run_one(check: Check) -> list[Finding]:
                try:
                    return await check.run(ctx)
                except Exception as exc:  # um check quebrado não derruba o scan
                    errors.append(f"{check.id}: {exc.__class__.__name__}: {exc}")
                    self.p.log(traceback.format_exc(limit=3))
                    return []
                finally:
                    self.p.advance(PHASE)

            batches = await asyncio.gather(*(run_one(c) for c in checks))

        unique: dict[str, Finding] = {}
        for f in (f for batch in batches for f in batch):
            unique.setdefault(f.fingerprint, f)
        return sorted(unique.values(), key=Finding.sort_key), errors
