"""Orquestrador do Sniffer: roda os checks registrados em paralelo."""

from __future__ import annotations

import asyncio
import re
import traceback

import httpx

from tbm import USER_AGENT
from tbm.models import Finding, ScanResult
from tbm.progress import NullProgress, ProgressHook
from tbm.scope import Scope
from tbm.sniffer import (  # noqa: F401 (importar registra os checks)
    cve,
    http_checks,
    iot_checks,
    network_checks,
    secrets,
    service_checks,
    smb_checks,
    ssh_checks,
    tls_checks,
    udp_checks,
    upnp_checks,
)
from tbm.sniffer.base import REGISTRY, Check, CheckContext, SnifferOptions
from tbm.sniffer.context import apply_context
from tbm.sniffer.cve import NVDClient

PHASE = "Sniffer · checks"


class Sniffer:
    def __init__(self, options: SnifferOptions, progress: ProgressHook | None = None) -> None:
        self.o = options
        self.p = progress or NullProgress()

    def checks(self) -> list[Check]:
        from tbm.plugins import load_plugins

        load_plugins()  # só os plugins autorizados em `tbm plugins enable`
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

        # Amarra cada achado à identidade do dispositivo (MAC/nome), não ao IP:
        # assim o fingerprint sobrevive à troca de IP pelo DHCP.
        identities = {h.address: h.identity for h in scan.hosts}
        unique: dict[str, Finding] = {}
        for f in (f for batch in batches for f in batch):
            if f.device is None and f.host in identities:
                f.device = identities[f.host]
            unique.setdefault(f.fingerprint, f)
        merged = merge_cve_duplicates(list(unique.values()))
        apply_context(merged)
        return sorted(merged, key=Finding.sort_key), errors


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def merge_cve_duplicates(findings: list[Finding]) -> list[Finding]:
    """Remove o achado genérico do NVD quando um check específico já cobre o mesmo CVE.

    Exemplo: o Terrapin (CVE-2023-48795) aparecia duas vezes, como CVE do
    Dropbear e como achado de ssh.algorithms, e era contado em dobro na nota.
    Ficamos com o específico, que tem evidência e correção melhores, e ele
    herda do genérico o que só o NVD sabe: EPSS, KEV, CVSS e a severidade maior.
    """
    generic = {
        (f.host, f.port, f.key): f
        for f in findings
        if f.check_id == "cve.nvd" and CVE_RE.fullmatch(f.key)
    }
    if not generic:
        return findings
    absorbed: set[str] = set()
    for f in findings:
        if f.check_id == "cve.nvd":
            continue
        for cve_id in sorted(set(CVE_RE.findall(" ".join([f.title, *f.references])))):
            g = generic.get((f.host, f.port, cve_id))
            if g is None:
                continue
            absorbed.add(g.fingerprint)
            f.kev = f.kev or g.kev
            f.cvss = f.cvss if f.cvss is not None else g.cvss
            if g.epss is not None and f.epss is None:
                f.epss = g.epss
                if g.epss >= 0.01:
                    f.title += f" · EPSS {g.epss:.0%}"
            if g.severity.rank > f.severity.rank:
                f.severity = g.severity
            if g.references and g.references[0] not in f.references:
                f.references.append(g.references[0])
    return [f for f in findings if f.fingerprint not in absorbed]
