"""Correlação de versões de serviços com CVEs via API 2.0 do NVD (NIST).

- Mapeamos o produto identificado no banner para um CPE (vendor:product).
- `virtualMatchString` pede ao NVD todos os CVEs cujas configurações casam com
  aquele CPE, incluindo faixas de versão (versionEndExcluding etc.).
- Resultados ficam em cache em disco por 24h; o limite público é de 5 req/30s
  (50 com API key: export NVD_API_KEY=...).

Limitação importante: distros Linux fazem backport de patches sem mudar a
versão anunciada (ex.: OpenSSH 8.2p1 no Ubuntu 20.04 tem correções de 9.x).
Por isso os achados de CVE são "potenciais" e pedem confirmação.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import httpx

from tbm.asyncutil import RateLimiter
from tbm.models import Finding, Host, Service, Severity
from tbm.sniffer.base import Check, CheckContext, register

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CPE_MAP: dict[str, list[tuple[str, str]]] = {
    "OpenSSH": [("openbsd", "openssh")],
    "Dropbear SSH": [("dropbear_ssh_project", "dropbear_ssh")],
    "nginx": [("f5", "nginx"), ("nginx", "nginx")],
    "OpenResty": [("openresty", "openresty")],
    "Apache httpd": [("apache", "http_server")],
    "Microsoft IIS": [("microsoft", "internet_information_services")],
    "lighttpd": [("lighttpd", "lighttpd")],
    "Jetty": [("eclipse", "jetty")],
    "vsftpd": [("vsftpd_project", "vsftpd"), ("beasts", "vsftpd")],
    "ProFTPD": [("proftpd", "proftpd")],
    "FileZilla Server": [("filezilla-project", "filezilla_server")],
    "Exim": [("exim", "exim")],
    "Redis": [("redis", "redis")],
    "MySQL": [("oracle", "mysql")],
    "MariaDB": [("mariadb", "mariadb")],
}


class NVDError(RuntimeError):
    pass


@dataclass
class CVERecord:
    id: str
    score: float | None
    description: str
    published: str | None = None
    kev: bool = False  # está no catálogo CISA de vulnerabilidades exploradas ativamente
    kev_action: str | None = None

    @property
    def url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.id}"


def cpe_candidates(product: str | None, version: str | None) -> list[str]:
    if not product or not version or product not in CPE_MAP:
        return []
    ver, update = version, "*"
    if product == "OpenSSH" and (m := re.match(r"^(\d+\.\d+)(p\d+)?", version)):
        ver, update = m.group(1), m.group(2) or "*"
    if not re.fullmatch(r"[\w.\-]+", ver):
        return []
    return [f"cpe:2.3:a:{v}:{p}:{ver}:{update}:*:*:*:*:*:*" for v, p in CPE_MAP[product]]


def _score(metrics: dict[str, Any]) -> float | None:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        with_score = primary.get("cvssData", {}).get("baseScore")
        if with_score is not None:
            return float(with_score)
    return None


def parse_nvd_response(payload: dict[str, Any]) -> list[CVERecord]:
    records = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        if cve.get("vulnStatus") == "Rejected":
            continue
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
        )
        records.append(CVERecord(
            id=cve["id"],
            score=_score(cve.get("metrics", {})),
            description=desc,
            published=cve.get("published"),
            kev="cisaExploitAdd" in cve,
            kev_action=cve.get("cisaRequiredAction"),
        ))
    return records


class NVDClient:
    def __init__(
        self,
        http: httpx.AsyncClient,
        api_key: str | None = None,
        cache_dir: Path | None = None,
        ttl: float = 86_400,
    ) -> None:
        self.http = http
        self.api_key = api_key
        self.cache_dir = cache_dir
        self.ttl = ttl
        self._limiter = RateLimiter(50 if api_key else 5, 30.0)
        self._memo: dict[str, list[CVERecord]] = {}

    def _cache_file(self, cpe: str) -> Path | None:
        if not self.cache_dir:
            return None
        return self.cache_dir / f"{hashlib.sha1(cpe.encode()).hexdigest()}.json"

    def _cache_get(self, cpe: str) -> list[CVERecord] | None:
        path = self._cache_file(cpe)
        if path is None or not path.exists() or time.time() - path.stat().st_mtime > self.ttl:
            return None
        try:
            return [CVERecord(**r) for r in json.loads(path.read_text(encoding="utf-8"))]
        except (OSError, ValueError, TypeError):
            return None

    def _cache_put(self, cpe: str, records: list[CVERecord]) -> None:
        path = self._cache_file(cpe)
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([asdict(r) for r in records]), encoding="utf-8")

    async def _request(self, params: dict[str, Any]) -> dict[str, Any]:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        for attempt in range(4):
            await self._limiter.acquire()
            try:
                resp = await self.http.get(NVD_URL, params=params, headers=headers, timeout=40)
            except httpx.HTTPError as exc:
                if attempt == 3:
                    raise NVDError(f"falha ao consultar o NVD: {exc}") from exc
                await asyncio.sleep(3 * (attempt + 1))
                continue
            if resp.status_code == 404:  # CPE sem correspondência
                return {"vulnerabilities": [], "totalResults": 0}
            if resp.status_code in (403, 429, 500, 502, 503):
                await asyncio.sleep(6 * (attempt + 1))
                continue
            resp.raise_for_status()
            return resp.json()
        raise NVDError("NVD indisponível ou limite de requisições excedido (use NVD_API_KEY)")

    async def search(self, cpe: str) -> list[CVERecord]:
        if cpe in self._memo:
            return self._memo[cpe]
        if (cached := self._cache_get(cpe)) is not None:
            self._memo[cpe] = cached
            return cached

        records: list[CVERecord] = []
        start = 0
        while True:
            payload = await self._request(
                {"virtualMatchString": cpe, "resultsPerPage": 500, "startIndex": start}
            )
            records += parse_nvd_response(payload)
            start += payload.get("resultsPerPage") or 500
            if start >= payload.get("totalResults", 0) or start >= 2000:
                break
        self._cache_put(cpe, records)
        self._memo[cpe] = records
        return records


def cve_finding(check_id: str, host: Host, svc: Service, rec: CVERecord) -> Finding:
    severity = Severity.CRITICAL if rec.kev else Severity.from_cvss(rec.score)
    desc = rec.description
    if rec.kev:
        desc = "⚠ Explorada ativamente (catálogo CISA KEV). " + desc
    desc += (
        "\n\nCorrespondência por versão anunciada no banner. Distros fazem backport de "
        "correções sem mudar a versão, então confirme antes de concluir."
    )
    return Finding(
        check_id=check_id,
        key=rec.id,
        severity=severity,
        title=f"{rec.id} em {svc.label}",
        host=host.address,
        port=svc.port,
        description=desc,
        evidence=f"Banner: {(svc.banner or svc.label)[:120]}",
        remediation=rec.kev_action or f"Atualize o {svc.product} para uma versão corrigida.",
        references=[rec.url],
        cvss=rec.score,
    )


@register
class CVECheck(Check):
    id = "cve.nvd"
    name = "CVEs conhecidos (NVD)"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.nvd is None:
            return []
        groups: dict[tuple[str, str], list[tuple[Host, Service]]] = {}
        for host, svc in ctx.services(lambda s: bool(cpe_candidates(s.product, s.version))):
            groups.setdefault((svc.product, svc.version), []).append((host, svc))  # type: ignore[arg-type]

        findings: list[Finding] = []
        for (product, version), locations in groups.items():
            records: dict[str, CVERecord] = {}
            for cpe in cpe_candidates(product, version):
                for rec in await ctx.nvd.search(cpe):
                    records[rec.id] = rec
            top = sorted(records.values(), key=lambda r: (r.kev, r.score or 0), reverse=True)
            top = top[: ctx.options.max_cves_per_service]
            for host, svc in locations:
                findings += [cve_finding(self.id, host, svc, rec) for rec in top]
        return findings
