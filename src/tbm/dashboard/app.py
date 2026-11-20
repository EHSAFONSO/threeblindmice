"""Dashboard local (FastAPI) sobre o histórico do Squeak.

Sem `gui`: somente leitura. Nenhum endpoint dispara scans, então, mesmo
exposto por engano, ele não vira um scanner controlável pela rede.
Com `gui`: interface completa (rotas em routes/, proteção em security.py).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from tbm import __version__, i18n
from tbm.dashboard.icons import device_icon
from tbm.dashboard.routes import Ctx, include_all
from tbm.dashboard.templating import (  # noqa: F401 (reexportados: API usada nos testes e templates)
    CATEGORIES,
    HERE,
    SEV_NAMES,
    action_title,
    make_render,
    mini_path,
    sev_name,
)
from tbm.dashboard.views import worst
from tbm.models import ScanResult
from tbm.squeak import HistoryStore

if TYPE_CHECKING:
    from tbm.dashboard.jobs import JobRunner
    from tbm.dashboard.security import GuiSettings


def build_inventory(history: list[ScanResult], seen: dict[str, dict] | None = None) -> list[dict]:
    """Dispositivos do último scan, com primeira aparição, frequência e IPs anteriores.

    `history` vem do mais antigo para o mais novo. O casamento é pela identidade
    (MAC/nome), então troca de IP não cria um "dispositivo novo". Com `seen`
    (de `HistoryStore.sightings`), basta passar o último scan em `history`.
    """
    latest = history[-1]
    if seen is None:
        seen = {}
        for scan in history:
            for h in scan.hosts:
                entry = seen.setdefault(h.identity, {"first": scan.started_at, "times": 0, "ips": []})
                entry["times"] += 1
                if not entry["ips"] or entry["ips"][-1] != h.address:
                    entry["ips"].append(h.address)
    by_host: dict[str, list] = {}
    for f in latest.findings:
        by_host.setdefault(f.host, []).append(f)
    devices = []
    for h in latest.hosts:
        mine = by_host.get(h.address, [])
        counts = {s: sum(1 for f in mine if f.severity.value == s and not f.accepted)
                  for s in ("critical", "high", "medium", "low")}
        info = seen.get(h.identity) or {"first": latest.started_at, "times": 1, "ips": [h.address]}
        devices.append({
            "host": h,
            "services": [s for s in h.discovery.get("mdns_services", "").split(",") if s][:6],
            "counts": counts,
            "total": sum(counts.values()),
            "accepted": sum(1 for f in mine if f.accepted),
            "first_seen": info["first"].strftime("%d/%m/%Y"),
            "times_seen": info["times"],
            "ips": info["ips"],
            "icon": device_icon(h.device_type),
            "sev": worst(latest, h.address),
        })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
    return sorted(devices, key=lambda d: (order[d["sev"]], -d["total"], d["host"].address))



def create_app(store: HistoryStore, gui: GuiSettings | None = None,
               runner: JobRunner | None = None) -> FastAPI:
    """Sem `gui`: dashboard somente leitura (`tbm dashboard`). Com `gui`: interface completa
    (`tbm gui`/`tbm app`), que dispara scans e por isso exige token de sessão (ver security.py)."""
    app = FastAPI(title="threeblindmice", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    class LanguageMiddleware:
        """Escolhe o idioma da requisição: cookie tbm-lang, senão o Accept-Language do navegador."""

        def __init__(self, inner):
            self.inner = inner

        async def __call__(self, scope, receive, send):
            if scope["type"] != "http":
                return await self.inner(scope, receive, send)
            headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
            cookies = {}
            for part in headers.get("cookie", "").split(";"):
                k, _, v = part.strip().partition("=")
                cookies[k] = v
            lang = i18n.normalize(cookies.get(i18n.COOKIE)) or i18n.from_accept_language(headers.get("accept-language"))
            with i18n.use(lang):
                await self.inner(scope, receive, send)

    app.add_middleware(LanguageMiddleware)

    if gui is not None:
        from tbm.dashboard.jobs import JobRunner
        from tbm.dashboard.security import check_request

        runner = runner or JobRunner(store)

        @app.middleware("http")
        async def guard(request: Request, call_next):
            blocked = check_request(request, gui)
            return blocked if blocked is not None else await call_next(request)

    include_all(app, Ctx(store=store, render=make_render(store, gui), gui=gui, runner=runner))
    return app
