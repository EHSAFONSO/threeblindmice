"""Dashboard local (FastAPI) sobre o histórico do Squeak.

Sem `gui`: somente leitura. Nenhum endpoint dispara scans, então, mesmo
exposto por engano, ele não vira um scanner controlável pela rede.
Com `gui`: interface completa (ver gui.py e security.py).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tbm.dashboard.jobs import JobRunner
    from tbm.dashboard.security import GuiSettings

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

from tbm import __version__, i18n
from tbm.dashboard.charts import sparkline
from tbm.dashboard.icons import device_icon
from tbm.dashboard.views import device_detail, health, network_map, timeline, worst
from tbm.models import ScanResult
from tbm.squeak import HistoryStore, diff_scans, render_html
from tbm.squeak.notify import port_label

HERE = Path(__file__).parent
_env = Environment(
    loader=FileSystemLoader(HERE / "templates"),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
_env.filters["port"] = port_label
_env.globals["device_icon"] = device_icon
_env.globals["_"] = i18n.gettext
_env.globals["html_lang"] = i18n.html_lang
_env.globals["get_lang"] = i18n.get_lang
_env.globals["js_i18n"] = i18n.js_catalog
_env.globals["LANGS"] = i18n.LANGS
_env.filters["dtype"] = i18n.device_type


def action_guide(action, scan):
    """Passo a passo da correção no modelo do roteador (ou None)."""
    from tbm.squeak.guides import guide_for

    return guide_for(action.kind, scan.host(action.host), scan.gateway)


_env.globals["action_guide"] = action_guide


def action_title(action) -> str:
    """Título da ação no idioma da interface (o modelo do tipo é traduzido, o aparelho não)."""
    from tbm.squeak.actions import KINDS

    device = action.device
    if action.device_type and action.device_type in device:
        device = device.replace(action.device_type, i18n.device_type(action.device_type) or action.device_type)
    if action.kind in KINDS:
        return i18n.gettext(KINDS[action.kind].title).replace("{dev}", device)
    return action.title


_env.globals["action_title"] = action_title


def _when(iso: str) -> str:
    return iso[:16].replace("T", " ")


_env.filters["when"] = _when


def build_inventory(history: list[ScanResult]) -> list[dict]:
    """Dispositivos do último scan, com primeira aparição, frequência e IPs anteriores.

    `history` vem do mais antigo para o mais novo. O casamento é pela identidade
    (MAC/nome), então troca de IP não cria um "dispositivo novo".
    """
    latest = history[-1]
    seen: dict[str, dict] = {}
    for scan in history:
        for h in scan.hosts:
            entry = seen.setdefault(h.identity, {"first": scan.started_at, "times": 0, "ips": []})
            entry["times"] += 1
            if not entry["ips"] or entry["ips"][-1] != h.address:
                entry["ips"].append(h.address)
    devices = []
    for h in latest.hosts:
        mine = [f for f in latest.findings if f.host == h.address]
        counts = {s: sum(1 for f in mine if f.severity.value == s and not f.accepted)
                  for s in ("critical", "high", "medium", "low")}
        info = seen[h.identity]
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

    @app.get("/lang/{code}")
    def set_language(code: str, request: Request) -> RedirectResponse:
        from urllib.parse import urlparse

        lang = i18n.normalize(code) or i18n.DEFAULT
        # volta para a página de onde veio (só o caminho: nunca redireciona para outro site)
        ref = urlparse(request.headers.get("referer", ""))
        target = ref.path if ref.path.startswith("/") and not ref.path.startswith("//") else "/"
        if ref.query:
            target += "?" + ref.query
        resp = RedirectResponse(target, status_code=303)
        resp.set_cookie(i18n.COOKIE, lang, max_age=365 * 86400, samesite="strict", httponly=False)
        return resp

    def render(name: str, **ctx) -> HTMLResponse:
        nav = [r["label"] for r in store.labels()]
        return HTMLResponse(_env.get_template(name).render(
            version=__version__, nav_labels=nav, gui=gui is not None,
            csrf_token=gui.token if gui else "", **ctx))

    def latest_label() -> str | None:
        labels = store.labels()
        return max(labels, key=lambda r: r["started_at"])["label"] if labels else None

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request, label: str | None = None):
        chosen = label or latest_label()
        if chosen is None:
            if gui is not None:
                return RedirectResponse("/welcome", status_code=303)
            return render("index.html.j2", h=None, sparks={})
        data = health(store, chosen)
        if data is None:
            raise HTTPException(404, "rótulo sem scans")
        sparks = {lb: sparkline([r["score"] or 0 for r in reversed(store.list(lb, 20))]) for lb in data.labels}
        return render("index.html.j2", h=data, sparks=sparks)

    @app.get("/partials/label/{label}", response_class=HTMLResponse)
    def label_panel(label: str) -> HTMLResponse:
        rows = store.list(label, 30)
        if not rows:
            raise HTTPException(404, "rótulo sem scans")
        return render("label.html.j2", label=label, rows=rows, t=timeline(store, label))

    @app.get("/partials/diff/{new_id}", response_class=HTMLResponse)
    def diff_panel(new_id: str) -> HTMLResponse:
        new = store.get(new_id)
        if new is None:
            raise HTTPException(404, "scan não encontrado")
        old = store.latest(new.label, exclude=new.scan_id, before=new.started_at.isoformat())
        return render("diff.html.j2", d=diff_scans(old, new), new=new)

    @app.get("/partials/device/{label}/{address}", response_class=HTMLResponse)
    def device_panel(label: str, address: str) -> HTMLResponse:
        data = device_detail(store, label, address)
        if data is None:
            raise HTTPException(404, "dispositivo não encontrado")
        return render("device.html.j2", **data)

    @app.get("/scan/{scan_id}", response_class=HTMLResponse)
    def scan_report(scan_id: str) -> HTMLResponse:
        try:
            result = store.get(scan_id)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        if result is None:
            raise HTTPException(404, "scan não encontrado")
        previous = store.latest(result.label, exclude=result.scan_id, before=result.started_at.isoformat())
        return HTMLResponse(render_html(result, diff_scans(previous, result)))

    @app.get("/inventory/{label}", response_class=HTMLResponse)
    def inventory(label: str) -> HTMLResponse:
        rows = store.list(label, 50)
        if not rows:
            raise HTTPException(404, "rótulo sem scans")
        history = [s for r in reversed(rows) if (s := store.get(r["scan_id"])) is not None]
        latest = history[-1]
        return render("inventory.html.j2", label=label, scan=latest,
                      devices=build_inventory(history), scans_seen=len(history))

    @app.get("/map")
    def map_default():
        label = latest_label()
        return RedirectResponse(f"/map/{label}" if label else "/", status_code=303)

    @app.get("/map/{label}", response_class=HTMLResponse)
    def network(label: str) -> HTMLResponse:
        scan = store.latest(label)
        if scan is None:
            raise HTTPException(404, "rótulo sem scans")
        return render("map.html.j2", label=label, scan=scan, m=network_map(scan))

    @app.get("/api/scans")
    def api_scans(label: str | None = None, limit: int = 50) -> JSONResponse:
        return JSONResponse([dict(r) for r in store.list(label, min(limit, 500))])

    if gui is not None:
        from tbm.dashboard.gui import install_gui
        from tbm.dashboard.jobs import JobRunner

        install_gui(app, store, gui, render, runner or JobRunner(store))
    return app
