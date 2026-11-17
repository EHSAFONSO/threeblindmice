"""Dashboard local (FastAPI + HTMX) sobre o histórico do Squeak.

Só leitura: nenhum endpoint dispara scans. Assim, mesmo exposto por engano,
o dashboard não vira um scanner controlável pela rede.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tbm.dashboard.jobs import JobRunner
    from tbm.dashboard.security import GuiSettings

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from tbm import __version__
from tbm.dashboard.charts import score_chart, sparkline
from tbm.models import ScanResult
from tbm.squeak import HistoryStore, diff_scans, render_html
from tbm.squeak.notify import port_label

_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
_env.filters["port"] = port_label


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
        })
    return sorted(devices, key=lambda d: (-d["total"], d["host"].address))


def create_app(store: HistoryStore, gui: GuiSettings | None = None,
               runner: JobRunner | None = None) -> FastAPI:
    """Sem `gui`: dashboard somente leitura (`tbm dashboard`). Com `gui`: interface completa
    (`tbm gui`), que dispara scans e por isso exige token de sessão (ver security.py)."""
    app = FastAPI(title="threeblindmice", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url=None)

    def render(name: str, **ctx) -> HTMLResponse:
        nav = [r["label"] for r in store.labels()]
        return HTMLResponse(_env.get_template(name).render(
            version=__version__, nav_labels=nav, gui=gui is not None,
            csrf_token=gui.token if gui else "", **ctx))

    def series(label: str, limit: int = 30) -> list:
        return list(reversed(store.list(label, limit)))

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        labels = store.labels()
        sparks = {r["label"]: sparkline([s["score"] or 0 for s in series(r["label"], 20)]) for r in labels}
        return render("index.html.j2", labels=labels, sparks=sparks)

    @app.get("/partials/label/{label}", response_class=HTMLResponse)
    def label_panel(label: str) -> HTMLResponse:
        rows = series(label)
        if not rows:
            raise HTTPException(404, "rótulo sem scans")
        chart = score_chart([(_when(r["started_at"])[5:], r["score"] or 0) for r in rows])
        return render("label.html.j2", label=label, rows=list(reversed(rows)), chart=chart)

    @app.get("/partials/diff/{new_id}", response_class=HTMLResponse)
    def diff_panel(new_id: str) -> HTMLResponse:
        new = store.get(new_id)
        if new is None:
            raise HTTPException(404, "scan não encontrado")
        old = store.latest(new.label, exclude=new.scan_id, before=new.started_at.isoformat())
        return render("diff.html.j2", d=diff_scans(old, new), new=new)

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

    @app.get("/api/scans")
    def api_scans(label: str | None = None, limit: int = 50) -> JSONResponse:
        return JSONResponse([dict(r) for r in store.list(label, min(limit, 500))])

    if gui is not None:
        from tbm.dashboard.gui import install_gui
        from tbm.dashboard.jobs import JobRunner

        install_gui(app, store, gui, render, runner or JobRunner(store))
    return app
