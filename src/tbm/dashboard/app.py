"""Dashboard local (FastAPI + HTMX) sobre o histórico do Squeak.

Só leitura: nenhum endpoint dispara scans. Assim, mesmo exposto por engano,
o dashboard não vira um scanner controlável pela rede.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from tbm import __version__
from tbm.dashboard.charts import score_chart, sparkline
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


def create_app(store: HistoryStore) -> FastAPI:
    app = FastAPI(title="threeblindmice", version=__version__, docs_url=None, redoc_url=None)

    def render(name: str, **ctx) -> HTMLResponse:
        return HTMLResponse(_env.get_template(name).render(version=__version__, **ctx))

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

    @app.get("/api/scans")
    def api_scans(label: str | None = None, limit: int = 50) -> JSONResponse:
        return JSONResponse([dict(r) for r in store.list(label, min(limit, 500))])

    return app
