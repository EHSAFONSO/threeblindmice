"""Rotas interativas da interface gráfica: novo scan, achados com aceitação, catálogo."""

from __future__ import annotations

from collections.abc import Callable
from datetime import date

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, ValidationError, field_validator

from tbm.dashboard.features import TOOLS, catalog
from tbm.dashboard.jobs import BusyError, JobRunner, ScanParams
from tbm.dashboard.security import GuiSettings, check_request
from tbm.models import Severity
from tbm.scope import ScopeError
from tbm.scout.discovery import suggested_target
from tbm.squeak import HistoryStore
from tbm.squeak.acceptance import is_active

Render = Callable[..., HTMLResponse]


class AcceptBody(BaseModel):
    fingerprint: str
    label: str
    reason: str
    until: str | None = None

    @field_validator("reason")
    @classmethod
    def _reason(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("explique por que o risco é aceito")
        return v.strip()[:300]

    @field_validator("until")
    @classmethod
    def _until(cls, v: str | None) -> str | None:
        if v:
            if date.fromisoformat(v) < date.today():
                raise ValueError("a validade precisa ser uma data futura")
        return v or None


class FingerprintBody(BaseModel):
    fingerprint: str


def _errors(exc: ValidationError) -> str:
    return "; ".join(str(e["msg"]).removeprefix("Value error, ") for e in exc.errors())


def install_gui(app: FastAPI, store: HistoryStore, gui: GuiSettings, render: Render,
                runner: JobRunner) -> None:
    @app.middleware("http")
    async def guard(request: Request, call_next):
        blocked = check_request(request, gui)
        return blocked if blocked is not None else await call_next(request)

    def latest_label() -> str | None:
        labels = store.labels()
        return max(labels, key=lambda r: r["started_at"])["label"] if labels else None

    # ───────────────────────── novo scan ─────────────────────────

    @app.get("/scan", response_class=HTMLResponse)
    def scan_form() -> HTMLResponse:
        current = runner.current
        running = current.id if current and current.status in ("queued", "running") else None
        return render("scan.html.j2", suggested=suggested_target(), label=latest_label() or "casa",
                      running=running)

    @app.post("/api/scan")
    async def start_scan(request: Request) -> JSONResponse:
        try:
            params = ScanParams.model_validate(await request.json())
            job = runner.submit(params)
        except ValidationError as exc:
            return JSONResponse({"error": _errors(exc)}, status_code=400)
        except (ScopeError, ValueError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        except BusyError as exc:
            return JSONResponse({"error": str(exc)}, status_code=409)
        return JSONResponse({"job": job.id}, status_code=202)

    @app.get("/api/jobs/{job_id}")
    def job_status(job_id: str) -> JSONResponse:
        job = runner.jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "job não encontrado")
        return JSONResponse(job.to_dict())

    # ───────────────────────── achados ─────────────────────────

    @app.get("/findings")
    def findings_default() -> RedirectResponse:
        label = latest_label()
        return RedirectResponse(f"/findings/{label}" if label else "/scan", status_code=303)

    @app.get("/inventory")
    def inventory_default() -> RedirectResponse:
        label = latest_label()
        return RedirectResponse(f"/inventory/{label}" if label else "/scan", status_code=303)

    @app.get("/findings/{label}", response_class=HTMLResponse)
    def findings(label: str) -> HTMLResponse:
        scan = store.latest(label)
        if scan is None:
            raise HTTPException(404, "rótulo sem scans")
        acceptances = store.acceptances()
        devices = {h.address: h for h in scan.hosts}
        rows = []
        for f in scan.findings:
            row = acceptances.get(f.fingerprint)
            pending = row is not None and is_active(row) and not f.accepted  # vale no próximo scan
            h = devices.get(f.host)
            rows.append({"f": f, "pending": pending, "accepted_now": f.accepted or pending,
                         "device": (h.device_name or h.device_type or h.address) if h else f.host})
        return render("findings.html.j2", label=label, scan=scan, rows=rows,
                      severities=sorted(Severity, key=lambda s: -s.rank),
                      device_names=sorted({r["device"] for r in rows}))

    @app.post("/api/accept")
    async def accept(request: Request) -> JSONResponse:
        try:
            body = AcceptBody.model_validate(await request.json())
        except ValidationError as exc:
            return JSONResponse({"error": _errors(exc)}, status_code=400)
        scan = store.latest(body.label)
        match = next((f for f in scan.findings if f.fingerprint == body.fingerprint), None) if scan else None
        if match is None:
            return JSONResponse({"error": "achado não encontrado no último scan"}, status_code=404)
        store.accept(match.fingerprint, body.reason, until=body.until, label=body.label,
                     title=match.title, location=match.location)
        return JSONResponse({"ok": True})

    @app.post("/api/unaccept")
    async def unaccept(request: Request) -> JSONResponse:
        try:
            body = FingerprintBody.model_validate(await request.json())
        except ValidationError as exc:
            return JSONResponse({"error": _errors(exc)}, status_code=400)
        if len(body.fingerprint) != 16:
            return JSONResponse({"error": "fingerprint inválido"}, status_code=400)
        return JSONResponse({"removed": store.unaccept(body.fingerprint)})

    # ───────────────────────── funcionalidades ─────────────────────────

    @app.get("/features", response_class=HTMLResponse)
    def features() -> HTMLResponse:
        return render("features.html.j2", checks=catalog(), tools=TOOLS)
