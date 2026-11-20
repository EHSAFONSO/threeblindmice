"""Novo scan: boas-vindas, situação, aviso de versão nova, formulário e acompanhamento do job."""

from __future__ import annotations

import asyncio
import sys
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import ValidationError

from tbm import schedule
from tbm.config import describe, notify_target
from tbm.dashboard.jobs import BusyError, ScanParams
from tbm.dashboard.routes import Ctx, errors
from tbm.scope import ScopeError
from tbm.scout.discovery import local_ipv4, suggested_target


def build(ctx: Ctx) -> APIRouter:
    r = APIRouter()
    store, render, runner = ctx.store, ctx.render, ctx.jobs

    @r.get("/welcome", response_class=HTMLResponse)
    def welcome() -> HTMLResponse:
        return render("welcome.html.j2", suggested=suggested_target(), local_ip=local_ipv4())

    status_cache: dict[str, tuple[float, dict]] = {}

    @r.get("/partials/status", response_class=HTMLResponse)
    async def status_partial() -> HTMLResponse:
        label = ctx.latest_label() or "casa"
        cached = status_cache.get(label)
        if cached is None or time.monotonic() - cached[0] > 60:
            # consultar o Agendador do Windows leva ~1s: cache curto, fora da thread do servidor
            st = await asyncio.to_thread(schedule.status, sys.platform, label)
            status_cache[label] = (time.monotonic(), st)
        st = status_cache[label][1]
        return render("status.html.j2", st=st, notify=describe(notify_target()[0]))

    @r.get("/partials/update", response_class=HTMLResponse)
    async def update_partial() -> HTMLResponse:
        from tbm import update

        release = await update.check()
        return render("update.html.j2", release=release) if release else HTMLResponse("")

    @r.post("/api/update/disable")
    async def update_disable() -> JSONResponse:
        from tbm import update

        update.set_enabled(False)
        return JSONResponse({"ok": True})

    @r.get("/scan", response_class=HTMLResponse)
    async def scan_form() -> HTMLResponse:
        from tbm.pipeline import current_network_label
        from tbm.scout.discovery import local_networks

        current = runner.current
        running = current.id if current and current.status in ("queued", "running") else None
        try:  # rede conhecida? (pelo MAC do roteador) Sugere o mesmo histórico
            known = await asyncio.wait_for(current_network_label(store), 5)
        except (TimeoutError, OSError):
            known = None
        return render("scan.html.j2", suggested=suggested_target(), label=known or ctx.latest_label() or "casa",
                      running=running, known_network=known, networks=local_networks())

    @r.post("/api/scan")
    async def start_scan(request: Request) -> JSONResponse:
        try:
            params = ScanParams.model_validate(await request.json())
            job = runner.submit(params)
        except ValidationError as exc:
            return JSONResponse({"error": errors(exc)}, status_code=400)
        except (ScopeError, ValueError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        except BusyError as exc:
            return JSONResponse({"error": str(exc)}, status_code=409)
        return JSONResponse({"job": job.id}, status_code=202)

    @r.get("/api/jobs/{job_id}")
    def job_status(job_id: str) -> JSONResponse:
        job = runner.jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "job não encontrado")
        return JSONResponse(job.to_dict())

    return r
