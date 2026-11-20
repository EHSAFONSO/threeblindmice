"""App da área de trabalho (instância única): mostrar a janela, encerrar e informar a versão."""

from __future__ import annotations

import asyncio
import threading

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from tbm import __version__
from tbm.dashboard.routes import Ctx


def build(ctx: Ctx) -> APIRouter:
    r = APIRouter()

    @r.post("/api/app/show")
    async def app_show(request: Request) -> JSONResponse:
        hooks = getattr(request.app.state, "desktop", None)
        if not hooks:
            return JSONResponse({"error": "sem janela"}, status_code=404)
        await asyncio.to_thread(hooks["show"])
        return JSONResponse({"ok": True, "version": __version__})

    @r.post("/api/app/quit")
    async def app_quit(request: Request) -> JSONResponse:
        hooks = getattr(request.app.state, "desktop", None)
        if not hooks:
            return JSONResponse({"error": "sem janela"}, status_code=404)
        threading.Timer(0.2, hooks["quit"]).start()  # responde antes de fechar
        return JSONResponse({"ok": True})

    @r.get("/api/app/version")
    def app_version() -> JSONResponse:
        return JSONResponse({"version": __version__})

    return r
