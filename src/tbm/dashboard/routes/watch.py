"""Vigia: scan agendado no sistema, iniciar com o sistema e "rodar agora"."""

from __future__ import annotations

import asyncio
import re
import subprocess
import sys
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ValidationError, field_validator

from tbm import schedule
from tbm.config import describe, notify_target
from tbm.dashboard.routes import Ctx, errors
from tbm.scope import Scope, ScopeError
from tbm.scout.discovery import suggested_target


class WatchBody(BaseModel):
    targets: str
    label: str = "casa"
    hours: Literal[1, 3, 6, 12, 24] = 6
    udp: bool = True
    gentle: bool = False

    @field_validator("label")
    @classmethod
    def _label(cls, v: str) -> str:
        if not re.fullmatch(r"[\w.-]{1,40}", v.strip()):
            raise ValueError("use só letras, números, ponto, hífen ou sublinhado (até 40)")
        return v.strip()

    @property
    def target_list(self) -> list[str]:
        items = [t for t in re.split(r"[\s,;]+", self.targets) if t]
        if not items:
            raise ValueError("informe pelo menos um alvo")
        return items


def build(ctx: Ctx) -> APIRouter:
    r = APIRouter()
    store, render = ctx.store, ctx.render

    @r.get("/watch", response_class=HTMLResponse)
    def watch_page(label: str | None = None) -> HTMLResponse:
        label = label or ctx.latest_label() or "casa"
        if not re.fullmatch(r"[\w.-]{1,40}", label):
            raise HTTPException(400, "rótulo inválido")
        last = store.latest(label)
        from tbm.desktop import autostart

        return render("watch.html.j2", label=label, st=schedule.status(sys.platform, label),
                      log=schedule.read_log(label), suggested=suggested_target(), last=last,
                      notify=describe(notify_target()[0]), platform=sys.platform,
                      autostart_on=autostart.is_enabled(), autostart_ok=autostart.supported())

    @r.post("/api/watch/autostart")
    async def watch_autostart(request: Request) -> JSONResponse:
        from tbm.desktop import autostart

        body = await request.json()
        if not isinstance(body, dict) or not isinstance(body.get("enabled"), bool):
            return JSONResponse({"error": "envie {enabled: true|false}"}, status_code=400)
        try:
            autostart.enable() if body["enabled"] else autostart.disable()
        except OSError as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)
        return JSONResponse({"ok": True, "enabled": autostart.is_enabled()})

    @r.post("/api/watch/install")
    async def watch_install(request: Request) -> JSONResponse:
        try:
            body = WatchBody.model_validate(await request.json())
            Scope.default().resolve(body.target_list)
        except ValidationError as exc:
            return JSONResponse({"error": errors(exc)}, 400)
        except (ScopeError, ValueError) as exc:
            return JSONResponse({"error": str(exc)}, 400)
        extra = [*(["--udp"] if body.udp else []), *(["--gentle"] if body.gentle else [])]
        plan = schedule.build_plan(sys.platform, body.target_list, body.label, body.hours * 3600, extra)
        if plan.manual and not plan.commands:
            return JSONResponse({"manual": plan.manual})
        try:
            await asyncio.to_thread(schedule.execute, plan)
        except RuntimeError as exc:
            return JSONResponse({"error": str(exc)}, 500)
        return JSONResponse({"ok": True, "description": plan.description, "warnings": plan.warnings})

    @r.post("/api/watch/remove")
    async def watch_remove(request: Request) -> JSONResponse:
        label = str((await request.json()).get("label", ""))
        if not re.fullmatch(r"[\w.-]{1,40}", label):
            return JSONResponse({"error": "rótulo inválido"}, 400)
        try:
            await asyncio.to_thread(schedule.execute, schedule.remove_plan(sys.platform, label))
        except RuntimeError as exc:
            return JSONResponse({"error": str(exc)}, 500)
        return JSONResponse({"ok": True})

    @r.post("/api/watch/run-now")
    async def watch_run_now(request: Request) -> JSONResponse:
        label = str((await request.json()).get("label", ""))
        if sys.platform != "win32" or not re.fullmatch(r"[\w.-]{1,40}", label):
            return JSONResponse({"error": "disponível só no Windows"}, 400)
        proc = await asyncio.to_thread(subprocess.run, ["schtasks", "/Run", "/TN", schedule.task_name(label)],
                                       capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            return JSONResponse({"error": (proc.stderr or proc.stdout).strip()}, 500)
        return JSONResponse({"ok": True})

    return r
