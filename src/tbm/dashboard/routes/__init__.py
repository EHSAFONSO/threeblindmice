"""Rotas da interface, um APIRouter por área.

Cada módulo expõe `build(ctx) -> APIRouter`. Sem `ctx.gui`, só entram as rotas de
leitura (o `tbm dashboard` nunca dispara scans); com `ctx.gui`, a interface completa.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi import FastAPI
from pydantic import ValidationError

from tbm.dashboard.templating import Render, latest_label

if TYPE_CHECKING:
    from tbm.dashboard.jobs import JobRunner
    from tbm.dashboard.security import GuiSettings
    from tbm.squeak import HistoryStore


@dataclass
class Ctx:
    store: HistoryStore
    render: Render
    gui: GuiSettings | None = None
    runner: JobRunner | None = None

    def latest_label(self) -> str | None:
        return latest_label(self.store)

    @property
    def jobs(self) -> JobRunner:
        """O executor de scans: só existe na interface completa."""
        if self.runner is None:
            raise RuntimeError("rota da interface completa registrada sem executor de scans")
        return self.runner


def errors(exc: ValidationError) -> str:
    return "; ".join(str(e["msg"]).removeprefix("Value error, ") for e in exc.errors())


def include_all(app: FastAPI, ctx: Ctx) -> None:
    from tbm.dashboard.routes import alerts, app_control, devices, findings, notifications, overview, scan, watch

    app.include_router(overview.build(ctx))
    app.include_router(devices.build(ctx))
    if ctx.gui is not None:
        for module in (scan, findings, app_control, notifications, alerts, watch):
            app.include_router(module.build(ctx))
