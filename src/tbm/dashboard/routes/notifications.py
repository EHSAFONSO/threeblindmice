"""Notificações da interface (o sino): contador e painel."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse

from tbm.dashboard.routes import Ctx


def build(ctx: Ctx) -> APIRouter:
    r = APIRouter()
    store, render = ctx.store, ctx.render

    @r.get("/api/notifications/count")
    def notifications_count() -> JSONResponse:
        return JSONResponse({"unread": store.unread_events()})

    @r.get("/partials/notifications", response_class=HTMLResponse)
    def notifications_panel() -> HTMLResponse:
        events = store.events(30)
        store.mark_events_read()
        return render("notifications.html.j2", events=events)

    return r
