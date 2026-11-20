"""Aparelhos: inventário, mapa, página e painel do aparelho, e o cadastro (nome, aprovação)."""

from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, ValidationError, field_validator

from tbm.dashboard.routes import Ctx, errors
from tbm.dashboard.templating import CATEGORIES
from tbm.dashboard.views import device_detail, network_map


class DeviceBody(BaseModel):
    identity: str
    alias: str | None = None
    trusted: bool | None = None
    category: str | None = None
    note: str | None = None

    @field_validator("category")
    @classmethod
    def _category(cls, v: str | None) -> str | None:
        if v not in (None, "") and v not in CATEGORIES:
            raise ValueError("categoria inválida")
        return v

    @field_validator("note")
    @classmethod
    def _note(cls, v: str | None) -> str | None:
        if v is not None and len(v) > 1000:
            raise ValueError("nota com até 1000 caracteres")
        return v

    @field_validator("identity")
    @classmethod
    def _identity(cls, v: str) -> str:
        if not re.fullmatch(r"(mac|name|ip):[^\x00-\x1f]{1,120}", v):
            raise ValueError("identidade inválida")
        return v

    @field_validator("alias")
    @classmethod
    def _alias(cls, v: str | None) -> str | None:
        if v is not None and (len(v) > 40 or any(ord(c) < 32 for c in v)):
            raise ValueError("nome com até 40 caracteres, sem quebras de linha")
        return v


def build(ctx: Ctx) -> APIRouter:
    from tbm.dashboard.app import build_inventory

    r = APIRouter()
    store, render = ctx.store, ctx.render

    @r.get("/partials/device/{label}/{address}", response_class=HTMLResponse)
    def device_panel(label: str, address: str) -> HTMLResponse:
        data = device_detail(store, label, address)
        if data is None:
            raise HTTPException(404, "dispositivo não encontrado")
        return render("device.html.j2", **data)

    @r.get("/device/{label}/{address}", response_class=HTMLResponse)
    def device_page(label: str, address: str) -> HTMLResponse:
        from tbm.dashboard.views import device_history
        from tbm.squeak.actions import impacts

        data = device_detail(store, label, address)
        if data is None:
            raise HTTPException(404, "dispositivo não encontrado")
        history = device_history(store, label, data["host"].identity)
        return render("device_page.html.j2", **data, history=history,
                      impact=impacts(data["scan"], data["actions"]))

    @r.get("/inventory/{label}", response_class=HTMLResponse)
    def inventory(label: str) -> HTMLResponse:
        latest = store.latest(label)
        if latest is None:
            raise HTTPException(404, "rótulo sem scans")
        # o último completo (serviços mDNS, achados); o histórico só pelos índices
        seen, n = store.sightings(label, 50)
        return render("inventory.html.j2", label=label, scan=latest,
                      devices=build_inventory([latest], seen), scans_seen=n)

    @r.get("/map")
    def map_default():
        label = ctx.latest_label()
        return RedirectResponse(f"/map/{label}" if label else "/", status_code=303)

    @r.get("/map/{label}", response_class=HTMLResponse)
    def network(label: str) -> HTMLResponse:
        scan = store.latest(label)
        if scan is None:
            raise HTTPException(404, "rótulo sem scans")
        from tbm.dashboard.views import offline_hosts

        return render("map.html.j2", label=label, scan=scan, m=network_map(scan, offline_hosts(store, label, scan)))

    if ctx.gui is None:
        return r

    @r.get("/inventory")
    def inventory_default() -> RedirectResponse:
        label = ctx.latest_label()
        return RedirectResponse(f"/inventory/{label}" if label else "/scan", status_code=303)

    @r.post("/api/device")
    async def device(request: Request) -> JSONResponse:
        try:
            body = DeviceBody.model_validate(await request.json())
        except ValidationError as exc:
            return JSONResponse({"error": errors(exc)}, status_code=400)
        if body.alias is None and body.trusted is None and body.category is None and body.note is None:
            return JSONResponse({"error": "nada para alterar"}, status_code=400)
        previous = store.devices().get(body.identity)
        store.set_device(body.identity, alias=body.alias, trusted=body.trusted, category=body.category, note=body.note)
        # devolve o estado anterior: a interface usa para o "Desfazer"
        before = {k: previous[k] for k in ("alias", "category", "note")} if previous else {}
        if previous:
            before["trusted"] = bool(previous["trusted"])
        return JSONResponse({"ok": True, "before": before})

    return r
