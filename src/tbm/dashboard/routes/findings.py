"""Achados: lista, aceitar/desfazer risco, "corrigir agora", verificação e carta ao provedor."""

from __future__ import annotations

from datetime import date

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, ValidationError, field_validator

from tbm.dashboard.jobs import BusyError
from tbm.dashboard.routes import Ctx, errors
from tbm.models import Severity
from tbm.squeak.acceptance import is_active
from tbm.squeak.actions import build_actions, progress
from tbm.squeak.letter import build_letter


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


def build(ctx: Ctx) -> APIRouter:
    r = APIRouter()
    store, render, runner = ctx.store, ctx.render, ctx.jobs

    @r.get("/findings")
    def findings_default() -> RedirectResponse:
        label = ctx.latest_label()
        return RedirectResponse(f"/findings/{label}" if label else "/scan", status_code=303)

    @r.get("/findings/{label}", response_class=HTMLResponse)
    def findings(label: str) -> HTMLResponse:
        scan = store.latest(label)
        if scan is None:
            raise HTTPException(404, "rótulo sem scans")
        acceptances = store.acceptances()
        # aceito agora pela interface, mas o scan ainda não foi refeito: já mostramos como aceito
        pending = {fp for fp, row in acceptances.items() if is_active(row)}
        history = store.light(label, 30, skip_latest=True)
        actions = build_actions(scan)
        info = [f for f in scan.findings if f.severity is Severity.INFO]
        accepted = [f for f in scan.findings if f.accepted]
        from tbm.squeak.actions import impacts

        return render("findings.html.j2", label=label, scan=scan, actions=actions, info=info, accepted=accepted,
                      pending=pending, progress=progress(history, scan), labels=[r["label"] for r in store.labels()],
                      impact=impacts(scan, actions))

    @r.post("/api/accept")
    async def accept(request: Request) -> JSONResponse:
        try:
            body = AcceptBody.model_validate(await request.json())
        except ValidationError as exc:
            return JSONResponse({"error": errors(exc)}, status_code=400)
        scan = store.latest(body.label)
        match = next((f for f in scan.findings if f.fingerprint == body.fingerprint), None) if scan else None
        if match is None:
            return JSONResponse({"error": "achado não encontrado no último scan"}, status_code=404)
        store.accept(match.fingerprint, body.reason, until=body.until, label=body.label,
                     title=match.title, location=match.location)
        return JSONResponse({"ok": True})

    @r.post("/api/unaccept")
    async def unaccept(request: Request) -> JSONResponse:
        try:
            body = FingerprintBody.model_validate(await request.json())
        except ValidationError as exc:
            return JSONResponse({"error": errors(exc)}, status_code=400)
        if len(body.fingerprint) != 16:
            return JSONResponse({"error": "fingerprint inválido"}, status_code=400)
        return JSONResponse({"removed": store.unaccept(body.fingerprint)})

    @r.get("/fix/{label}/{key}", response_class=HTMLResponse)
    def fix_page(label: str, key: str) -> Response:
        from tbm.squeak.actions import project
        from tbm.squeak.guides import guide_for

        scan = store.latest(label)
        action = next((a for a in build_actions(scan) if a.key == key), None) if scan else None
        if scan is None or action is None:
            return RedirectResponse(f"/findings/{label}", status_code=303)  # já resolvida ou não existe mais
        guide = guide_for(action.kind, scan.host(action.host), scan.gateway)
        steps = guide.steps if guide else list(dict.fromkeys(f.remediation for f in action.findings if f.remediation))
        verifiable = action.host not in ("local", "wifi") and scan.host(action.host) is not None
        return render("fix.html.j2", label=label, scan=scan, a=action, guide=guide, steps=steps,
                      projection=project(scan, [action]), verifiable=verifiable)

    @r.post("/api/verify")
    async def verify(request: Request) -> JSONResponse:
        body = await request.json()
        label, key = str(body.get("label", "")), str(body.get("key", ""))
        scan = store.latest(label)
        action = next((a for a in build_actions(scan) if a.key == key), None) if scan else None
        if scan is None or action is None or scan.host(action.host) is None:
            return JSONResponse({"error": "ação não encontrada no último scan"}, status_code=404)
        try:
            job = runner.submit_verify(label, action.host, [f.fingerprint for f in action.findings])
        except BusyError as exc:
            return JSONResponse({"error": str(exc)}, status_code=409)
        return JSONResponse({"job": job.id}, status_code=202)

    @r.get("/letter", response_class=HTMLResponse)
    def letter_page(label: str | None = None, host: str | None = None) -> HTMLResponse:
        label = label or ctx.latest_label()
        scan = store.latest(label) if label else None
        candidates = []
        if scan:
            for h in scan.hosts:
                n = sum(1 for f in scan.findings if f.host == h.address and f.severity.rank >= Severity.MEDIUM.rank)
                if n:
                    candidates.append({"address": h.address, "label": h.display, "count": n})
        return render("letter.html.j2", label=label, labels=[r["label"] for r in store.labels()],
                      candidates=candidates, selected=host)

    @r.post("/api/letter")
    async def letter_api(request: Request) -> JSONResponse:
        data = await request.json()
        label, address = str(data.get("label", "")), str(data.get("host", ""))
        scan = store.latest(label)
        target = scan.host(address) if scan else None
        if target is None or scan is None:
            return JSONResponse({"error": "equipamento não encontrado no último scan"}, 404)
        try:
            min_sev = Severity(str(data.get("min_severity", "medium")))
        except ValueError:
            return JSONResponse({"error": "severidade inválida"}, 400)
        name = str(data.get("name") or "").strip()[:80] or None
        return JSONResponse({"text": build_letter(scan, target, name=name, min_severity=min_sev)})

    return r
