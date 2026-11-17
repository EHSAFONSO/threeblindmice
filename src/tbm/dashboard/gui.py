"""Rotas interativas da interface gráfica: novo scan, achados com aceitação, catálogo."""

from __future__ import annotations

import asyncio
import re
import secrets
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import date
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, ValidationError, field_validator

from tbm import schedule
from tbm.config import describe, notify_target, persist_notify
from tbm.dashboard.features import TOOLS, catalog
from tbm.dashboard.jobs import BusyError, JobRunner, ScanParams
from tbm.dashboard.security import GuiSettings, check_request
from tbm.models import Severity
from tbm.scope import Scope, ScopeError
from tbm.scout.discovery import local_ipv4, suggested_target
from tbm.squeak import HistoryStore
from tbm.squeak.acceptance import is_active
from tbm.squeak.actions import build_actions, progress
from tbm.squeak.letter import build_letter
from tbm.squeak.notify import send_test
from tbm.squeak.telegram import TelegramError, bot_username, find_chats, looks_like_token

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


class AlertBody(BaseModel):
    kind: Literal["telegram", "ntfy", "url"]
    token: str | None = None
    chat_id: str | None = None
    topic: str | None = None
    url: str | None = None

    def target(self) -> str:
        if self.kind == "telegram":
            token, chat = (self.token or "").strip(), str(self.chat_id or "").strip()
            if not looks_like_token(token):
                raise ValueError("token do bot inválido")
            if not re.fullmatch(r"-?\d+", chat):
                raise ValueError("escolha a conversa que vai receber os alertas")
            return f"tg://{token}/{chat}"
        if self.kind == "ntfy":
            topic = (self.topic or "").strip()
            if not re.fullmatch(r"[\w-]{6,64}", topic):
                raise ValueError("o tópico precisa ter de 6 a 64 letras, números, - ou _")
            return f"ntfy://{topic}"
        url = (self.url or "").strip()
        if not url.startswith("https://"):
            raise ValueError("o webhook precisa ser uma URL https://")
        return url


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


async def _test_delivery(target: str) -> str | None:
    """Manda a mensagem de teste. Devolve None se chegou, ou a explicação do erro."""
    try:
        status = await send_test(target)
    except ValueError as exc:
        return str(exc)
    except httpx.HTTPError as exc:
        return f"não consegui conectar ao destino ({exc.__class__.__name__})"
    if 200 <= status < 300:
        return None
    hint = {401: "token inválido", 400: "chat_id errado ou você ainda não falou com o bot",
            403: "o bot foi bloqueado ou removido do chat", 404: "endereço não encontrado"}.get(status, "")
    return f"o destino respondeu HTTP {status}" + (f" ({hint})" if hint else "")


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

    # ───────────────────────── boas-vindas e situação ─────────────────────────

    @app.get("/welcome", response_class=HTMLResponse)
    def welcome() -> HTMLResponse:
        return render("welcome.html.j2", suggested=suggested_target(), local_ip=local_ipv4())

    status_cache: dict[str, tuple[float, dict]] = {}

    @app.get("/partials/status", response_class=HTMLResponse)
    async def status_partial() -> HTMLResponse:
        label = latest_label() or "casa"
        cached = status_cache.get(label)
        if cached is None or time.monotonic() - cached[0] > 60:
            # consultar o Agendador do Windows leva ~1s: cache curto, fora da thread do servidor
            st = await asyncio.to_thread(schedule.status, sys.platform, label)
            status_cache[label] = (time.monotonic(), st)
        st = status_cache[label][1]
        return render("status.html.j2", st=st, notify=describe(notify_target()[0]))

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
        # aceito agora pela interface, mas o scan ainda não foi refeito: já mostramos como aceito
        pending = {fp for fp, row in acceptances.items() if is_active(row)}
        history = [s for r in store.list(label, 30)[1:] if (s := store.get(r["scan_id"])) is not None]
        actions = build_actions(scan)
        info = [f for f in scan.findings if f.severity is Severity.INFO]
        accepted = [f for f in scan.findings if f.accepted]
        return render("findings.html.j2", label=label, scan=scan, actions=actions, info=info, accepted=accepted,
                      pending=pending, progress=progress(history, scan), labels=[r["label"] for r in store.labels()])

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

    # ───────────────────────── alertas ─────────────────────────

    @app.get("/alerts", response_class=HTMLResponse)
    def alerts_page() -> HTMLResponse:
        target, source = notify_target()
        return render("alerts.html.j2", current=describe(target), source=source,
                      suggested_topic=f"tbm-{secrets.token_hex(5)}")

    @app.post("/api/telegram/lookup")
    async def telegram_lookup(request: Request) -> JSONResponse:
        token = str((await request.json()).get("token", "")).strip()
        if not looks_like_token(token):
            return JSONResponse({"error": "isso não parece um token de bot (formato 123456789:AAH…)"}, 400)
        try:
            bot = await bot_username(token)
            chats = await find_chats(token)
        except TelegramError as exc:
            return JSONResponse({"error": str(exc)}, 400)
        except httpx.HTTPError:
            return JSONResponse({"error": "sem conexão com o Telegram"}, 502)
        return JSONResponse({"bot": bot, "chats": [{"id": c.id, "title": c.title, "kind": c.kind} for c in chats]})

    @app.post("/api/alerts/save")
    async def alerts_save(request: Request) -> JSONResponse:
        try:
            body = AlertBody.model_validate(await request.json())
            target = body.target()
        except ValidationError as exc:
            return JSONResponse({"error": _errors(exc)}, 400)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, 400)
        # Só grava depois que a mensagem de teste chegar: config quebrada não entra.
        error = await _test_delivery(target)
        if error:
            return JSONResponse({"error": error}, 400)
        notes = persist_notify(target)
        return JSONResponse({"ok": True, "current": describe(target), "notes": notes})

    @app.post("/api/alerts/test")
    async def alerts_test() -> JSONResponse:
        target, _ = notify_target()
        if not target:
            return JSONResponse({"error": "nenhum destino configurado"}, 400)
        error = await _test_delivery(target)
        return JSONResponse({"error": error}, 400) if error else JSONResponse({"ok": True})

    @app.post("/api/alerts/remove")
    async def alerts_remove() -> JSONResponse:
        return JSONResponse({"ok": True, "notes": persist_notify(None)})

    # ───────────────────────── vigia ─────────────────────────

    @app.get("/watch", response_class=HTMLResponse)
    def watch_page(label: str | None = None) -> HTMLResponse:
        label = label or latest_label() or "casa"
        if not re.fullmatch(r"[\w.-]{1,40}", label):
            raise HTTPException(400, "rótulo inválido")
        last = store.latest(label)
        return render("watch.html.j2", label=label, st=schedule.status(sys.platform, label),
                      log=schedule.read_log(label), suggested=suggested_target(), last=last,
                      notify=describe(notify_target()[0]), platform=sys.platform)

    @app.post("/api/watch/install")
    async def watch_install(request: Request) -> JSONResponse:
        try:
            body = WatchBody.model_validate(await request.json())
            Scope.default().resolve(body.target_list)
        except ValidationError as exc:
            return JSONResponse({"error": _errors(exc)}, 400)
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

    @app.post("/api/watch/remove")
    async def watch_remove(request: Request) -> JSONResponse:
        label = str((await request.json()).get("label", ""))
        if not re.fullmatch(r"[\w.-]{1,40}", label):
            return JSONResponse({"error": "rótulo inválido"}, 400)
        try:
            await asyncio.to_thread(schedule.execute, schedule.remove_plan(sys.platform, label))
        except RuntimeError as exc:
            return JSONResponse({"error": str(exc)}, 500)
        return JSONResponse({"ok": True})

    @app.post("/api/watch/run-now")
    async def watch_run_now(request: Request) -> JSONResponse:
        label = str((await request.json()).get("label", ""))
        if sys.platform != "win32" or not re.fullmatch(r"[\w.-]{1,40}", label):
            return JSONResponse({"error": "disponível só no Windows"}, 400)
        proc = await asyncio.to_thread(subprocess.run, ["schtasks", "/Run", "/TN", schedule.task_name(label)],
                                       capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            return JSONResponse({"error": (proc.stderr or proc.stdout).strip()}, 500)
        return JSONResponse({"ok": True})

    # ───────────────────────── carta ─────────────────────────

    @app.get("/letter", response_class=HTMLResponse)
    def letter_page(label: str | None = None, host: str | None = None) -> HTMLResponse:
        label = label or latest_label()
        scan = store.latest(label) if label else None
        candidates = []
        if scan:
            for h in scan.hosts:
                n = sum(1 for f in scan.findings if f.host == h.address and f.severity.rank >= Severity.MEDIUM.rank)
                if n:
                    candidates.append({"address": h.address, "label": h.display, "count": n})
        return render("letter.html.j2", label=label, labels=[r["label"] for r in store.labels()],
                      candidates=candidates, selected=host)

    @app.post("/api/letter")
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
