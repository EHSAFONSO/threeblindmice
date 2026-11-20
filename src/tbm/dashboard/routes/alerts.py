"""Alertas: escolher o destino (Telegram, ntfy, webhook), testar, horário de silêncio e resumo semanal."""

from __future__ import annotations

import re
import secrets
from typing import Literal

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ValidationError

from tbm import config
from tbm.config import describe, notify_target, persist_notify
from tbm.dashboard.routes import Ctx, errors
from tbm.squeak.notify import send_test
from tbm.squeak.telegram import TelegramError, bot_username, find_chats, looks_like_token


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


def build(ctx: Ctx) -> APIRouter:
    r = APIRouter()
    render = ctx.render

    @r.get("/alerts", response_class=HTMLResponse)
    def alerts_page() -> HTMLResponse:
        target, source = notify_target()
        from tbm.squeak import summary

        q = config.quiet_hours()
        return render("alerts.html.j2", current=describe(target), source=source,
                      suggested_topic=f"tbm-{secrets.token_hex(5)}", weekly=summary.enabled(),
                      quiet_start=q[0] if q else "", quiet_end=q[1] if q else "")

    @r.post("/api/alerts/summary")
    async def alerts_summary(request: Request) -> JSONResponse:
        from tbm.squeak import summary

        body = await request.json()
        if not isinstance(body, dict) or not isinstance(body.get("enabled"), bool):
            return JSONResponse({"error": "envie {enabled: true|false}"}, status_code=400)
        summary.set_enabled(body["enabled"])
        return JSONResponse({"ok": True, "enabled": body["enabled"]})

    @r.post("/api/telegram/lookup")
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

    @r.post("/api/alerts/quiet")
    async def alerts_quiet(request: Request) -> JSONResponse:
        body = await request.json()
        if not isinstance(body, dict):
            return JSONResponse({"error": "corpo inválido"}, status_code=400)
        start, end = str(body.get("start", "")), str(body.get("end", ""))
        data = config.load()
        if start and end:
            if not (re.fullmatch(r"\d{2}:\d{2}", start) and re.fullmatch(r"\d{2}:\d{2}", end)):
                return JSONResponse({"error": "use HH:MM"}, status_code=400)
            data["quiet_start"], data["quiet_end"] = start, end
        else:
            data.pop("quiet_start", None), data.pop("quiet_end", None)
        config.save(data)
        return JSONResponse({"ok": True})

    @r.post("/api/alerts/save")
    async def alerts_save(request: Request) -> JSONResponse:
        try:
            body = AlertBody.model_validate(await request.json())
            target = body.target()
        except ValidationError as exc:
            return JSONResponse({"error": errors(exc)}, 400)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, 400)
        # Só grava depois que a mensagem de teste chegar: config quebrada não entra.
        error = await _test_delivery(target)
        if error:
            return JSONResponse({"error": error}, 400)
        notes = persist_notify(target)
        return JSONResponse({"ok": True, "current": describe(target), "notes": notes})

    @r.post("/api/alerts/test")
    async def alerts_test() -> JSONResponse:
        target, _ = notify_target()
        if not target:
            return JSONResponse({"error": "nenhum destino configurado"}, 400)
        error = await _test_delivery(target)
        return JSONResponse({"error": error}, 400) if error else JSONResponse({"ok": True})

    @r.post("/api/alerts/remove")
    async def alerts_remove() -> JSONResponse:
        return JSONResponse({"ok": True, "notes": persist_notify(None)})

    return r
