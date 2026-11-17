"""Configuração assistida do Telegram: valida o token e descobre o chat_id.

A receita manual (`getUpdates` e pegar `result[-1].message.chat.id`) falha
num caso comum: ao tocar em "Iniciar", o Telegram também gera um update do
tipo `my_chat_member`, que não tem `.message`. Se ele for o último, o
chat_id sai vazio. Aqui procuramos o chat em todos os tipos de update.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import httpx

from tbm import USER_AGENT

API = "https://api.telegram.org/bot{token}/{method}"
TOKEN_RE = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{30,}$")
# Campos de update que carregam um objeto "chat"
_CHAT_CARRIERS = ("message", "edited_message", "channel_post", "edited_channel_post",
                  "my_chat_member", "chat_member", "chat_join_request")


@dataclass(frozen=True)
class Chat:
    id: int
    kind: str  # private, group, supergroup, channel
    title: str


class TelegramError(RuntimeError):
    pass


def looks_like_token(token: str) -> bool:
    return bool(TOKEN_RE.fullmatch(token.strip()))


def chats_from_updates(updates: list[dict[str, Any]]) -> list[Chat]:
    """Todos os chats distintos que aparecem nos updates, do mais recente ao mais antigo."""
    found: dict[int, Chat] = {}
    for upd in reversed(updates):
        candidates = [upd.get(k) for k in _CHAT_CARRIERS]
        if cb := upd.get("callback_query"):
            candidates.append(cb.get("message"))
        for obj in candidates:
            chat = (obj or {}).get("chat")
            if not chat or "id" not in chat or chat["id"] in found:
                continue
            title = chat.get("title") or " ".join(
                x for x in (chat.get("first_name"), chat.get("last_name")) if x) or chat.get("username") or "?"
            found[chat["id"]] = Chat(chat["id"], chat.get("type", "?"), title)
    return list(found.values())


async def _call(client: httpx.AsyncClient, token: str, method: str) -> Any:
    resp = await client.get(API.format(token=token, method=method))
    data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    if resp.status_code == 401 or (data and not data.get("ok") and data.get("error_code") == 401):
        raise TelegramError("token inválido: confira o que o @BotFather enviou")
    if not data.get("ok"):
        raise TelegramError(f"Telegram respondeu {resp.status_code}: {data.get('description', 'erro')}")
    return data["result"]


async def bot_username(token: str, transport: httpx.AsyncBaseTransport | None = None) -> str:
    async with httpx.AsyncClient(timeout=15, headers={"User-Agent": USER_AGENT}, transport=transport) as c:
        return (await _call(c, token, "getMe")).get("username", "?")


async def find_chats(token: str, transport: httpx.AsyncBaseTransport | None = None) -> list[Chat]:
    async with httpx.AsyncClient(timeout=15, headers={"User-Agent": USER_AGENT}, transport=transport) as c:
        return chats_from_updates(await _call(c, token, "getUpdates"))
