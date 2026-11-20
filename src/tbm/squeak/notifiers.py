"""Destinos de alerta como registro: cada destino é uma classe `Notifier`.

Para acrescentar um destino, crie uma subclasse e decore com `@register_notifier`.
A ordem importa: o primeiro que reconhece a URL ganha; sem nenhum, vale o webhook genérico.
Nenhum `describe` devolve segredo (token, caminho do webhook, senha).
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any, ClassVar
from urllib.parse import ParseResult, unquote, urlparse

import httpx

from tbm import USER_AGENT


@dataclass
class Delivery:
    """Uma requisição HTTP pronta. Separada do envio para dar para testar sem rede."""

    url: str
    json: dict[str, Any] | None = None
    content: bytes | None = None
    headers: dict[str, str] = field(default_factory=dict)


class Notifier:
    """Um tipo de destino. `matches` decide pela URL; `delivery` monta a requisição; `send` envia."""

    kind: ClassVar[str] = "webhook"

    def matches(self, p: ParseResult) -> bool:
        raise NotImplementedError

    def describe(self, p: ParseResult) -> str:
        raise NotImplementedError

    def delivery(self, target: str, text: str, *, title: str, priority: str,
                 extra: dict[str, Any] | None) -> Delivery:
        raise NotImplementedError

    async def send(self, target: str, text: str, *, title: str = "threeblindmice", priority: str = "default",
                   extra: dict[str, Any] | None = None, transport: httpx.AsyncBaseTransport | None = None,
                   check: bool = True) -> int:
        """Envia e devolve o status. Com `check`, erro HTTP vira exceção (httpx.HTTPStatusError)."""
        d = self.delivery(target, text, title=title, priority=priority, extra=extra)
        async with httpx.AsyncClient(timeout=15, headers={"User-Agent": USER_AGENT}, transport=transport) as client:
            resp = await client.post(d.url, json=d.json, content=d.content, headers=d.headers)
        if check:
            resp.raise_for_status()
        return resp.status_code


NOTIFIERS: list[Notifier] = []


def register_notifier(cls: type[Notifier]) -> type[Notifier]:
    NOTIFIERS.append(cls())
    return cls


def notifier_for(target: str) -> tuple[Notifier, ParseResult]:
    """O destino que reconhece a URL; o webhook genérico é a última opção."""
    p = urlparse(target)
    for n in NOTIFIERS:
        if n.matches(p):
            return n, p
    return FALLBACK, p


# ───────────────────────────── destinos nativos ─────────────────────────────


@register_notifier
class TelegramNotifier(Notifier):
    kind = "telegram"

    def matches(self, p: ParseResult) -> bool:
        return p.scheme == "tg"

    def describe(self, p: ParseResult) -> str:
        chat = p.path.strip("/") or "?"
        # Só o final do chat_id: o número aparece em prints da tela que você compartilhar.
        shown = "••••" + chat[-4:] if len(chat) > 4 else chat
        return f"Telegram · chat {shown}"

    def delivery(self, target: str, text: str, *, title: str, priority: str,
                 extra: dict[str, Any] | None) -> Delivery:
        p = urlparse(target)
        # tg://<token>/<chat_id>: o token tem ':' e por isso vai inteiro no "netloc"
        token, chat_id = p.netloc, p.path.strip("/")
        # Mensagens específicas, mas sem nunca ecoar o token.
        if not token:
            raise ValueError("TBM_WEBHOOK do Telegram sem o token. Formato: tg://<token-do-bot>/<chat_id>. "
                             "Use `tbm telegram-setup` para configurar.")
        if ":" not in token:
            raise ValueError("o token do Telegram parece incompleto (deveria ter ':'). "
                             "Use `tbm telegram-setup` para configurar.")
        if not chat_id:
            raise ValueError("TBM_WEBHOOK do Telegram sem o chat_id no final (tg://<token>/<chat_id>). "
                             "Use `tbm telegram-setup` para descobrir o chat_id.")
        if not re.fullmatch(r"-?\d+|@\w+", chat_id):
            raise ValueError("chat_id do Telegram inválido: deveria ser um número (ex.: 123456789 ou -100…). "
                             "Use `tbm telegram-setup`.")
        return Delivery(f"https://api.telegram.org/bot{token}/sendMessage",
                        json={"chat_id": chat_id, "text": text[:4000], "disable_web_page_preview": True})


@register_notifier
class NtfyNotifier(Notifier):
    kind = "ntfy"

    def matches(self, p: ParseResult) -> bool:
        return p.scheme == "ntfy" or (p.hostname or "") == "ntfy.sh"

    @staticmethod
    def _topic(p: ParseResult) -> str:
        return (p.netloc + p.path).strip("/") if p.scheme == "ntfy" else p.path.strip("/")

    def describe(self, p: ParseResult) -> str:
        topic = self._topic(p)
        shown = topic[:4] + "…" + topic[-2:] if len(topic) > 8 else "…"
        return f"ntfy · tópico {shown}"

    def delivery(self, target: str, text: str, *, title: str, priority: str,
                 extra: dict[str, Any] | None) -> Delivery:
        p = urlparse(target)
        base = "https://ntfy.sh" if p.scheme == "ntfy" else f"{p.scheme}://{p.netloc}"
        return Delivery(f"{base}/{self._topic(p)}", content=text.encode(),
                        headers={"Title": title, "Priority": priority, "Tags": "mouse,shield"})


@register_notifier
class PushoverNotifier(Notifier):
    kind = "pushover"

    def matches(self, p: ParseResult) -> bool:
        return p.scheme == "pushover"

    def describe(self, p: ParseResult) -> str:
        return "Pushover"

    def delivery(self, target: str, text: str, *, title: str, priority: str,
                 extra: dict[str, Any] | None) -> Delivery:
        # pushover://<app_token>@<user_key> — sem urlparse.hostname, que deixa minúsculo
        token, _, user = urlparse(target).netloc.partition("@")
        if not token or not user:
            raise ValueError("Pushover: use pushover://<app_token>@<user_key>.")
        prio = {"urgent": "1", "high": "1"}.get(priority, "0")
        return Delivery("https://api.pushover.net/1/messages.json",
                        json={"token": token, "user": user, "message": text[:1024], "title": title, "priority": prio})


@register_notifier
class HomeAssistantNotifier(Notifier):
    kind = "hass"

    def matches(self, p: ParseResult) -> bool:
        return p.scheme in ("hass", "homeassistant")

    def describe(self, p: ParseResult) -> str:
        return f"Home Assistant · {p.hostname or '?'}"

    def delivery(self, target: str, text: str, *, title: str, priority: str,
                 extra: dict[str, Any] | None) -> Delivery:
        # hass://<host>/<webhook_id>  (webhook do Home Assistant; use https:// no host real)
        p = urlparse(target)
        webhook, host = p.path.strip("/"), p.hostname or ""
        if not webhook or not host:
            raise ValueError("Home Assistant: use hass://<host>/<webhook_id>.")
        scheme = "https" if p.port in (None, 443) else "http"
        base = f"{scheme}://{host}" + (f":{p.port}" if p.port else "")
        payload = {"title": title, "message": text, "priority": priority, **(extra or {})}
        return Delivery(f"{base}/api/webhook/{webhook}", json=payload)


@register_notifier
class DiscordNotifier(Notifier):
    kind = "discord"

    def matches(self, p: ParseResult) -> bool:
        host = p.hostname or ""
        return host.endswith("discord.com") or host.endswith("discordapp.com")

    def describe(self, p: ParseResult) -> str:
        return "Discord (webhook)"

    def delivery(self, target: str, text: str, *, title: str, priority: str,
                 extra: dict[str, Any] | None) -> Delivery:
        return Delivery(target, json={"content": text[:1990], "username": "threeblindmice"})


@register_notifier
class SlackNotifier(Notifier):
    kind = "slack"

    def matches(self, p: ParseResult) -> bool:
        return (p.hostname or "").endswith("slack.com")

    def describe(self, p: ParseResult) -> str:
        return "Slack (webhook)"

    def delivery(self, target: str, text: str, *, title: str, priority: str,
                 extra: dict[str, Any] | None) -> Delivery:
        return Delivery(target, json={"text": text})


@register_notifier
class EmailNotifier(Notifier):
    """E-mail por SMTP: smtp(s)://usuario:senha@servidor:porta/destinatario@exemplo.com

    Fora do modelo HTTP dos outros destinos: a entrega é por smtplib, numa thread
    (é bloqueante). A porta 465 usa SSL direto; 587/25 usam STARTTLS.
    """

    kind = "email"

    def matches(self, p: ParseResult) -> bool:
        return p.scheme in ("smtp", "smtps", "mailto")

    def describe(self, p: ParseResult) -> str:
        return f"E-mail · {unquote(p.path.strip('/')) or '?'}"

    def delivery(self, target: str, text: str, *, title: str, priority: str,
                 extra: dict[str, Any] | None) -> Delivery:
        raise ValueError("e-mail não é enviado por HTTP")

    async def send(self, target: str, text: str, *, title: str = "threeblindmice", priority: str = "default",
                   extra: dict[str, Any] | None = None, transport: httpx.AsyncBaseTransport | None = None,
                   check: bool = True) -> int:
        await asyncio.to_thread(send_email, target, title, text)
        return 250  # "requested mail action okay" do SMTP


def send_email(target: str, subject: str, body: str) -> None:
    import smtplib
    from email.message import EmailMessage

    p = urlparse(target)
    to_addr = unquote(p.path.strip("/"))
    if not p.hostname or not to_addr:
        raise ValueError("E-mail: use smtp://usuario:senha@servidor:porta/destino@exemplo.com")
    user = unquote(p.username) if p.username else None
    password = unquote(p.password) if p.password else None
    port = p.port or (465 if p.scheme == "smtps" else 587)
    msg = EmailMessage()
    msg["From"] = user or f"threeblindmice@{p.hostname}"
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    if p.scheme == "smtps" or port == 465:
        with smtplib.SMTP_SSL(p.hostname, port, timeout=20) as s:
            if user and password:
                s.login(user, password)
            s.send_message(msg)
    else:
        with smtplib.SMTP(p.hostname, port, timeout=20) as s:
            s.ehlo()
            if port != 25:
                s.starttls()
            if user and password:
                s.login(user, password)
            s.send_message(msg)


class WebhookNotifier(Notifier):
    """Qualquer outra URL: POST com o texto e, nos alertas, o JSON completo do que mudou."""

    kind = "webhook"

    def matches(self, p: ParseResult) -> bool:
        return True

    def describe(self, p: ParseResult) -> str:
        return f"Webhook em {p.hostname or '?'}"

    def delivery(self, target: str, text: str, *, title: str, priority: str,
                 extra: dict[str, Any] | None) -> Delivery:
        return Delivery(target, json={"text": text, **(extra or {})})


FALLBACK: Notifier = WebhookNotifier()
