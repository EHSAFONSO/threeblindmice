"""Alertas: Discord, Slack, Telegram, ntfy ou webhook JSON genérico.

Só dispara quando há algo *novo* de severidade ≥ mínima. Alerta que toca
toda vez acaba ignorado.

Formatos de destino aceitos em --notify / TBM_WEBHOOK:
- https://discord.com/api/webhooks/...      → Discord
- https://hooks.slack.com/services/...      → Slack
- tg://<token-do-bot>/<chat_id>             → Telegram (Bot API)
- ntfy://<tópico>  ou  https://ntfy.sh/<tópico>  → ntfy (push grátis no celular)
- qualquer outra URL https                  → POST com JSON completo
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from tbm import USER_AGENT
from tbm.models import Finding, PortKey, ScanResult, Severity
from tbm.squeak.diff import ScanDiff


def port_label(port: PortKey) -> str:
    host, number, transport = port
    return f"{host}:{number}" + ("/udp" if transport == "udp" else "")


def relevant(diff: ScanDiff, min_severity: Severity) -> list[Finding]:
    return [f for f in diff.new_findings if f.severity.rank >= min_severity.rank and not f.accepted]


def build_message(result: ScanResult, diff: ScanDiff, items: list[Finding]) -> str:
    delta = f" ({diff.score_delta:+d})" if diff.score_delta else ""
    lines = [
        f"🐭 threeblindmice · scan '{result.label}' · nota {result.grade} "
        f"({result.score}/100{delta})",
    ]
    if items:
        lines.append(f"{len(items)} achado(s) novo(s):")
        lines += [f"• [{f.severity.value.upper()}] {f.title} ({f.location})" for f in items[:15]]
        if len(items) > 15:
            lines.append(f"… e mais {len(items) - 15}")
    unknown = [h for h in diff.alert_hosts if not h.trusted]
    known = [h for h in diff.alert_hosts if h.trusted]
    if unknown:
        lines.append("⚠ Aparelho DESCONHECIDO na rede: " + ", ".join(h.display for h in unknown[:10]))
        lines.append("  (se for seu, aprove em Dispositivos para não alertar de novo)")
    if known:
        lines.append("Voltaram à rede (aprovados): " + ", ".join(h.display for h in known[:10]))
    if diff.alert_ports:
        lines.append("Portas novas: " + ", ".join(port_label(p) for p in diff.alert_ports[:10]))
    for ip, old_mac, new_mac in diff.mac_changes[:5]:
        lines.append(f"⚠ MAC de {ip} mudou: {old_mac} → {new_mac} (troca de aparelho ou ARP spoofing?)")
    if diff.resolved_findings:
        lines.append(f"✅ {len(diff.resolved_findings)} achado(s) resolvido(s)")
    return "\n".join(lines)


@dataclass
class Delivery:
    """Uma requisição HTTP pronta. Separada do envio para dar para testar sem rede."""

    url: str
    json: dict[str, Any] | None = None
    content: bytes | None = None
    headers: dict[str, str] = field(default_factory=dict)


def _highest(items: list[Finding]) -> Severity | None:
    return max((f.severity for f in items), key=lambda s: s.rank, default=None)


def build_delivery(target: str, result: ScanResult, diff: ScanDiff, items: list[Finding]) -> Delivery:
    top = _highest(items)
    priority = {Severity.CRITICAL: "urgent", Severity.HIGH: "high"}.get(top, "default") if top else "low"
    generic = {
        "scan_id": result.scan_id,
        "label": result.label,
        "score": result.score,
        "grade": result.grade,
        "new_findings": [f.model_dump(mode="json") for f in items],
        "new_hosts": [h.model_dump(mode="json", exclude={"services"}) for h in diff.alert_hosts],
        "opened_ports": [port_label(p) for p in diff.alert_ports],
        "mac_changes": [{"ip": ip, "old": o, "new": n} for ip, o, n in diff.mac_changes],
    }
    return text_delivery(target, build_message(result, diff, items),
                         title=f"threeblindmice: {result.label} ({result.grade})", priority=priority, extra=generic)


def text_delivery(target: str, text: str, *, title: str = "threeblindmice", priority: str = "default",
                  extra: dict[str, Any] | None = None) -> Delivery:
    """Uma mensagem de texto para qualquer destino suportado (alertas e o resumo semanal)."""
    parsed = urlparse(target)
    host = parsed.hostname or ""

    if parsed.scheme == "tg":
        # tg://<token>/<chat_id>: o token tem ':' e por isso vai inteiro no "netloc"
        token, chat_id = parsed.netloc, parsed.path.strip("/")
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

    if parsed.scheme == "ntfy" or host == "ntfy.sh":
        topic = (parsed.netloc + parsed.path).strip("/") if parsed.scheme == "ntfy" else parsed.path.strip("/")
        base = "https://ntfy.sh" if parsed.scheme == "ntfy" else f"{parsed.scheme}://{parsed.netloc}"
        return Delivery(f"{base}/{topic}", content=text.encode(), headers={
            "Title": title,
            "Priority": priority,
            "Tags": "mouse,shield",
        })

    if parsed.scheme == "pushover":
        # pushover://<app_token>@<user_key> — sem urlparse.hostname, que deixa minúsculo
        token2, _, user2 = parsed.netloc.partition("@")
        if not token2 or not user2:
            raise ValueError("Pushover: use pushover://<app_token>@<user_key>.")
        prio = {"urgent": "1", "high": "1"}.get(priority, "0")
        return Delivery("https://api.pushover.net/1/messages.json",
                        json={"token": token2, "user": user2, "message": text[:1024], "title": title, "priority": prio})

    if parsed.scheme in ("hass", "homeassistant"):
        # hass://<host>/<webhook_id>  (webhook do Home Assistant; use https:// no host real)
        webhook = parsed.path.strip("/")
        if not webhook or not host:
            raise ValueError("Home Assistant: use hass://<host>/<webhook_id>.")
        scheme = "https" if parsed.port in (None, 443, 8123) and parsed.port != 8123 else "http"
        base = f"{scheme}://{host}" + (f":{parsed.port}" if parsed.port else "")
        payload = {"title": title, "message": text, "priority": priority, **(extra or {})}
        return Delivery(f"{base}/api/webhook/{webhook}", json=payload)

    if host.endswith("discord.com") or host.endswith("discordapp.com"):
        return Delivery(target, json={"content": text[:1990], "username": "threeblindmice"})
    if host.endswith("slack.com"):
        return Delivery(target, json={"text": text})
    return Delivery(target, json={"text": text, **(extra or {})})


async def send_text(target: str, text: str, *, title: str = "threeblindmice",
                    transport: httpx.AsyncBaseTransport | None = None) -> None:
    if urlparse(target).scheme in ("smtp", "smtps", "mailto"):
        await asyncio.to_thread(_send_email, target, title, text)
        return
    d = text_delivery(target, text, title=title)
    async with httpx.AsyncClient(timeout=15, headers={"User-Agent": USER_AGENT}, transport=transport) as client:
        resp = await client.post(d.url, json=d.json, content=d.content, headers=d.headers)
        resp.raise_for_status()


def _send_email(target: str, subject: str, body: str) -> None:
    """E-mail por SMTP. Formato: smtp(s)://usuario:senha@servidor:porta/destinatario@exemplo.com

    Fora do modelo HTTP das outras notificações: aqui a entrega é por smtplib,
    numa thread (é bloqueante). A porta 465 usa SSL direto; 587/25 usam STARTTLS.
    """
    import smtplib
    from email.message import EmailMessage
    from urllib.parse import unquote

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


def build_payload(url: str, result: ScanResult, diff: ScanDiff, items: list[Finding]) -> dict:
    """Compatibilidade: o corpo JSON dos destinos baseados em JSON."""
    return build_delivery(url, result, diff, items).json or {}


async def send_test(url: str, transport: httpx.AsyncBaseTransport | None = None) -> int:
    """Manda uma mensagem de teste para o destino. Devolve o status HTTP.

    Serve para validar a configuração (token, chat_id, tópico) sem esperar um
    scan encontrar algo novo.
    """
    from tbm.models import Host  # import local: evita ciclo models ← notify

    result = ScanResult(label="teste", score=100, grade="A")
    diff = ScanDiff(previous_id=None, new_hosts=[Host(address="0.0.0.0", device_name="teste de conexão")])
    d = build_delivery(url, result, diff, [])
    async with httpx.AsyncClient(timeout=15, headers={"User-Agent": USER_AGENT},
                                 transport=transport) as client:
        resp = await client.post(d.url, json=d.json, content=d.content, headers=d.headers)
    return resp.status_code


def in_quiet_hours(start: str, end: str, now: datetime | None = None) -> bool:
    """Estamos dentro da janela de silêncio (HH:MM–HH:MM, atravessa a meia-noite)?"""
    try:
        s, e = datetime.strptime(start, "%H:%M").time(), datetime.strptime(end, "%H:%M").time()
    except (ValueError, TypeError):
        return False
    cur = (now or datetime.now()).time()
    return (s <= cur < e) if s <= e else (cur >= s or cur < e)


async def send_webhook(
    url: str, result: ScanResult, diff: ScanDiff, min_severity: Severity = Severity.MEDIUM,
    transport: httpx.AsyncBaseTransport | None = None, quiet: tuple[str, str] | None = None,
) -> bool:
    """Retorna True se enviou, False se não havia nada relevante."""
    items = relevant(diff, min_severity)
    # Só o inédito alerta (diff.alert_*): porta de celular que dorme e acorda não é novidade.
    if not items and not diff.alert_hosts and not diff.alert_ports and not diff.mac_changes:
        return False
    # Horário de silêncio: segura tudo que não for crítico (um crítico sempre passa).
    if quiet and in_quiet_hours(*quiet) and (_highest(items) or Severity.LOW).rank < Severity.CRITICAL.rank:
        return False
    d = build_delivery(url, result, diff, items)
    async with httpx.AsyncClient(timeout=15, headers={"User-Agent": USER_AGENT},
                                 transport=transport) as client:
        resp = await client.post(d.url, json=d.json, content=d.content, headers=d.headers)
        resp.raise_for_status()
    return True
