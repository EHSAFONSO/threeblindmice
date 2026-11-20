"""Alertas: Discord, Slack, Telegram, ntfy, Pushover, Home Assistant, e-mail ou webhook JSON genérico.

Só dispara quando há algo *novo* de severidade ≥ mínima. Alerta que toca
toda vez acaba ignorado.

Formatos de destino aceitos em --notify / TBM_WEBHOOK (cada um é um `Notifier`,
ver tbm/squeak/notifiers.py):
- https://discord.com/api/webhooks/...      → Discord
- https://hooks.slack.com/services/...      → Slack
- tg://<token-do-bot>/<chat_id>             → Telegram (Bot API)
- ntfy://<tópico>  ou  https://ntfy.sh/<tópico>  → ntfy (push grátis no celular)
- pushover://<app_token>@<user_key>         → Pushover
- hass://<host>/<webhook_id>                → Home Assistant
- smtp://usuario:senha@servidor:587/destino@exemplo.com → e-mail
- qualquer outra URL https                  → POST com JSON completo
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx

from tbm.models import Finding, PortKey, ScanResult, Severity
from tbm.squeak.diff import ScanDiff
from tbm.squeak.notifiers import Delivery, notifier_for, send_email

__all__ = ["Delivery", "build_delivery", "build_message", "build_payload", "in_quiet_hours", "port_label",
           "relevant", "send_email", "send_test", "send_text", "send_webhook", "text_delivery"]


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


def _highest(items: list[Finding]) -> Severity | None:
    return max((f.severity for f in items), key=lambda s: s.rank, default=None)


def _alert(result: ScanResult, diff: ScanDiff, items: list[Finding]) -> dict[str, Any]:
    """Texto, título, prioridade e o JSON completo de um alerta (para qualquer destino)."""
    top = _highest(items)
    priority = {Severity.CRITICAL: "urgent", Severity.HIGH: "high"}.get(top, "default") if top else "low"
    extra = {
        "scan_id": result.scan_id,
        "label": result.label,
        "score": result.score,
        "grade": result.grade,
        "new_findings": [f.model_dump(mode="json") for f in items],
        "new_hosts": [h.model_dump(mode="json", exclude={"services"}) for h in diff.alert_hosts],
        "opened_ports": [port_label(p) for p in diff.alert_ports],
        "mac_changes": [{"ip": ip, "old": o, "new": n} for ip, o, n in diff.mac_changes],
    }
    return {"text": build_message(result, diff, items), "title": f"threeblindmice: {result.label} ({result.grade})",
            "priority": priority, "extra": extra}


def build_delivery(target: str, result: ScanResult, diff: ScanDiff, items: list[Finding]) -> Delivery:
    a = _alert(result, diff, items)
    return text_delivery(target, a["text"], title=a["title"], priority=a["priority"], extra=a["extra"])


def text_delivery(target: str, text: str, *, title: str = "threeblindmice", priority: str = "default",
                  extra: dict[str, Any] | None = None) -> Delivery:
    """A requisição HTTP de uma mensagem para o destino (alertas e o resumo semanal)."""
    notifier, _ = notifier_for(target)
    return notifier.delivery(target, text, title=title, priority=priority, extra=extra)


async def send_text(target: str, text: str, *, title: str = "threeblindmice",
                    transport: httpx.AsyncBaseTransport | None = None) -> None:
    notifier, _ = notifier_for(target)
    await notifier.send(target, text, title=title, transport=transport)


def build_payload(url: str, result: ScanResult, diff: ScanDiff, items: list[Finding]) -> dict:
    """Compatibilidade: o corpo JSON dos destinos baseados em JSON."""
    return build_delivery(url, result, diff, items).json or {}


async def send_test(url: str, transport: httpx.AsyncBaseTransport | None = None) -> int:
    """Manda uma mensagem de teste para o destino. Devolve o status (HTTP, ou 250 no e-mail).

    Serve para validar a configuração (token, chat_id, tópico) sem esperar um
    scan encontrar algo novo.
    """
    from tbm.models import Host  # import local: evita ciclo models ← notify

    result = ScanResult(label="teste", score=100, grade="A")
    diff = ScanDiff(previous_id=None, new_hosts=[Host(address="0.0.0.0", device_name="teste de conexão")])
    a = _alert(result, diff, [])
    notifier, _ = notifier_for(url)
    return await notifier.send(url, a["text"], title=a["title"], priority=a["priority"], extra=a["extra"],
                               transport=transport, check=False)


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
    a = _alert(result, diff, items)
    notifier, _ = notifier_for(url)
    await notifier.send(url, a["text"], title=a["title"], priority=a["priority"], extra=a["extra"],
                        transport=transport)
    return True
