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

from dataclasses import dataclass, field
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
    if diff.new_hosts:
        lines.append("Dispositivos novos na rede: " + ", ".join(h.display for h in diff.new_hosts[:10]))
    if diff.opened_ports:
        lines.append("Portas novas: " + ", ".join(port_label(p) for p in diff.opened_ports[:10]))
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
    text = build_message(result, diff, items)
    parsed = urlparse(target)
    host = parsed.hostname or ""

    if parsed.scheme == "tg":
        # tg://<token>/<chat_id>: o token tem ':' e por isso vai inteiro no "netloc"
        token, chat_id = parsed.netloc, parsed.path.strip("/")
        if not token or not chat_id:
            raise ValueError("formato do Telegram: tg://<token-do-bot>/<chat_id>")
        return Delivery(f"https://api.telegram.org/bot{token}/sendMessage",
                        json={"chat_id": chat_id, "text": text[:4000], "disable_web_page_preview": True})

    if parsed.scheme == "ntfy" or host == "ntfy.sh":
        topic = (parsed.netloc + parsed.path).strip("/") if parsed.scheme == "ntfy" else parsed.path.strip("/")
        base = "https://ntfy.sh" if parsed.scheme == "ntfy" else f"{parsed.scheme}://{parsed.netloc}"
        top = _highest(items)
        priority = {Severity.CRITICAL: "urgent", Severity.HIGH: "high"}.get(top, "default") if top else "low"
        return Delivery(f"{base}/{topic}", content=text.encode(), headers={
            "Title": f"threeblindmice: {result.label} ({result.grade})",
            "Priority": priority,
            "Tags": "mouse,shield",
        })

    if host.endswith("discord.com") or host.endswith("discordapp.com"):
        return Delivery(target, json={"content": text[:1990], "username": "threeblindmice"})
    if host.endswith("slack.com"):
        return Delivery(target, json={"text": text})
    return Delivery(target, json={
        "text": text,
        "scan_id": result.scan_id,
        "label": result.label,
        "score": result.score,
        "grade": result.grade,
        "new_findings": [f.model_dump(mode="json") for f in items],
        "new_hosts": [h.model_dump(mode="json", exclude={"services"}) for h in diff.new_hosts],
        "opened_ports": [port_label(p) for p in diff.opened_ports],
        "mac_changes": [{"ip": ip, "old": o, "new": n} for ip, o, n in diff.mac_changes],
    })


def build_payload(url: str, result: ScanResult, diff: ScanDiff, items: list[Finding]) -> dict:
    """Compatibilidade: o corpo JSON dos destinos baseados em JSON."""
    return build_delivery(url, result, diff, items).json or {}


async def send_webhook(
    url: str, result: ScanResult, diff: ScanDiff, min_severity: Severity = Severity.MEDIUM,
    transport: httpx.AsyncBaseTransport | None = None,
) -> bool:
    """Retorna True se enviou, False se não havia nada relevante."""
    items = relevant(diff, min_severity)
    if not items and not diff.new_hosts and not diff.opened_ports and not diff.mac_changes:
        return False
    d = build_delivery(url, result, diff, items)
    async with httpx.AsyncClient(timeout=15, headers={"User-Agent": USER_AGENT},
                                 transport=transport) as client:
        resp = await client.post(d.url, json=d.json, content=d.content, headers=d.headers)
        resp.raise_for_status()
    return True
