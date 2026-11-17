"""Alertas por webhook (Discord, Slack ou JSON genérico).

Só dispara quando há algo *novo* de severidade ≥ mínima. Alerta que toca
toda vez acaba ignorado.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from tbm import USER_AGENT
from tbm.models import Finding, PortKey, ScanResult, Severity
from tbm.squeak.diff import ScanDiff


def port_label(port: PortKey) -> str:
    host, number, transport = port
    return f"{host}:{number}" + ("/udp" if transport == "udp" else "")


def relevant(diff: ScanDiff, min_severity: Severity) -> list[Finding]:
    return [f for f in diff.new_findings if f.severity.rank >= min_severity.rank]


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


def build_payload(url: str, result: ScanResult, diff: ScanDiff, items: list[Finding]) -> dict:
    text = build_message(result, diff, items)
    host = urlparse(url).hostname or ""
    if host.endswith("discord.com") or host.endswith("discordapp.com"):
        return {"content": text[:1990], "username": "threeblindmice"}
    if host.endswith("slack.com"):
        return {"text": text}
    return {
        "text": text,
        "scan_id": result.scan_id,
        "label": result.label,
        "score": result.score,
        "grade": result.grade,
        "new_findings": [f.model_dump(mode="json") for f in items],
        "new_hosts": [h.model_dump(mode="json", exclude={"services"}) for h in diff.new_hosts],
        "opened_ports": [port_label(p) for p in diff.opened_ports],
        "mac_changes": [{"ip": ip, "old": o, "new": n} for ip, o, n in diff.mac_changes],
    }


async def send_webhook(
    url: str, result: ScanResult, diff: ScanDiff, min_severity: Severity = Severity.MEDIUM
) -> bool:
    """Retorna True se enviou, False se não havia nada relevante."""
    items = relevant(diff, min_severity)
    if not items and not diff.new_hosts and not diff.opened_ports and not diff.mac_changes:
        return False
    async with httpx.AsyncClient(timeout=15, headers={"User-Agent": USER_AGENT}) as client:
        resp = await client.post(url, json=build_payload(url, result, diff, items))
        resp.raise_for_status()
    return True
