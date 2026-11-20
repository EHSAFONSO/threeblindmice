"""Dados das páginas visuais: painel de saúde, mapa da rede e linha do tempo.

Só cálculo, sem HTML: os templates desenham, os testes conferem os números.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from html import escape
from typing import Any

from tbm.dashboard.icons import device_icon
from tbm.i18n import gettext as _
from tbm.models import Host, ScanResult, Severity, utcnow
from tbm.squeak import HistoryStore, diff_scans
from tbm.squeak.actions import Action, build_actions, impacts, progress, project

SEV_ORDER = ["critical", "high", "medium", "low"]


def worst(scan: ScanResult, address: str) -> str:
    """Pior severidade *aberta* do aparelho: critical/high/medium/low, ou ok."""
    ranks = [f.severity for f in scan.findings
             if f.host == address and not f.accepted and f.severity is not Severity.INFO]
    if not ranks:
        return "ok"
    return max(ranks, key=lambda s: s.rank).value


def humanize_age(when: datetime, now: datetime | None = None) -> str:
    seconds = int(((now or utcnow()) - when).total_seconds())
    if seconds < 90:
        return _("agora há pouco")
    if seconds < 3600:
        return _("há {n} min", n=seconds // 60)
    if seconds < 86400:
        return _("há {n} h", n=seconds // 3600)
    days = seconds // 86400
    return _("ontem") if days == 1 else _("há {n} dias", n=days)


def gauge(score: int, radius: int = 78) -> dict[str, float]:
    circumference = 2 * math.pi * radius
    return {"r": radius, "c": round(circumference, 1), "offset": round(circumference * (1 - score / 100), 1)}


# ───────────────────────────── painel de saúde ─────────────────────────────


@dataclass
class Health:
    label: str
    scan: ScanResult
    actions: list[Action]
    progress: Any
    delta: int | None
    scores: list[int]
    devices: int
    open_counts: dict[str, int]
    age: str
    gauge: dict[str, float]
    labels: list[str] = field(default_factory=list)
    projection: Any = None  # nota se as 3 primeiras ações forem feitas
    impact: dict[str, int] = field(default_factory=dict)  # pontos que cada ação soma
    unknown: int = 0  # aparelhos não aprovados
    resolved_total: int = 0


def health(store: HistoryStore, label: str) -> Health | None:
    scan = store.latest(label)
    if scan is None:
        return None
    rows = store.list(label, 30)
    history = store.light(label, 30, skip_latest=True)  # do mais antigo ao anterior a este
    previous = history[-1] if history else None
    delta = None
    if previous and previous.score is not None and scan.score is not None:
        delta = scan.score - previous.score
    counts = {s: 0 for s in SEV_ORDER}
    for f in scan.findings:
        if not f.accepted and f.severity.value in counts:
            counts[f.severity.value] += 1
    actions = build_actions(scan)
    return Health(
        label=label, scan=scan, actions=actions, progress=progress(history, scan), delta=delta,
        scores=[r["score"] or 0 for r in reversed(rows)], devices=len(scan.hosts), open_counts=counts,
        age=humanize_age(scan.started_at), gauge=gauge(scan.score or 0),
        labels=[r["label"] for r in store.labels()],
        projection=project(scan, actions[:3]) if actions else None,
        impact=impacts(scan, actions),
        unknown=sum(1 for h in scan.hosts if not h.trusted),
    )


# ───────────────────────────── mapa da rede ─────────────────────────────

MAP_W = 960
# Notas do mapa: o texto é a chave de tradução (ver tbm/i18n.py, EXTRA_KEYS)
NOTE_ESTIMATED = "O roteador principal foi estimado (scans anteriores à v0.7 não registravam o gateway)."
NOTE_DOUBLE_NAT = ("Há {n} roteadores/modems na mesma rede. Pode haver NAT duplo (comum quando o modem da operadora "
                   "fica entre a internet e o seu roteador); vale conferir com o provedor.")
PER_ROW = 6


def _short(h: Host) -> str:
    name = h.name or h.device_type or h.address
    return name if len(name) <= 22 else name[:20] + "…"


def network_map(scan: ScanResult, offline: list[Host] | None = None) -> dict[str, Any]:
    """Internet → roteador → aparelhos. `offline`: vistos em scans recentes, ausentes neste."""
    def ip_order(h: Host) -> tuple[int, ...]:
        parts = h.address.split(".")
        return tuple(int(p) for p in parts) if len(parts) == 4 and all(p.isdigit() for p in parts) else (999,)

    hosts = sorted(scan.hosts, key=ip_order)
    by_ip = {h.address: h for h in hosts}
    routers = [h for h in hosts if h.device_type == "roteador/modem"]
    notes: list[dict[str, Any]] = []
    gw = by_ip.get(scan.gateway or "")
    if gw is None:
        gw = routers[0] if routers else None
        if gw is not None:
            notes.append({"text": NOTE_ESTIMATED, "args": {}})
    other_routers = [h for h in routers if h is not gw]
    devices = [h for h in hosts if h is not gw and h not in other_routers]

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    cx = MAP_W / 2
    nodes.append({"x": cx, "y": 56, "icon": "globe", "label": "Internet", "sub": "", "sev": "none", "address": None})

    def node(h: Host, x: float, y: float, role: str) -> dict[str, Any]:
        # A dica é inserida como HTML no navegador, e o nome vem da *rede* (mDNS/SSDP):
        # um aparelho malicioso pode se anunciar como "<img onerror=…>". Tudo escapado.
        tip = f"<b>{escape(_short(h))}</b><br>{escape(h.address)}"
        if h.device_type:
            tip += f" · {escape(h.device_type)}"
        return {"x": round(x), "y": round(y), "icon": device_icon(h.device_type), "label": _short(h), "sub": h.address,
                "type": h.device_type, "trusted": h.trusted, "category": h.category or "",
                "sev": worst(scan, h.address), "address": h.address, "role": role, "tip": tip}

    hub_y = 186
    if gw is not None:
        nodes.append(node(gw, cx, hub_y, "gateway"))
        edges.append({"x1": cx, "y1": 56, "x2": cx, "y2": hub_y, "dashed": False})
    for i, r in enumerate(other_routers):
        x = cx + (240 * (i // 2 + 1)) * (1 if i % 2 == 0 else -1)
        nodes.append(node(r, x, hub_y, "router"))
        edges.append({"x1": cx, "y1": hub_y, "x2": x, "y2": hub_y, "dashed": True})
    if other_routers:
        notes.append({"text": NOTE_DOUBLE_NAT, "args": {"n": len(other_routers) + 1}})

    top = hub_y + 140
    for i, h in enumerate(devices):
        row, col = divmod(i, PER_ROW)
        in_row = min(PER_ROW, len(devices) - row * PER_ROW)
        spacing = MAP_W / (in_row + 1)
        x, y = spacing * (col + 1), top + row * 140
        nodes.append(node(h, x, y, "device"))
        if gw is not None:
            edges.append({"x1": cx, "y1": hub_y, "x2": x, "y2": y, "dashed": False})
    rows = math.ceil(len(devices) / PER_ROW) if devices else 0
    height = (top + (rows - 1) * 140 + 80) if rows else hub_y + 90
    # aparelhos que sumiram: uma faixa embaixo, tracejada, sem ligação com o roteador
    off = offline or []
    if off:
        off_top = height + 70
        for i, h in enumerate(off[:PER_ROW * 2]):
            row, col = divmod(i, PER_ROW)
            in_row = min(PER_ROW, len(off) - row * PER_ROW)
            n = node(h, MAP_W / (in_row + 1) * (col + 1), off_top + row * 130, "offline")
            n["sev"] = "none"
            nodes.append(n)
        height = off_top + (math.ceil(min(len(off), PER_ROW * 2) / PER_ROW) - 1) * 130 + 80
    legend = {s: sum(1 for n in nodes if n["sev"] == s) for s in [*SEV_ORDER, "ok"]}
    return {"width": MAP_W, "height": height, "nodes": nodes, "edges": edges, "notes": notes, "legend": legend,
            "offline_y": (top + (rows - 1) * 140 + 80 + 30) if off and rows else None}


def offline_hosts(store: HistoryStore, label: str, scan: ScanResult, window: int = 10) -> list[Host]:
    """Aparelhos vistos nos últimos scans que não apareceram neste (desligados ou fora de casa)."""
    present = {h.identity for h in scan.hosts}
    seen: dict[str, Host] = {}
    for old in reversed(store.light(label, window, skip_latest=True)):  # do mais recente ao mais antigo
        for h in old.hosts:
            if h.identity not in present and h.identity not in seen:
                seen[h.identity] = h
    return list(seen.values())


# ───────────────────────────── linha do tempo ─────────────────────────────

CHART = {"w": 760, "h": 250, "l": 40, "r": 18, "t": 16, "b": 34}


def timeline(store: HistoryStore, label: str, limit: int = 30) -> dict[str, Any]:
    scans = store.light(label, limit)
    w, h, left, right, top, bottom = (CHART[k] for k in ("w", "h", "l", "r", "t", "b"))
    pw, ph = w - left - right, h - top - bottom
    n = len(scans)

    def x(i: int) -> float:
        return left + (pw / 2 if n == 1 else pw * i / (n - 1))

    def y(score: float) -> float:
        return top + ph * (1 - score / 100)

    points: list[dict[str, Any]] = []
    prev: ScanResult | None = None
    for i, s in enumerate(scans):
        events: list[str] = []
        if prev is not None:
            d = diff_scans(prev, s)
            if d.new_hosts:
                events.append(_("{n} dispositivo(s) novo(s)", n=len(d.new_hosts)))
            if d.new_findings:
                events.append(_("{n} achado(s) novo(s)", n=len(d.new_findings)))
            if d.resolved_findings:
                events.append(_("{n} resolvido(s)", n=len(d.resolved_findings)))
            if d.mac_changes:
                events.append(_("MAC trocado"))
        before = sum(1 for f in prev.findings if f.accepted) if prev else 0
        newly_accepted = sum(1 for f in s.findings if f.accepted) - before
        if newly_accepted > 0:
            events.append(_("{n} risco(s) aceito(s)", n=newly_accepted))
        local = s.started_at.astimezone()
        tip = (f"<b>{local:%d/%m %H:%M}</b> · " + _("nota {g} {s}/100", g=s.grade, s=s.score)
               + "".join(f"<br>• {e}" for e in events))
        points.append({"x": round(x(i), 1), "y": round(y(s.score or 0), 1), "id": s.scan_id, "tip": tip,
                       "event": bool(events), "label": f"{local:%d/%m %H:%M}"})
        prev = s

    # Rótulos do eixo X sem sobreposição: o último sempre aparece e os demais
    # só se ficarem a pelo menos 95 px dele e entre si (o bug da v0.6).
    labels: list[dict[str, Any]] = []
    min_gap = 95
    if points:
        last = points[-1]
        for p in points[:-1]:
            if (not labels or p["x"] - labels[-1]["x"] >= min_gap) and last["x"] - p["x"] >= min_gap:
                labels.append({"x": p["x"], "text": p["label"], "anchor": "start" if not labels else "middle"})
        labels.append({"x": last["x"], "text": last["label"], "anchor": "end" if n > 1 else "middle"})
    path = " ".join(f"{'M' if i == 0 else 'L'}{p['x']},{p['y']}" for i, p in enumerate(points))
    area = (f"{path} L{points[-1]['x']},{top + ph} L{points[0]['x']},{top + ph} Z") if n > 1 else ""
    return {"w": w, "h": h, "left": left, "right": w - right, "top": top, "bottom": top + ph,
            "grid": [{"y": round(y(v), 1), "v": v} for v in (0, 25, 50, 75, 100)],
            "band_good": {"y": y(100), "h": y(90) - y(100)}, "band_bad": {"y": y(40), "h": y(0) - y(40)},
            "points": points, "labels": labels, "path": path, "area": area}


def device_history(store: HistoryStore, label: str, identity: str, limit: int = 30) -> dict[str, Any]:
    """O que mudou neste aparelho, scan a scan: IP, portas e achados abertos."""
    events: list[dict[str, Any]] = []
    series: list[int] = []
    prev: dict[str, Any] | None = None
    for scan in store.light(label, limit):
        host = next((h for h in scan.hosts if h.identity == identity), None)
        if host is None:
            continue
        ports = {s.port for s in host.services if s.transport == "tcp"}
        open_fp = {f.fingerprint: f.title for f in scan.findings
                   if f.host == host.address and not f.accepted and f.severity is not Severity.INFO}
        series.append(len(open_fp))
        when = scan.started_at.astimezone().strftime("%d/%m %H:%M")
        if prev is None:
            events.append({"when": when, "text": _("Visto pela primeira vez em {ip}", ip=host.address)})
        else:
            if host.address != prev["ip"]:
                events.append({"when": when, "text": _("IP mudou: {a} → {b}", a=prev["ip"], b=host.address)})
            if opened := sorted(ports - prev["ports"]):
                events.append({"when": when, "text": _("Porta(s) aberta(s): {p}", p=", ".join(map(str, opened)))})
            if closed := sorted(prev["ports"] - ports):
                events.append({"when": when, "text": _("Porta(s) fechada(s): {p}", p=", ".join(map(str, closed)))})
            if fixed := [t for fp, t in prev["open"].items() if fp not in open_fp]:
                events.append({"when": when, "text": _("Resolvido: {t}", t="; ".join(fixed[:3]))})
            if new := [t for fp, t in open_fp.items() if fp not in prev["open"]]:
                events.append({"when": when, "text": _("Novo problema: {t}", t="; ".join(new[:3]))})
        prev = {"ip": host.address, "ports": ports, "open": open_fp}
    return {"events": list(reversed(events))[:25], "series": series}


def device_detail(store: HistoryStore, label: str, address: str) -> dict[str, Any] | None:
    scan = store.latest(label)
    if scan is None:
        return None
    host = scan.host(address)
    if host is None:
        return None
    findings = sorted((f for f in scan.findings if f.host == address), key=lambda f: f.sort_key())
    actions = [a for a in build_actions(scan) if a.host == address]
    first_seen = store.first_seen(label, host.identity)
    return {"host": host, "findings": findings, "actions": actions, "sev": worst(scan, address),
            "icon": device_icon(host.device_type), "first_seen": first_seen, "label": label, "scan": scan}
