"""Ambiente Jinja da interface: filtros, globais e a função `render` das rotas."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from tbm import __version__, i18n
from tbm.dashboard.icons import device_icon
from tbm.squeak.notify import port_label

if TYPE_CHECKING:
    from tbm.dashboard.security import GuiSettings
    from tbm.squeak import HistoryStore

HERE = Path(__file__).parent
Render = Callable[..., HTMLResponse]

env = Environment(
    loader=FileSystemLoader(HERE / "templates"),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)

SEV_NAMES = {"critical": "crítico", "high": "alto", "medium": "médio", "low": "baixo", "info": "info",
             "ok": "sem problemas"}

CATEGORIES = {"familia": "Família", "visitas": "Visitas", "casa-inteligente": "Casa inteligente",
              "trabalho": "Trabalho", "infraestrutura": "Infraestrutura"}


def sev_name(value) -> str:
    """Nome da severidade no idioma da interface (aceita Severity ou texto)."""
    key = getattr(value, "value", value)
    return i18n.gettext(SEV_NAMES.get(key, key))


def model_label(host) -> str | None:
    from tbm.scout.model import model_label as label

    return label(host)


def mini_path(values: list[int], w: int = 300, h: int = 64) -> dict[str, str]:
    """Curva suave (Catmull-Rom → Bézier) para os gráficos pequenos, com área preenchida."""
    if not values:
        return {"line": "", "area": "", "x": "0", "y": "0"}
    if len(values) == 1:
        values = values * 2
    pad = 4
    span = max(max(values) - min(values), 10)
    mid = (max(values) + min(values)) / 2
    lo, hi = mid - span / 2, mid + span / 2
    pts = [(pad + (w - 2 * pad) * i / (len(values) - 1), pad + (h - 2 * pad) * (1 - (v - lo) / (hi - lo)))
           for i, v in enumerate(values)]
    d = f"M{pts[0][0]:.1f},{pts[0][1]:.1f}"
    for i in range(len(pts) - 1):
        p0, p1, p2 = pts[max(i - 1, 0)], pts[i], pts[i + 1]
        p3 = pts[min(i + 2, len(pts) - 1)]
        c1 = (p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6)
        c2 = (p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6)
        d += f" C{c1[0]:.1f},{c1[1]:.1f} {c2[0]:.1f},{c2[1]:.1f} {p2[0]:.1f},{p2[1]:.1f}"
    area = d + f" L{pts[-1][0]:.1f},{h} L{pts[0][0]:.1f},{h} Z"
    return {"line": d, "area": area, "x": f"{pts[-1][0]:.1f}", "y": f"{pts[-1][1]:.1f}", "w": str(w), "h": str(h)}


def action_guide(action, scan):
    """Passo a passo da correção no modelo do roteador (ou None)."""
    from tbm.squeak.guides import guide_for

    return guide_for(action.kind, scan.host(action.host), scan.gateway)


def action_title(action) -> str:
    """Título da ação no idioma da interface (o modelo do tipo é traduzido, o aparelho não)."""
    from tbm.squeak.actions import KINDS

    device = action.device
    if action.device_type and action.device_type in device:
        device = device.replace(action.device_type, i18n.device_type(action.device_type) or action.device_type)
    if action.kind in KINDS:
        return i18n.gettext(KINDS[action.kind].title).replace("{dev}", device)
    return action.title


def when(iso: str) -> str:
    return iso[:16].replace("T", " ")


env.filters.update(port=port_label, dtype=i18n.device_type, sev=sev_name, when=when)
env.globals.update(
    device_icon=device_icon, _=i18n.gettext, html_lang=i18n.html_lang, get_lang=i18n.get_lang,
    js_i18n=i18n.js_catalog, LANGS=i18n.LANGS, CATEGORIES=CATEGORIES, model_label=model_label,
    mini_path=mini_path, action_guide=action_guide, action_title=action_title,
)


def latest_label(store: HistoryStore) -> str | None:
    """Rótulo do scan mais recente (a página que abre por padrão)."""
    labels = store.labels()
    return max(labels, key=lambda r: r["started_at"])["label"] if labels else None


def make_render(store: HistoryStore, gui: GuiSettings | None) -> Render:
    def nav_unknown() -> int:
        """Aparelhos do último scan que você ainda não aprovou (selo no menu)."""
        label = latest_label(store)
        scan = store.latest(label) if label else None
        return sum(1 for h in scan.hosts if not h.trusted) if scan else 0

    def render(name: str, **ctx) -> HTMLResponse:
        nav = [r["label"] for r in store.labels()]
        return HTMLResponse(env.get_template(name).render(
            version=__version__, nav_labels=nav, gui=gui is not None, nav_unknown=nav_unknown,
            csrf_token=gui.token if gui else "", **ctx))

    return render
