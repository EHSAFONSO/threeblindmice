"""Resumo semanal: a nota da semana, o que mudou e a ação mais importante.

Os alertas só tocam quando aparece algo novo. Numa rede tranquila, isso quer
dizer semanas de silêncio, e o silêncio faz a gente esquecer que o vigia
existe (ou não perceber que ele parou). Uma vez por semana, depois de um scan
agendado, o tbm manda um resumo curto pelo mesmo destino dos alertas.

Ligado por padrão quando há destino de alertas; desligue com
`tbm summary --disable` ou na página Alertas.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from tbm import config
from tbm.models import ScanResult, utcnow
from tbm.squeak.actions import build_actions
from tbm.squeak.diff import diff_scans
from tbm.squeak.store import HistoryStore

INTERVAL = timedelta(days=7)
CONFIG_KEY = "weekly_summary"


def enabled() -> bool:
    return bool(config.load().get(CONFIG_KEY, True))


def set_enabled(value: bool) -> None:
    data = config.load()
    data[CONFIG_KEY] = value
    config.save(data)


def _meta_key(label: str) -> str:
    return f"summary_sent:{label}"


def build_summary(store: HistoryStore, label: str, now: datetime | None = None) -> str | None:
    now = now or utcnow()
    current = store.latest(label)
    if current is None:
        return None
    week_ago = (now - INTERVAL).isoformat()
    baseline = store.latest(label, before=week_ago)
    rows = [r for r in store.list(label, 200) if r["started_at"] >= week_ago]
    lines = [f"🐭 Resumo da semana · {label}",
             f"Nota {current.grade} ({current.score}/100)" + _delta(baseline, current)]
    lines.append(f"{len(rows)} scan(s) nos últimos 7 dias · {len(current.hosts)} aparelho(s) na rede")
    if baseline is not None:
        d = diff_scans(baseline, current)
        if d.resolved_findings:
            lines.append(f"✅ {len(d.resolved_findings)} problema(s) resolvido(s)")
        if d.new_findings:
            lines.append(f"🆕 {len(d.new_findings)} problema(s) novo(s)")
        unknown = [h for h in d.new_hosts if not h.trusted]
        if unknown:
            lines.append("⚠ Aparelhos novos ainda não aprovados: " + ", ".join(h.display for h in unknown[:5]))
    expiring = expiring_acceptances(store, now)
    if expiring:
        lines.append(f"⏰ {len(expiring)} risco(s) aceito(s) vencendo em até 7 dias: " + ", ".join(expiring[:5]))
    actions = build_actions(current)
    if actions:
        lines.append(f"👉 Próximo passo: {actions[0].title} (resolve {len(actions[0].findings)} achado(s))")
    else:
        lines.append("👏 Nada pendente para corrigir.")
    return "\n".join(lines)


def expiring_acceptances(store: HistoryStore, now: datetime | None = None, days: int = 7) -> list[str]:
    """Títulos dos riscos aceitos cujo prazo (until) vence nos próximos `days` dias."""
    from datetime import datetime, timedelta

    today = (now or utcnow()).date()
    out = []
    for row in store.acceptances().values():
        if not row["until"]:
            continue
        try:
            due = datetime.strptime(row["until"], "%Y-%m-%d").date()
        except ValueError:
            continue
        if today <= due <= today + timedelta(days=days):
            out.append(row["title"] or row["fingerprint"][:8])
    return out


def _delta(baseline: ScanResult | None, current: ScanResult) -> str:
    if baseline is None or baseline.score is None or current.score is None:
        return ""
    delta = current.score - baseline.score
    return f", {delta:+d} na semana" if delta else ", igual à semana passada"


def due(store: HistoryStore, label: str, now: datetime | None = None) -> bool:
    if not enabled():
        return False
    last = store.meta(_meta_key(label))
    if last is None:
        return True
    try:
        return (now or utcnow()) - datetime.fromisoformat(last) >= INTERVAL
    except ValueError:
        return True


def mark_sent(store: HistoryStore, label: str, now: datetime | None = None) -> None:
    store.set_meta(_meta_key(label), (now or utcnow()).isoformat())


async def maybe_send(store: HistoryStore, label: str, target: str | None) -> bool:
    """Envia se já faz 7 dias desde o último resumo deste rótulo. Devolve se enviou."""
    if not target or not due(store, label):
        return False
    text = build_summary(store, label)
    if text is None:
        return False
    from tbm.squeak.notify import send_text

    await send_text(target, text, title=f"threeblindmice: resumo semanal ({label})")
    mark_sent(store, label)
    return True
