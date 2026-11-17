"""Gráficos SVG gerados no servidor: sem biblioteca JS, funcionam até impressos."""

from __future__ import annotations

from html import escape


def score_chart(points: list[tuple[str, int]], width: int = 720, height: int = 220) -> str:
    """Linha da nota (0–100) ao longo do tempo. `points` = [(rótulo, nota)], do mais antigo ao mais novo."""
    if not points:
        return '<p class="muted">Sem dados ainda.</p>'
    pad_l, pad_r, pad_t, pad_b = 36, 12, 12, 28
    plot_w, plot_h = width - pad_l - pad_r, height - pad_t - pad_b
    n = len(points)

    def x(i: int) -> float:
        return pad_l + (plot_w / 2 if n == 1 else plot_w * i / (n - 1))

    def y(score: int) -> float:
        return pad_t + plot_h * (1 - score / 100)

    grid = "".join(
        f'<line x1="{pad_l}" x2="{width - pad_r}" y1="{y(v):.1f}" y2="{y(v):.1f}" class="grid"/>'
        f'<text x="{pad_l - 6}" y="{y(v) + 4:.1f}" class="axis" text-anchor="end">{v}</text>'
        for v in (0, 25, 50, 75, 100)
    )
    # Faixas das notas A (≥90) e F (<40) para leitura rápida
    bands = (
        f'<rect x="{pad_l}" y="{y(100):.1f}" width="{plot_w}" height="{y(90) - y(100):.1f}" class="band-good"/>'
        f'<rect x="{pad_l}" y="{y(40):.1f}" width="{plot_w}" height="{y(0) - y(40):.1f}" class="band-bad"/>'
    )
    path = " ".join(f"{'M' if i == 0 else 'L'}{x(i):.1f},{y(s):.1f}" for i, (_, s) in enumerate(points))
    dots = "".join(
        f'<circle cx="{x(i):.1f}" cy="{y(s):.1f}" r="4" class="dot"><title>{escape(lbl)}: {s}</title></circle>'
        for i, (lbl, s) in enumerate(points)
    )
    step = max(1, n // 6)

    def anchor(i: int) -> str:  # nas pontas, ancorar para dentro evita cortar o texto
        if n > 1 and i == 0:
            return "start"
        return "end" if n > 1 and i == n - 1 else "middle"

    labels = "".join(
        f'<text x="{x(i):.1f}" y="{height - 8}" class="axis" text-anchor="{anchor(i)}">{escape(lbl)}</text>'
        for i, (lbl, _) in enumerate(points) if i % step == 0 or i == n - 1
    )
    return (
        f'<svg viewBox="0 0 {width} {height}" class="chart" role="img" '
        f'aria-label="Evolução da nota">{bands}{grid}<path d="{path}" class="line"/>{dots}{labels}</svg>'
    )


def sparkline(scores: list[int], width: int = 120, height: int = 28) -> str:
    if len(scores) < 2:
        return ""
    step = width / (len(scores) - 1)
    pts = " ".join(f"{i * step:.1f},{height - 2 - (s / 100) * (height - 4):.1f}" for i, s in enumerate(scores))
    return f'<svg viewBox="0 0 {width} {height}" class="spark"><polyline points="{pts}"/></svg>'
