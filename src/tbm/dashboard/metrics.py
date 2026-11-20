"""Métricas no formato Prometheus (texto), para quem já tem Grafana/Prometheus.

Exposto em GET /metrics no dashboard somente leitura (`tbm dashboard`), sem
token: são só números agregados (nota e contagem por severidade de cada
rótulo), nunca IPs, MACs ou nomes de aparelhos. Nada que identifique a rede.
"""

from __future__ import annotations

from tbm.squeak import HistoryStore

_SEV = ("critical", "high", "medium", "low")


def render_metrics(store: HistoryStore) -> str:
    lines = [
        "# HELP tbm_score Nota do último scan (0-100).",
        "# TYPE tbm_score gauge",
        "# HELP tbm_findings_open Achados abertos por severidade no último scan.",
        "# TYPE tbm_findings_open gauge",
        "# HELP tbm_devices Dispositivos no último scan.",
        "# TYPE tbm_devices gauge",
        "# HELP tbm_last_scan_timestamp_seconds Horário do último scan (epoch).",
        "# TYPE tbm_last_scan_timestamp_seconds gauge",
    ]
    for row in store.labels():
        label = _escape(row["label"])
        lines.append(f'tbm_score{{label="{label}"}} {row["score"] or 0}')
        lines.append(f'tbm_devices{{label="{label}"}} {row["hosts"] or 0}')
        for sev in _SEV:
            lines.append(f'tbm_findings_open{{label="{label}",severity="{sev}"}} {row[sev] or 0}')
        scan = store.latest(row["label"])
        if scan is not None:
            lines.append(f'tbm_last_scan_timestamp_seconds{{label="{label}"}} {scan.started_at.timestamp():.0f}')
    return "\n".join(lines) + "\n"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
