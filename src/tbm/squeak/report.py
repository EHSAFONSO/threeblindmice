"""Geração de relatórios: HTML autocontido, JSON e SARIF."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from tbm import __version__
from tbm.models import ScanResult, Severity
from tbm.squeak.diff import ScanDiff
from tbm.squeak.notify import port_label
from tbm.squeak.sarif import to_sarif

_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
_env.filters["port"] = port_label


def render_html(result: ScanResult, diff: ScanDiff | None = None) -> str:
    template = _env.get_template("report.html.j2")
    return template.render(
        r=result,
        diff=diff,
        counts=result.severity_counts(),
        severities=sorted(Severity, key=lambda s: -s.rank),
        version=__version__,
    )


def write_report(result: ScanResult, path: Path, diff: ScanDiff | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    suffix = path.suffix.lower()
    if suffix == ".json":
        path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    elif suffix == ".sarif":
        path.write_text(json.dumps(to_sarif(result), indent=2), encoding="utf-8")
    else:
        path.write_text(render_html(result, diff), encoding="utf-8")
    return path
