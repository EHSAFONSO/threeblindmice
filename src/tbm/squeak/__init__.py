"""Squeak: comunicação. Nota de risco, histórico, diff, relatórios e alertas."""

from tbm.paths import tbm_home
from tbm.squeak.diff import ScanDiff, diff_scans
from tbm.squeak.notify import send_webhook
from tbm.squeak.redact import redact
from tbm.squeak.report import render_html, write_report
from tbm.squeak.sarif import to_sarif
from tbm.squeak.scoring import grade_for, score_findings
from tbm.squeak.store import HistoryStore

__all__ = [
    "HistoryStore",
    "ScanDiff",
    "diff_scans",
    "grade_for",
    "redact",
    "render_html",
    "score_findings",
    "send_webhook",
    "tbm_home",
    "to_sarif",
    "write_report",
]
