"""Squeak: comunicação. Nota de risco, histórico, diff, relatório e alertas."""

from tbm.squeak.diff import ScanDiff, diff_scans
from tbm.squeak.notify import send_webhook
from tbm.squeak.report import render_html, write_report
from tbm.squeak.scoring import grade_for, score_findings
from tbm.squeak.store import HistoryStore, tbm_home

__all__ = [
    "HistoryStore",
    "ScanDiff",
    "diff_scans",
    "grade_for",
    "render_html",
    "score_findings",
    "send_webhook",
    "tbm_home",
    "write_report",
]
