from pathlib import Path

from tbm.models import Finding, Host, ScanResult, Service, Severity
from tbm.pipeline import finalize
from tbm.squeak import HistoryStore, diff_scans, grade_for, render_html, score_findings
from tbm.squeak.notify import build_payload


def _f(sev: Severity, key: str = "", host: str = "10.0.0.1", port: int = 22) -> Finding:
    return Finding(check_id="t", title=f"achado {key}", severity=sev, host=host, port=port, key=key)


def test_score_and_grade():
    assert score_findings([]) == 100 and grade_for(100) == "A"
    one_critical = score_findings([_f(Severity.CRITICAL)])
    many_low = score_findings([_f(Severity.LOW, str(i)) for i in range(5)])
    assert one_critical < many_low < 100
    assert score_findings([_f(Severity.INFO)]) == 100
    assert grade_for(0) == "F"


def test_fingerprint_is_stable():
    assert _f(Severity.LOW, "a").fingerprint == _f(Severity.HIGH, "a").fingerprint
    assert _f(Severity.LOW, "a").fingerprint != _f(Severity.LOW, "b").fingerprint


def _scan(findings, ports, hosts=("10.0.0.1",)) -> ScanResult:
    r = ScanResult(
        label="casa",
        hosts=[Host(address=h, services=[Service(port=p) for p in ports]) for h in hosts],
        findings=findings,
    )
    return finalize(r)


def test_diff():
    old = _scan([_f(Severity.HIGH, "a"), _f(Severity.LOW, "b")], [22, 80])
    new = _scan([_f(Severity.LOW, "b"), _f(Severity.CRITICAL, "c")], [22, 443],
                hosts=("10.0.0.1", "10.0.0.2"))
    d = diff_scans(old, new)
    assert [f.key for f in d.new_findings] == ["c"]
    assert [f.key for f in d.resolved_findings] == ["a"]
    assert [f.key for f in d.persisting_findings] == ["b"]
    assert d.new_hosts == ["10.0.0.2"]
    assert d.opened_ports == [("10.0.0.1", 443)]  # 10.0.0.2 é host novo, não "porta nova"
    assert d.closed_ports == [("10.0.0.1", 80)]
    assert d.score_delta == new.score - old.score
    assert d.has_changes


def test_diff_ignores_ports_not_scanned_in_both():
    old = _scan([], [135, 445])
    old.ports_scanned = [135, 445]
    new = _scan([], [445, 8000])
    new.ports_scanned = [445, 8000]
    d = diff_scans(old, new)
    assert d.closed_ports == [] and d.opened_ports == []


def test_history_roundtrip(tmp_path: Path):
    store = HistoryStore(tmp_path / "h.db")
    first = _scan([_f(Severity.HIGH, "a")], [22])
    second = _scan([], [22])
    store.save(first)
    store.save(second)
    assert store.get(first.scan_id[:6]).scan_id == first.scan_id
    assert store.latest("casa", exclude=second.scan_id).scan_id == first.scan_id
    assert len(store.list("casa")) == 2


def test_report_renders_and_escapes():
    evil = Finding(check_id="t", title="<script>alert(1)</script>", severity=Severity.HIGH,
                   host="10.0.0.1")
    html = render_html(_scan([evil], [22]), diff_scans(None, _scan([evil], [22])))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "threeblindmice" in html


def test_webhook_payload_formats():
    r = _scan([_f(Severity.HIGH, "a")], [22])
    d = diff_scans(None, r)
    discord = build_payload("https://discord.com/api/webhooks/x", r, d, d.new_findings)
    slack = build_payload("https://hooks.slack.com/services/x", r, d, d.new_findings)
    generic = build_payload("https://example.invalid/hook", r, d, d.new_findings)
    assert "content" in discord and "text" in slack
    assert generic["new_findings"][0]["severity"] == "high"
