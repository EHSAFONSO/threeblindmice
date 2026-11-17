"""EPSS, backport, CVE end-to-end (com HTTP falso), segredos, SARIF, redação, escopo, dashboard."""

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from tbm.cli import app, parse_interval
from tbm.dashboard import create_app
from tbm.models import Finding, Host, ScanResult, Service, Severity, TLSInfo
from tbm.pipeline import finalize
from tbm.scope import Scope, ScopeError
from tbm.sniffer import Sniffer, SnifferOptions
from tbm.sniffer.backport import compare_versions, distro_package, ubuntu_fixed
from tbm.sniffer.base import CheckContext
from tbm.sniffer.cve import CVECheck, NVDClient
from tbm.sniffer.epss import EPSSClient
from tbm.sniffer.secrets import is_ignored, scan_paths
from tbm.sniffer.tls_checks import analyze_tls
from tbm.squeak import HistoryStore, redact, to_sarif
from tbm.squeak.scoring import score_findings

# ───────────────────────────── versões dpkg ─────────────────────────────


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.0", "1.0", 0),
        ("1.0~rc1", "1.0", -1),
        ("1:8.2p1-4ubuntu0.5", "1:8.2p1-4ubuntu0.9", -1),
        ("1:8.2p1-4ubuntu0.10", "1:8.2p1-4ubuntu0.9", 1),
        ("2.0", "1.9", 1),
        ("1:1.0", "2.0", 1),  # epoch manda
        ("1.0-1", "1.0-1ubuntu1", -1),
        ("1.0a", "1.0+", -1),  # letras antes de símbolos
    ],
)
def test_dpkg_compare(a, b, expected):
    result = compare_versions(a, b)
    assert (result > 0) - (result < 0) == expected


def test_distro_package_from_banner():
    pkg = distro_package("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
    assert pkg.distro == "ubuntu" and pkg.version == "1:8.2p1-4ubuntu0.5" and pkg.upstream == "8.2p1"
    assert distro_package("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2").distro == "debian"
    assert distro_package("SSH-2.0-OpenSSH_9.6") is None


UBUNTU_PAYLOAD = {"packages": [{"name": "openssh", "statuses": [
    {"release_codename": "focal", "status": "released", "description": "1:8.2p1-4ubuntu0.9"},
    {"release_codename": "jammy", "status": "released", "description": "1:8.9p1-3ubuntu0.4"},
]}]}


def test_ubuntu_fixed_logic():
    old = distro_package("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
    new = distro_package("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11")
    assert ubuntu_fixed(UBUNTU_PAYLOAD, old) is False
    assert ubuntu_fixed(UBUNTU_PAYLOAD, new) is True
    other = distro_package("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
    assert ubuntu_fixed(UBUNTU_PAYLOAD, other) is None  # release não listada


# ───────────────────── CVE + EPSS + backport (HTTP falso) ─────────────────────

def _nvd(cves):
    return {"totalResults": len(cves), "resultsPerPage": len(cves), "vulnerabilities": [
        {"cve": {"id": cid, "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": cid}],
                 "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": score}}]},
                 **({"cisaExploitAdd": "2024-01-01"} if kev else {})}}
        for cid, score, kev in cves
    ]}


def _fake_internet(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if "services.nvd.nist.gov" in url:
        return httpx.Response(200, json=_nvd([
            ("CVE-2023-0001", 9.8, False),   # crítico mas EPSS baixo
            ("CVE-2023-0002", 6.5, False),   # médio com EPSS alto
            ("CVE-2023-0003", 7.5, True),    # KEV
            ("CVE-2023-0004", 8.1, False),   # já corrigido pelo Ubuntu
        ]))
    if "api.first.org" in url:
        return httpx.Response(200, json={"data": [
            {"cve": "CVE-2023-0001", "epss": "0.002"},
            {"cve": "CVE-2023-0002", "epss": "0.71"},
            {"cve": "CVE-2023-0003", "epss": "0.40"},
        ]})
    if "ubuntu.com" in url:
        fixed = "1:8.2p1-4ubuntu0.3" if "0004" in url else "1:8.2p1-4ubuntu0.99"
        return httpx.Response(200, json={"packages": [{"name": "openssh", "statuses": [
            {"status": "released", "description": fixed}]}]})
    return httpx.Response(404)


async def test_cve_check_prioritizes_and_filters_backports(tmp_path):
    host = Host(address="10.0.0.7", services=[Service(
        port=22, name="ssh", product="OpenSSH", version="8.2p1",
        banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")])
    scan = ScanResult(hosts=[host])
    async with httpx.AsyncClient(transport=httpx.MockTransport(_fake_internet)) as http:
        ctx = CheckContext(scan=scan, http=http, options=SnifferOptions(cache_dir=tmp_path),
                           nvd=NVDClient(http, cache_dir=tmp_path))
        findings = await CVECheck().run(ctx)

    by_key = {f.key: f for f in findings}
    assert "CVE-2023-0004" not in by_key                           # backport
    assert by_key["backport"].severity is Severity.INFO
    assert by_key["CVE-2023-0003"].kev and by_key["CVE-2023-0003"].severity is Severity.CRITICAL
    assert by_key["CVE-2023-0002"].epss == pytest.approx(0.71)
    ordered = [f.key for f in sorted(findings, key=Finding.sort_key) if f.key.startswith("CVE")]
    assert ordered == ["CVE-2023-0003", "CVE-2023-0001", "CVE-2023-0002"]


async def test_epss_cache(tmp_path):
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"data": [{"cve": "CVE-1", "epss": "0.5"}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        assert (await EPSSClient(http, tmp_path).scores(["CVE-1", "CVE-2"])) == {"CVE-1": 0.5, "CVE-2": 0.0}
        assert (await EPSSClient(http, tmp_path).scores(["CVE-1"])) == {"CVE-1": 0.5}
    assert calls == 1  # o segundo cliente leu do cache em disco


def test_scoring_uses_exploitability():
    base = Finding(check_id="c", title="t", severity=Severity.HIGH, host="h", key="a")
    kev = base.model_copy(update={"kev": True})
    unlikely = base.model_copy(update={"epss": 0.001})
    assert score_findings([kev]) < score_findings([base]) < score_findings([unlikely])


# ───────────────────────────── escopo ─────────────────────────────


def test_scope_enforce():
    Scope.default().enforce(["192.168.0.1", "10.1.1.1"])
    with pytest.raises(ScopeError, match="8.8.8.8"):
        Scope.default().enforce(["192.168.0.1", "8.8.8.8"])


async def test_sniffer_refuses_out_of_scope_hosts():
    tampered = ScanResult(hosts=[Host(address="8.8.8.8", services=[Service(port=80, name="http")])])
    with pytest.raises(ScopeError):
        await Sniffer(SnifferOptions(active=True, cve=False)).run(tampered)


def test_cli_sniff_rejects_tampered_json(tmp_path):
    f = tmp_path / "scout.json"
    f.write_text(ScanResult(hosts=[Host(address="1.1.1.1")]).model_dump_json(), encoding="utf-8")
    result = CliRunner().invoke(app, ["sniff", str(f), "--no-cve"])
    assert result.exit_code == 2
    assert "fora do escopo" in result.output


def test_url_for_uses_validated_ip():
    """Proteção contra DNS rebinding: a URL usa o IP, nunca o hostname."""
    from tbm.sniffer.base import url_for

    h = Host(address="192.168.0.9", hostname="nas.lan")
    assert url_for(h, Service(port=8080, name="http")) == "http://192.168.0.9:8080/"


# ───────────────────────────── TLS legado ─────────────────────────────


def test_tls_untestable_is_reported():
    info = TLSInfo(not_after=datetime(2099, 1, 1, tzinfo=UTC), legacy_untestable=["TLSv1.0"])
    [f] = analyze_tls("h", 443, info)
    assert f.key == "legacy-untestable" and f.severity is Severity.INFO


# ───────────────────────────── segredos ─────────────────────────────

FAKE_GH = "ghp_" + "Ab1Cd2Ef3G" * 4


def test_secrets_pragma_ignore_and_location(tmp_path):
    (tmp_path / "app.py").write_text(
        f'TOKEN = "{FAKE_GH}"\n'
        f'TEST_TOKEN = "{FAKE_GH}"  # tbm:allow\n', encoding="utf-8")
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "data.txt").write_text(FAKE_GH, encoding="utf-8")
    (tmp_path / ".tbmignore").write_text("fixtures/\n", encoding="utf-8")
    [f] = scan_paths([tmp_path], base=tmp_path)
    assert (f.file, f.line) == ("app.py", 1)
    assert f.location == "app.py:1"


def test_tbmignore_with_bom(tmp_path):
    """O PowerShell 5.1 grava UTF-8 com BOM; o .tbmignore tem que funcionar mesmo assim."""
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.py").write_text(f'X = "{FAKE_GH}"', encoding="utf-8")
    (tmp_path / "app.py").write_text(f'T = "{FAKE_GH}"', encoding="utf-8-sig")
    (tmp_path / ".tbmignore").write_text("vendor/\n", encoding="utf-8-sig")
    [f] = scan_paths([tmp_path], base=tmp_path)
    assert f.file == "app.py" and "﻿" not in f.evidence


def test_ignore_patterns():
    assert is_ignored("tests/x.py", ["tests"])
    assert is_ignored("a/b/yarn.lock", ["*.lock"])
    assert is_ignored("docs/x/y.md", ["docs/**"])
    assert not is_ignored("src/tests_helper.py", ["tests"])


def test_secrets_multiple_paths_and_sarif_export(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a.env").write_text(f"GH={FAKE_GH}\n", encoding="utf-8")
    (tmp_path / "b.cfg").write_text("nada aqui\n", encoding="utf-8")
    out = tmp_path / "out.sarif"
    result = CliRunner().invoke(app, ["secrets", "a.env", "b.cfg", "-o", str(out)])
    assert result.exit_code == 1
    sarif = json.loads(out.read_text(encoding="utf-8"))
    res = sarif["runs"][0]["results"][0]
    assert res["ruleId"] == "secrets.local/github-token"
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "a.env" and loc["region"]["startLine"] == 1


def test_sarif_network_findings_use_logical_location():
    r = finalize(ScanResult(findings=[Finding(check_id="tls.config", title="x", host="10.0.0.1",
                                              port=443, severity=Severity.HIGH)]))
    sarif = to_sarif(r)
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "8.0"
    assert sarif["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0]["name"] == "10.0.0.1:443"


# ───────────────────────────── redação ─────────────────────────────


def test_redact_removes_evidence_but_keeps_structure():
    r = ScanResult(
        hosts=[Host(address="10.0.0.1", services=[Service(port=22, banner="SSH-2.0-x",
                                                          extra={"server": "nginx/1.2"})])],
        findings=[Finding(check_id="c", title="t", severity=Severity.LOW, host="10.0.0.1",
                          evidence="segredo")],
    )
    clean = redact(r)
    assert clean.findings[0].evidence.startswith("[omitido")
    assert clean.hosts[0].services[0].banner is None
    assert clean.findings[0].fingerprint == r.findings[0].fingerprint  # o diff continua funcionando
    assert r.findings[0].evidence == "segredo"  # original intacto


# ───────────────────────────── histórico e dashboard ─────────────────────────────


def _saved_store(tmp_path: Path) -> tuple[HistoryStore, list[ScanResult]]:
    store = HistoryStore(tmp_path / "h.db")
    scans = []
    for i, n in enumerate([3, 1]):
        r = ScanResult(label="casa", started_at=datetime(2026, 1, i + 1, tzinfo=UTC),
                       hosts=[Host(address=f"10.0.0.{j}") for j in range(1, 3 + i)],
                       findings=[Finding(check_id="c", title=f"f{k}", severity=Severity.HIGH,
                                         host="10.0.0.1", key=str(k)) for k in range(n)])
        store.save(finalize(r))
        scans.append(r)
    return store, scans


def test_store_labels_and_counts(tmp_path):
    store, scans = _saved_store(tmp_path)
    [row] = store.labels()
    assert row["label"] == "casa" and row["total"] == 2 and row["high"] == 1
    assert store.latest("casa", before=scans[1].started_at.isoformat()).scan_id == scans[0].scan_id


def test_dashboard_routes(tmp_path):
    store, scans = _saved_store(tmp_path)
    client = TestClient(create_app(store))
    home = client.get("/")
    assert home.status_code == 200 and "casa" in home.text and "data-get" in home.text
    assert not re.search(r'<(script|link)[^>]+(src|href)="https?://', home.text)  # nada externo: funciona offline
    assert client.get("/static/tbm.css").status_code == 200 and client.get("/static/tbm.js").status_code == 200
    inv = client.get("/inventory/casa")
    assert inv.status_code == 200 and "10.0.0.3" in inv.text and "Dispositivos" in inv.text
    assert client.get("/inventory/naoexiste").status_code == 404
    panel = client.get("/partials/label/casa")
    assert "<svg" in panel.text and scans[1].scan_id in panel.text
    diff = client.get(f"/partials/diff/{scans[1].scan_id}")
    assert "10.0.0.3" in diff.text  # host novo no segundo scan
    assert client.get(f"/scan/{scans[0].scan_id}").status_code == 200
    assert client.get("/scan/naoexiste").status_code == 404
    assert len(client.get("/api/scans").json()) == 2


def test_dashboard_empty(tmp_path):
    client = TestClient(create_app(HistoryStore(tmp_path / "vazio.db")))
    assert "Nenhum scan" in client.get("/").text


def test_parse_interval():
    assert parse_interval("30m") == 1800 and parse_interval("6h") == 21600 and parse_interval("1d") == 86400
    for bad in ("10s", "abc", "5x"):
        with pytest.raises(ValueError):
            parse_interval(bad)
