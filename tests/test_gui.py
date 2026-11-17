"""Interface gráfica: segurança (token, Host, Origin), scan com progresso, aceitação e catálogo."""

import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from tbm.dashboard import create_app
from tbm.dashboard.features import CHECKS, catalog
from tbm.dashboard.jobs import JobRunner
from tbm.dashboard.security import GuiSettings
from tbm.models import Finding, Host, ScanResult, Service, Severity
from tbm.pipeline import finalize
from tbm.sniffer import REGISTRY
from tbm.squeak import HistoryStore, diff_scans
from tbm.squeak.acceptance import apply_acceptances

ORIGIN = {"Origin": "http://testserver"}


def fake_executor(delay: float = 0.0):
    async def run(spec, store, progress):
        progress.start("Scout · varredura de portas", 4)
        for _ in range(4):
            await asyncio.sleep(delay / 4)
            progress.advance("Scout · varredura de portas")
        progress.log("2/254 hosts encontrados")
        result = finalize(ScanResult(
            label=spec.label, targets=spec.specs,
            hosts=[Host(address="192.168.0.1", mac="aa:bb:cc:00:00:01", device_type="roteador/modem",
                        services=[Service(port=23, name="telnet")])],
            findings=[Finding(check_id="service.exposed", title="Telnet exposto", severity=Severity.HIGH,
                              host="192.168.0.1", port=23, device="mac:aa:bb:cc:00:00:01")],
        ))
        if apply_acceptances(result, store.acceptances()):  # como o pipeline.execute real
            finalize(result)
        diff = diff_scans(store.latest(spec.label), result)
        store.save(result)
        return result, diff
    return run


@pytest.fixture
def gui(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    settings = GuiSettings(port=8770, extra_hosts={"testserver"})
    runner = JobRunner(store, executor=fake_executor())
    client = TestClient(create_app(store, gui=settings, runner=runner))
    return client, settings, store, runner


def login(client, settings):
    r = client.get(f"/?token={settings.token}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert "httponly" in r.headers["set-cookie"].lower() and "samesite=strict" in r.headers["set-cookie"].lower()


def post(client, settings, url, json):
    return client.post(url, json=json, headers={**ORIGIN, "X-TBM-Token": settings.token})


def wait_job(client, job_id, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] in ("done", "error"):
            return job
        time.sleep(0.05)
    raise AssertionError("job não terminou")


# ───────────────────────────── segurança ─────────────────────────────


def test_requires_session_token(gui):
    client, settings, *_ = gui
    assert client.get("/").status_code == 401
    assert client.get("/?token=errado").status_code == 401
    login(client, settings)
    page = client.get("/")
    assert page.status_code == 200 and f'content="{settings.token}"' in page.text


def test_rejects_foreign_host_dns_rebinding(gui):
    client, settings, *_ = gui
    login(client, settings)
    assert client.get("/", headers={"Host": "evil.example:8770"}).status_code == 400


def test_actions_need_header_and_origin(gui):
    client, settings, *_ = gui
    login(client, settings)
    body = {"targets": "192.168.0.0/30", "label": "casa"}
    # cookie sozinho não basta (é o que um site malicioso conseguiria via CSRF)
    assert client.post("/api/scan", json=body, headers=ORIGIN).status_code == 403
    assert client.post("/api/scan", json=body,
                       headers={"Origin": "https://evil.example", "X-TBM-Token": settings.token}).status_code == 403
    assert post(client, settings, "/api/scan", body).status_code == 202


def test_readonly_dashboard_has_no_actions(tmp_path):
    client = TestClient(create_app(HistoryStore(tmp_path / "h.db")))
    assert client.get("/").status_code == 200  # sem token, como antes
    assert client.post("/api/scan", json={}).status_code in (404, 405)
    assert client.get("/scan").status_code in (404, 405)


# ───────────────────────────── scan ─────────────────────────────


def test_scan_runs_with_progress_and_summary(gui):
    client, settings, store, _ = gui
    login(client, settings)
    form = client.get("/scan")
    assert form.status_code == 200 and "Iniciar scan" in form.text
    job_id = post(client, settings, "/api/scan", {"targets": "192.168.0.0/30", "label": "casa"}).json()["job"]
    job = wait_job(client, job_id)
    assert job["status"] == "done", job
    assert job["phases"][0] == {"name": "Scout · varredura de portas", "done": 4, "total": 4}
    s = job["summary"]
    assert s["grade"] and s["counts"]["high"] == 1 and s["previous"] is None
    assert store.latest("casa").scan_id == s["scan_id"]


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({"targets": "8.8.8.8", "label": "casa"}, "fora do escopo"),
        ({"targets": "192.168.0.1", "label": "casa ruim!"}, "letras"),
        ({"targets": "192.168.0.1", "label": "casa", "ports": "0"}, "porta"),
        ({"targets": "  ", "label": "casa"}, "alvo"),
    ],
)
def test_scan_validation(gui, body, message):
    client, settings, *_ = gui
    login(client, settings)
    r = post(client, settings, "/api/scan", body)
    assert r.status_code == 400 and message in r.json()["error"]


def test_one_scan_at_a_time(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    settings = GuiSettings(port=8770, extra_hosts={"testserver"})
    client = TestClient(create_app(store, gui=settings, runner=JobRunner(store, executor=fake_executor(0.6))))
    login(client, settings)
    first = post(client, settings, "/api/scan", {"targets": "192.168.0.1", "label": "casa"})
    second = post(client, settings, "/api/scan", {"targets": "192.168.0.1", "label": "casa"})
    assert first.status_code == 202 and second.status_code == 409
    # Reabrir a página durante o scan volta a acompanhar o mesmo job
    assert f'watch("{first.json()["job"]}")' in client.get("/scan").text
    wait_job(client, first.json()["job"])


# ───────────────────────────── achados e aceitação ─────────────────────────────


def test_findings_accept_and_undo(gui):
    client, settings, store, _ = gui
    login(client, settings)
    wait_job(client, post(client, settings, "/api/scan", {"targets": "192.168.0.1", "label": "casa"}).json()["job"])
    fp = store.latest("casa").findings[0].fingerprint

    page = client.get("/findings/casa")
    assert page.status_code == 200 and "Telnet exposto" in page.text and "Aceitar risco" in page.text
    assert client.get("/findings", follow_redirects=False).headers["location"] == "/findings/casa"

    past = post(client, settings, "/api/accept",
                {"fingerprint": fp, "label": "casa", "reason": "x", "until": "2001-01-01"})
    assert past.status_code == 400 and "futura" in past.json()["error"]
    empty = post(client, settings, "/api/accept", {"fingerprint": fp, "label": "casa", "reason": " "})
    assert empty.status_code == 400

    ok = post(client, settings, "/api/accept", {"fingerprint": fp, "label": "casa", "reason": "ONT da operadora",
                                                 "until": "2099-01-01"})
    assert ok.status_code == 200 and fp in store.acceptances()
    assert "Desfazer aceitação" in client.get("/findings/casa").text  # já marcado antes do próximo scan

    # o próximo scan aplica a aceitação e a nota sobe
    rescan = post(client, settings, "/api/scan", {"targets": "192.168.0.1", "label": "casa"})
    job = wait_job(client, rescan.json()["job"])
    assert job["summary"]["accepted"] == 1 and job["summary"]["score"] == 100

    assert post(client, settings, "/api/unaccept", {"fingerprint": fp}).json()["removed"] == 1
    assert post(client, settings, "/api/unaccept", {"fingerprint": "curto"}).status_code == 400


def test_accept_unknown_finding(gui):
    client, settings, *_ = gui
    login(client, settings)
    r = post(client, settings, "/api/accept", {"fingerprint": "0" * 16, "label": "nada", "reason": "x"})
    assert r.status_code == 404


# ───────────────────────────── catálogo ─────────────────────────────


def test_every_check_is_explained():
    assert set(REGISTRY) == set(CHECKS), "check novo sem explicação na página de funcionalidades"
    assert all(row["what"] and row["why"] for row in catalog())


def test_features_and_welcome_pages(gui):
    client, settings, *_ = gui
    login(client, settings)
    assert "Fazer o primeiro scan" in client.get("/").text  # histórico vazio
    page = client.get("/features")
    assert page.status_code == 200
    assert all(cid in page.text for cid in REGISTRY)
    assert "tbm telegram-setup" in page.text
