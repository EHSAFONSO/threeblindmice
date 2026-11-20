"""Benchmarks reprodutíveis (fora do CI padrão): TBM_PERF=1 pytest -m perf tests/perf -s

- histórico sintético grande: tempo das páginas que antes abriam dezenas de scans inteiros;
- /16 simulada: tempo e memória da descoberta, sem nenhum pacote de rede de verdade.

Tamanhos ajustáveis por TBM_PERF_SCANS e TBM_PERF_HOSTS (padrão: 1.000 scans × 500 aparelhos).
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import random
import time
import tracemalloc
from datetime import UTC, datetime, timedelta

import pytest

from tbm.models import Finding, Host, ScanResult, Service, Severity
from tbm.squeak import HistoryStore

pytestmark = [
    pytest.mark.perf,
    pytest.mark.skipif(not os.environ.get("TBM_PERF"), reason="benchmarks só com TBM_PERF=1"),
]

PAGE_BUDGET_MS = 300


@pytest.fixture(scope="module")
def big_history(tmp_path_factory):
    n_scans = int(os.environ.get("TBM_PERF_SCANS", 1000))
    n_hosts = int(os.environ.get("TBM_PERF_HOSTS", 500))
    store = HistoryStore(tmp_path_factory.mktemp("perf") / "h.db")
    base = datetime(2026, 1, 1, tzinfo=UTC)
    for i in range(n_scans):
        hosts = [Host(address=f"10.0.{h // 250}.{h % 250 + 1}", mac=f"aa:bb:cc:00:{h // 256:02x}:{h % 256:02x}",
                      device_type="computador", services=[Service(port=p) for p in (22, 80, 443)][: h % 4])
                 for h in range(n_hosts)]
        findings = [Finding(check_id="http.admin", title="Painel", severity=Severity.MEDIUM, host=h.address,
                            device=h.identity, port=80, evidence="e" * 300) for h in hosts[: n_hosts // 5]]
        store.save(ScanResult(label="casa", started_at=base + timedelta(hours=i), hosts=hosts,
                              findings=findings, score=70, grade="C"))
    return store


@pytest.mark.parametrize("url", ["/", "/partials/label/casa", "/inventory/casa", "/map/casa",
                                 "/device/casa/10.0.0.5"])
def test_pages_within_budget(big_history, url):
    from fastapi.testclient import TestClient

    from tbm.dashboard.app import create_app

    client = TestClient(create_app(big_history))
    assert client.get(url).status_code == 200  # aquece caches e templates
    best = min(_timed(lambda: client.get(url)) for _ in range(3))
    print(f"\n{url}: {best:.0f} ms")
    assert best < PAGE_BUDGET_MS


def _timed(fn) -> float:
    t = time.perf_counter()
    fn()
    return (time.perf_counter() - t) * 1000


def test_discovery_of_a_slash16(monkeypatch):
    from tbm.scope import Target
    from tbm.scout import Scout, ScoutOptions, engine

    random.seed(1)
    net = ipaddress.ip_network("10.50.0.0/16")
    alive = {str(ip) for ip in net.hosts() if random.random() < 0.01}
    pings = []

    async def is_alive(host, timeout, sem, limiter=None, ports=()):
        async with sem:
            await asyncio.sleep(0)
        return host in alive

    async def ping_sweep(addresses, timeout=1.0, concurrency=64):
        pings.extend(addresses)
        return set()

    async def empty(*a, **k):
        return {}

    async def no_gateway():
        return None

    async def scan_host(self, target, sem):
        return Host(address=target.address, services=[Service(port=80)])

    for name, value in {"is_alive": is_alive, "ping_sweep": ping_sweep, "multicast_discover": empty,
                        "read_arp_table": empty, "default_gateway": no_gateway,
                        "enrich_model": lambda hosts: asyncio.sleep(0)}.items():
        monkeypatch.setattr(engine, name, value)
    monkeypatch.setattr(engine.Scout, "_scan_host", scan_host)

    targets = [Target(address=str(ip)) for ip in net.hosts()]
    tracemalloc.start()
    t = time.perf_counter()
    scout = Scout(ScoutOptions(ports=[80], banners=False, ipv6=False))
    hosts = asyncio.run(scout.run(targets))
    elapsed = time.perf_counter() - t
    peak = tracemalloc.get_traced_memory()[1] / 1e6
    tracemalloc.stop()
    print(f"\n/16: {len(hosts)} aparelhos em {elapsed:.1f}s, pico {peak:.0f} MB, {len(pings)} pings")
    assert scout.mode == "fast" and len(hosts) == len(alive)
    assert len(pings) <= engine.MAX_FAST_PINGS
    assert elapsed < 15 and peak < 150
