"""Fase 4: redes grandes. Tudo com a rede simulada: nenhum pacote sai da máquina."""

from __future__ import annotations

import asyncio
import errno
import ipaddress
import threading
import time

import pytest

from tbm.asyncutil import AdaptiveSemaphore
from tbm.models import Host, ScanResult, Service
from tbm.scope import Target
from tbm.scout import Scout, ScoutOptions, portscan
from tbm.scout import engine as scout_engine
from tbm.scout.checkpoint import Checkpoint, checkpoint_path


def targets(cidr: str) -> list[Target]:
    return [Target(address=str(ip)) for ip in ipaddress.ip_network(cidr).hosts()]


@pytest.fixture
def fake_net(monkeypatch):
    """Rede falsa: vivos = .1 e .50 de alguns /24; um aparelho só responde a ping."""
    calls: dict[str, list] = {"ping": [], "tcp": [], "scan": [], "local": []}
    tcp_alive = {"10.20.0.1", "10.20.0.50", "10.20.3.1"}
    ping_only = {"10.20.0.77"}

    async def is_alive(host, timeout, sem, limiter=None, ports=portscan.DISCOVERY_PORTS):
        calls["tcp"].append(ports)
        await asyncio.sleep(0.001)
        return host in tcp_alive

    async def ping_sweep(addresses, timeout=1.0, concurrency=64):
        calls["ping"].append(list(addresses))
        return {a for a in addresses if a in ping_only}

    async def nothing(*a, **k):
        return {}

    async def no_gw():
        return "10.20.0.1"

    async def scan_host(self, target, sem):
        calls["scan"].append(target.address)
        return Host(address=target.address, services=[Service(port=80)])

    monkeypatch.setattr(scout_engine, "is_alive", is_alive)
    monkeypatch.setattr(scout_engine, "ping_sweep", ping_sweep)
    monkeypatch.setattr(scout_engine, "multicast_discover", nothing)
    monkeypatch.setattr(scout_engine, "read_arp_table", nothing)
    monkeypatch.setattr(scout_engine, "default_gateway", no_gw)
    monkeypatch.setattr(scout_engine.Scout, "_scan_host", scan_host)
    monkeypatch.setattr(scout_engine, "enrich_model", lambda hosts: asyncio.sleep(0))
    from tbm.scout import discovery

    monkeypatch.setattr(discovery, "local_networks", lambda: calls["local"])
    calls["local"] = []
    return calls


def opts(**kw) -> ScoutOptions:
    return ScoutOptions(ports=[80], banners=False, ipv6=False, **kw)


def test_small_network_keeps_thorough_discovery(fake_net):
    scout = Scout(opts())
    hosts = asyncio.run(scout.run(targets("10.20.0.0/24")))
    assert scout.mode == "thorough"
    assert len(fake_net["ping"]) == 1 and len(fake_net["ping"][0]) == 254  # ping em todos, como sempre
    assert fake_net["tcp"][0] == portscan.DISCOVERY_PORTS
    assert {h.address for h in hosts} == {"10.20.0.1", "10.20.0.50", "10.20.0.77"}
    assert set(scout.timings) == {"discovery", "ports", "identify"}


def test_large_network_uses_fast_discovery(fake_net):
    scout = Scout(opts())
    hosts = asyncio.run(scout.run(targets("10.20.0.0/21")))  # 2046 endereços > /22
    assert scout.mode == "fast"
    assert fake_net["tcp"][0] == portscan.FAST_DISCOVERY_PORTS
    # ping só nos blocos /24 em que algo respondeu (10.20.0.x e 10.20.3.x), sem os já achados
    [pinged] = fake_net["ping"]
    assert {a.rsplit(".", 1)[0] for a in pinged} == {"10.20.0", "10.20.3"}
    in_blocks = [t.address for t in targets("10.20.0.0/21") if t.address.startswith(("10.20.0.", "10.20.3."))]
    assert len(pinged) == len(in_blocks) - 3  # menos os três que já responderam ao TCP
    # o aparelho que só responde a ping foi achado mesmo assim
    assert {h.address for h in hosts} == {"10.20.0.1", "10.20.0.50", "10.20.0.77", "10.20.3.1"}


def test_fast_mode_skips_ping_on_local_segment_and_caps_it(fake_net, monkeypatch):
    # bloco local: o ARP já cobre quem está vivo, então não precisa de ping
    fake_net["local"] = ["10.20.0.0/24"]
    asyncio.run(Scout(opts()).run(targets("10.20.0.0/21")))
    [pinged] = fake_net["ping"]
    assert {a.rsplit(".", 1)[0] for a in pinged} == {"10.20.3"}
    # teto de pings, priorizando os blocos com mais respostas
    fake_net["ping"].clear(), fake_net["local"].clear()
    monkeypatch.setattr(scout_engine, "MAX_FAST_PINGS", 100)
    asyncio.run(Scout(opts()).run(targets("10.20.0.0/21")))
    [pinged] = fake_net["ping"]
    assert len(pinged) == 100 and all(a.startswith("10.20.0.") for a in pinged)  # 10.20.0 tem 2 respostas


def test_fast_mode_adapts_timeout_to_measured_rtt(fake_net, monkeypatch):
    async def quick(host, timeout, sem, limiter=None, ports=()):
        await asyncio.sleep(0.01)
        return int(host.rsplit(".", 1)[1]) % 10 == 0  # 25 aparelhos: amostras de RTT suficientes

    monkeypatch.setattr(scout_engine, "is_alive", quick)
    scout = Scout(opts(timeout=1.0, discovery_mode="fast"))
    asyncio.run(scout.run(targets("10.20.0.0/24")))
    assert 0.3 <= scout.timeout < 1.0  # caiu pelo RTT, sem passar do piso
    explicit = Scout(opts(timeout=1.0, discovery_mode="thorough"))
    asyncio.run(explicit.run(targets("10.20.0.0/24")))
    assert explicit.timeout == 1.0  # na descoberta completa o timeout pedido não muda


def test_checkpoint_resume_skips_finished_blocks(fake_net, tmp_path, monkeypatch):
    path = tmp_path / "ck.json"
    real_add = Checkpoint.add
    blocks_done = []

    def add_then_crash(self, addresses, hosts):
        real_add(self, addresses, hosts)
        blocks_done.append(addresses)
        if len(blocks_done) == 1:
            raise KeyboardInterrupt  # "Ctrl+C" depois do primeiro bloco /24

    monkeypatch.setattr(Checkpoint, "add", add_then_crash)
    with pytest.raises(KeyboardInterrupt):
        asyncio.run(Scout(opts(checkpoint=path)).run(targets("10.20.0.0/21")))
    first = set(fake_net["scan"])
    assert path.exists() and first == {"10.20.0.1", "10.20.0.50", "10.20.0.77"}

    fake_net["scan"].clear(), fake_net["ping"].clear()
    scout = Scout(opts(checkpoint=path, resume=True))
    hosts = asyncio.run(scout.run(targets("10.20.0.0/21")))
    assert fake_net["ping"] == []  # a descoberta veio do checkpoint
    assert set(fake_net["scan"]) == {"10.20.3.1"}  # só o que faltava
    assert {h.address for h in hosts} == first | {"10.20.3.1"}
    assert not path.exists()  # terminou: checkpoint apagado


def test_checkpoint_ignored_when_targets_change(fake_net, tmp_path):
    path = tmp_path / "ck.json"
    ck, _ = Checkpoint.open(path, "outra-chave", resume=False)
    ck.save_discovery(["10.20.0.1"], {}, None, {}, 1.0)
    scout = Scout(opts(checkpoint=path, resume=True))
    asyncio.run(scout.run(targets("10.20.0.0/24")))
    assert fake_net["ping"]  # refez a descoberta


def test_checkpoint_file_is_private(tmp_path, monkeypatch):
    import os
    import stat
    import sys

    monkeypatch.setenv("TBM_HOME", str(tmp_path))
    p = checkpoint_path("casa/../x")
    assert p.parent == tmp_path / "checkpoints" and ".." not in p.name
    ck, _ = Checkpoint.open(p, "k", resume=False)
    ck.add(["10.0.0.1"], [Host(address="10.0.0.1")])
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


# ───────────────────────────── concorrência adaptativa ─────────────────────────────


def test_adaptive_semaphore_halves_on_error_burst():
    async def go():
        sem = AdaptiveSemaphore(400, floor=16, burst=5)
        for _ in range(5):
            sem.report_error()
        await asyncio.sleep(0)
        assert sem.limit == 200 and sem.shrinks == 1
        for _ in range(100):  # muitos surtos: nunca abaixo do piso
            for _ in range(5):
                sem.report_error()
        await asyncio.sleep(0.01)
        assert sem.limit == 16
        sem.close()

    asyncio.run(go())


def test_resource_errors_are_not_filtered_ports(monkeypatch):
    calls = []

    async def exhausted(host, port):
        calls.append(port)
        err = OSError(errno.ENOBUFS, "No buffer space available")
        raise err

    monkeypatch.setattr(portscan.asyncio, "open_connection", exhausted)

    async def go():
        sem = AdaptiveSemaphore(10, floor=2, burst=2)
        state = await portscan.guarded_probe(sem, "192.168.0.9", 80, 0.5)
        return state, sem

    state, sem = asyncio.run(go())
    assert state is portscan.PortState.FILTERED and len(calls) == 2  # tentou de novo antes de desistir
    assert sem.limit == 5  # e o paralelismo caiu


# ───────────────────────────── interface: cancelar e ETA ─────────────────────────────


def test_job_can_be_cancelled(tmp_path):
    from tbm.dashboard.jobs import JobRunner, ScanParams
    from tbm.squeak import HistoryStore

    started = threading.Event()

    async def slow(spec, store, progress):
        started.set()
        await asyncio.sleep(30)

    runner = JobRunner(HistoryStore(tmp_path / "h.db"), executor=slow)
    job = runner.submit(ScanParams(targets="192.168.0.10"))
    assert started.wait(5)
    t0 = time.monotonic()
    assert runner.cancel(job.id)
    while job.status == "running" and time.monotonic() - t0 < 5:
        time.sleep(0.02)
    assert job.status == "cancelled" and time.monotonic() - t0 < 2
    assert not runner.cancel(job.id)  # já terminou
    runner.submit(ScanParams(targets="192.168.0.10"))  # e libera para o próximo


def test_job_eta():
    from datetime import timedelta

    from tbm.dashboard.jobs import Job, ScanParams
    from tbm.models import utcnow

    job = Job(id="x", params=ScanParams(targets="192.168.0.1"), status="running")
    job.started = utcnow() - timedelta(seconds=60)
    job.phases = {"a": [25, 100]}
    assert 170 <= job.eta() <= 190  # 25% em 60 s → ~180 s
    job.phases = {"a": [1, 100]}
    assert job.eta() is None  # cedo demais para estimar


def test_timings_reach_the_result():
    from tbm.pipeline import run_sniffer
    from tbm.sniffer import SnifferOptions

    result = asyncio.run(run_sniffer(ScanResult(), SnifferOptions(cve=False, disabled={"network", "upnp"})))
    assert "checks" in result.timings
