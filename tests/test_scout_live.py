"""Scout contra servidores falsos em 127.0.0.1: sem rede externa."""

import asyncio
import socket

import pytest

from tbm.scope import Target
from tbm.scout import Scout, ScoutOptions
from tbm.sniffer.service_checks import ftp_allows_anonymous


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def fake_ssh():
    async def handler(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    yield server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()


async def test_scout_finds_open_port_and_banner(fake_ssh):
    closed = _free_port()
    opts = ScoutOptions(ports=[fake_ssh, closed], timeout=0.5, discovery=False,
                        legacy_tls=False, reverse_dns=False)
    hosts = await Scout(opts).run([Target("127.0.0.1")])
    assert len(hosts) == 1
    svc = hosts[0].services
    assert [s.port for s in svc] == [fake_ssh]
    assert svc[0].name == "ssh"
    assert svc[0].product == "OpenSSH"
    assert svc[0].version == "8.2p1"


@pytest.fixture
async def fake_ftp():
    async def handler(reader, writer):
        writer.write(b"220-Bem-vindo\r\n220 FTP pronto\r\n")
        await writer.drain()
        while line := await reader.readline():
            cmd = line.decode().strip().upper()
            if cmd.startswith("USER"):
                writer.write(b"331 Please specify the password.\r\n")
            elif cmd.startswith("PASS"):
                writer.write(b"230 Login successful.\r\n")
            elif cmd.startswith("QUIT"):
                writer.write(b"221 Goodbye.\r\n")
                await writer.drain()
                break
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    yield server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()


async def test_ftp_anonymous_detection(fake_ftp):
    assert await ftp_allows_anonymous("127.0.0.1", fake_ftp, timeout=2) is True


async def test_ftp_check_retries_after_silent_connection(monkeypatch):
    """1ª conexão: servidor calado (timeout). 2ª: responde normal. O check deve achar."""
    import tbm.sniffer.service_checks as sc
    from tbm.models import Host, ScanResult, Service
    from tbm.sniffer.base import CheckContext, SnifferOptions

    calls = 0

    async def flaky(host, port, timeout=5.0):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TimeoutError
        return True

    monkeypatch.setattr(sc, "ftp_allows_anonymous", flaky)
    scan = ScanResult(hosts=[Host(address="10.0.0.2", services=[Service(port=21, name="ftp")])])
    ctx = CheckContext(scan=scan, http=None, options=SnifferOptions(active=True))  # type: ignore[arg-type]
    [finding] = await sc.AnonymousFTPCheck().run(ctx)
    assert finding.title == "FTP aceita login anônimo" and calls == 2
