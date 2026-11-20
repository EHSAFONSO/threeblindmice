"""Testes do plugin de exemplo: rode com `pytest` dentro de examples/tbm-plugin-exemplo."""

import asyncio
from urllib.parse import urlparse

import httpx
from tbm_plugin_exemplo import AlertaEmArquivo, MarcaImpressoras, TelnetEscondido

from tbm.plugin import CheckContext, Host, ScanResult, Service, SnifferOptions


def test_check_finds_telnet_on_2323():
    cam = Host(address="192.168.0.50", services=[Service(port=80), Service(port=2323)])
    ctx = CheckContext(scan=ScanResult(hosts=[cam]), http=httpx.AsyncClient(), options=SnifferOptions())
    [f] = asyncio.run(TelnetEscondido().run(ctx))
    assert f.host == "192.168.0.50" and f.port == 2323


def test_file_destination(tmp_path):
    target = f"arquivo:///{(tmp_path / 'alertas.log').as_posix()}"
    n = AlertaEmArquivo()
    assert n.matches(urlparse(target)) and n.describe(urlparse(target)) == "Arquivo · alertas.log"
    asyncio.run(n.send(target, "oi"))
    assert "oi" in (tmp_path / "alertas.log").read_text(encoding="utf-8")


def test_enricher_marks_printers():
    hosts = [Host(address="192.168.0.30", services=[Service(port=9100)]), Host(address="192.168.0.31")]
    asyncio.run(MarcaImpressoras().enrich(hosts, None))
    assert hosts[0].device_type == "impressora" and hosts[1].device_type is None
