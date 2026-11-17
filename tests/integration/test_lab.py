"""Testes contra o laboratório do Docker Compose (integration/compose.yml).

Rodam só dentro do container scanner (TBM_INTEGRATION=1), onde os nomes
redis/ftp/web/ssh/snmp resolvem para IPs privados da rede do Compose.
"""

import os

import pytest
import pytest_asyncio

from tbm.pipeline import run_full_scan
from tbm.scope import Scope
from tbm.scout import ScoutOptions
from tbm.sniffer import SnifferOptions

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("TBM_INTEGRATION") != "1", reason="precisa do Docker Compose"),
]

SERVICES = ["redis", "ftp", "web", "ssh", "snmp"]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def lab_result():
    scope = Scope.default()
    targets = scope.resolve(SERVICES)
    return await run_full_scan(
        targets=targets,
        specs=SERVICES,
        scope_source=scope.source,
        label="lab",
        scout_options=ScoutOptions(ports=[21, 22, 80, 6379], udp=True, discovery=False,
                                   timeout=2.0, mac_lookup=False),
        sniffer_options=SnifferOptions(active=True, cve=False, scope=scope),
    )


def _titles(result) -> set[str]:
    return {f.title for f in result.findings}


@pytest.mark.asyncio(loop_scope="module")
async def test_redis_without_auth(lab_result):
    assert "Redis sem autenticação" in _titles(lab_result)


@pytest.mark.asyncio(loop_scope="module")
async def test_ftp_anonymous(lab_result):
    assert "FTP aceita login anônimo" in _titles(lab_result)


@pytest.mark.asyncio(loop_scope="module")
async def test_web_findings(lab_result):
    titles = _titles(lab_result)
    assert "Repositório .git exposto" in titles
    assert "Listagem de diretório habilitada" in titles
    assert any(t.startswith("Versão de software exposta") for t in titles)


@pytest.mark.asyncio(loop_scope="module")
async def test_ssh_findings(lab_result):
    titles = _titles(lab_result)
    assert "SSH aceita autenticação por senha" in titles
    assert "SSH aceita cifras fracas" in titles


@pytest.mark.asyncio(loop_scope="module")
async def test_snmp_public(lab_result):
    snmp = [f for f in lab_result.findings if f.check_id == "udp.services" and "SNMP" in f.title]
    assert snmp and "threeblindmice-lab-snmp" in snmp[0].evidence
