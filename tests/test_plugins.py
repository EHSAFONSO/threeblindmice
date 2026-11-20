"""Fase 3: plugins por entry points, só com autorização.

O plugin de exemplo (examples/tbm-plugin-exemplo) é "instalado" num diretório temporário
com um dist-info montado a partir do próprio pyproject.toml dele: o importlib.metadata
enxerga igual a um pip install, sem tocar no venv.
"""

from __future__ import annotations

import asyncio
import sys
import tomllib
from pathlib import Path

import pytest

from tbm import plugins
from tbm.models import Host, ScanResult, Service
from tbm.scout.extend import ENRICHERS
from tbm.sniffer.base import REGISTRY, SnifferOptions
from tbm.squeak.actions import CLASSIFIERS, KINDS, build_actions
from tbm.squeak.notifiers import NOTIFIERS, notifier_for

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "tbm-plugin-exemplo"


def fake_dist(root: Path, name: str, version: str, groups: dict[str, dict[str, str]]) -> None:
    info = root / f"{name.replace('-', '_')}-{version}.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8")
    lines = []
    for group, eps in groups.items():
        lines.append(f"[{group}]")
        lines += [f"{k} = {v}" for k, v in eps.items()]
    (info / "entry_points.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.fixture
def installed(tmp_path, monkeypatch):
    """Exemplo + um plugin quebrado "instalados"; tudo que eles registram é desfeito no fim."""
    monkeypatch.setenv("TBM_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("TBM_NO_PLUGINS", raising=False)
    meta = tomllib.loads((EXAMPLE / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    site = tmp_path / "site"
    fake_dist(site, meta["name"], meta["version"], meta["entry-points"])
    (site / "tbm_plugin_quebrado.py").write_text("raise RuntimeError('quebrei no import')\n", encoding="utf-8")
    fake_dist(site, "tbm-plugin-quebrado", "0.0.1", {"tbm.checks": {"ruim": "tbm_plugin_quebrado"}})
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.syspath_prepend(str(EXAMPLE / "src"))
    snapshot = (dict(REGISTRY), list(NOTIFIERS), dict(ENRICHERS), dict(KINDS), list(CLASSIFIERS))
    from tbm.locale_en import EN

    en_before = dict(EN)
    monkeypatch.setattr(plugins, "_loaded", False)
    yield
    REGISTRY.clear(), REGISTRY.update(snapshot[0])
    NOTIFIERS[:] = snapshot[1]
    ENRICHERS.clear(), ENRICHERS.update(snapshot[2])
    KINDS.clear(), KINDS.update(snapshot[3])
    CLASSIFIERS[:] = snapshot[4]
    EN.clear(), EN.update(en_before)
    plugins.ORIGINS.clear()
    plugins.LOAD_ERRORS.clear()
    for mod in ("tbm_plugin_exemplo", "tbm_plugin_quebrado"):
        sys.modules.pop(mod, None)


def test_installed_but_not_enabled_does_nothing(installed):
    entries = plugins.available()
    assert {e.name for e in entries if e.package == "tbm-plugin-exemplo"} == {"telnet-2323", "arquivo", "impressora"}
    assert not any(e.enabled for e in entries)
    assert plugins.load_plugins(force=True) == []
    assert "exemplo.telnet-2323" not in REGISTRY
    assert "tbm_plugin_exemplo" not in sys.modules  # nem foi importado
    assert notifier_for("arquivo:///x.log")[0].kind == "webhook"


def test_enabled_plugin_registers_everything(installed, tmp_path):
    plugins.set_enabled("tbm-plugin-exemplo", True)
    assert plugins.load_plugins(force=True) == []
    assert "exemplo.telnet-2323" in REGISTRY and "exemplo.impressora" in ENRICHERS
    assert plugins.ORIGINS["exemplo.telnet-2323"] == "tbm-plugin-exemplo 0.1.0"
    assert notifier_for("arquivo:///x.log")[0].kind == "arquivo"
    from tbm import config

    assert config.describe(f"arquivo:///{tmp_path.as_posix()}/a.log")["label"] == "Arquivo · a.log"
    # o check roda no Sniffer de verdade e o achado vira a ação do tipo registrado pelo plugin
    from tbm.sniffer import Sniffer

    cam = Host(address="192.168.0.50", mac="aa:bb:cc:dd:ee:ff", services=[Service(port=2323)])
    scan = ScanResult(hosts=[cam])
    findings, errors = asyncio.run(Sniffer(SnifferOptions(cve=False)).run(scan))
    mine = [f for f in findings if f.check_id == "exemplo.telnet-2323"]
    assert mine and not [e for e in errors if e.startswith("exemplo")]
    scan.findings = mine
    assert [a.kind for a in build_actions(scan)] == ["telnet-2323"]
    # e aparece com a origem na página Funcionalidades
    from tbm.dashboard.features import catalog

    row = next(r for r in catalog() if r["id"] == "exemplo.telnet-2323")
    assert row["origin"] == "tbm-plugin-exemplo 0.1.0" and row["what"].startswith("Procura")
    plugins.set_enabled("tbm-plugin-exemplo", False)
    assert plugins.enabled_packages() == []


def test_broken_plugin_is_isolated(installed):
    plugins.set_enabled("tbm-plugin-quebrado", True)
    plugins.set_enabled("tbm-plugin-exemplo", True)
    errors = plugins.load_plugins(force=True)
    assert len(errors) == 1 and "quebrado" in errors[0] and "quebrei no import" in errors[0]
    assert "exemplo.telnet-2323" in REGISTRY  # o outro carregou normalmente


def test_wrong_api_version_is_refused(installed, monkeypatch):
    plugins.set_enabled("tbm-plugin-exemplo", True)
    import tbm_plugin_exemplo

    monkeypatch.setattr(tbm_plugin_exemplo.TelnetEscondido, "TBM_API", 99)
    errors = plugins.load_plugins(force=True)
    assert any("API 99" in e for e in errors)
    assert "exemplo.telnet-2323" not in REGISTRY


def test_enricher_errors_and_host_changes_dont_break_scout(installed):
    from tbm.scout import Scout, ScoutOptions
    from tbm.scout.extend import Enricher, register_enricher

    @register_enricher
    class Quebra(Enricher):
        id, name = "teste.quebra", "quebra"

        async def enrich(self, hosts, options):
            raise ValueError("ops")

    @register_enricher
    class Intruso(Enricher):
        id, name = "teste.intruso", "intruso"

        async def enrich(self, hosts, options):
            hosts.append(Host(address="8.8.8.8"))  # fora do escopo: precisa ser desfeito

    scout = Scout(ScoutOptions(ports=[80]))
    hosts = [Host(address="192.168.0.9")]
    asyncio.run(scout._run_enrichers(hosts))
    assert [h.address for h in hosts] == ["192.168.0.9"]
    assert any("teste.quebra: ValueError" in e for e in scout.errors)
    assert any("teste.intruso" in e and "ignorado" in e for e in scout.errors)


def test_plugin_cli(installed):
    from typer.testing import CliRunner

    from tbm.cli import app

    out = CliRunner().invoke(app, ["plugins", "list"]).output
    assert "tbm-plugin-exemplo" in out and "não" in out
    res = CliRunner().invoke(app, ["plugins", "enable", "tbm-plugin-exemplo", "--yes"])
    assert res.exit_code == 0 and "autorizado" in res.output
    assert plugins.enabled_packages() == ["tbm-plugin-exemplo"]
    assert CliRunner().invoke(app, ["plugins", "enable", "nao-existe", "--yes"]).exit_code != 0
    assert CliRunner().invoke(app, ["plugins", "disable", "tbm-plugin-exemplo"]).exit_code == 0
    assert plugins.enabled_packages() == []
