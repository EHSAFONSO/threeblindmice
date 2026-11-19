"""Interface em inglês: todo texto marcado com _() tem tradução, e os marcadores batem."""

import ast
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from tbm import i18n
from tbm.dashboard import create_app
from tbm.dashboard.jobs import JobRunner
from tbm.dashboard.security import GuiSettings
from tbm.locale_en import EN
from tbm.squeak import HistoryStore
from tbm.squeak.actions import KINDS

SRC = Path(__file__).resolve().parent.parent / "src" / "tbm"
TEMPLATES = SRC / "dashboard" / "templates"
JINJA_CALL = re.compile(r'''_\(\s*"((?:[^"\\]|\\.)*)"|_\(\s*'((?:[^'\\]|\\.)*)\'''')


def template_keys() -> set[str]:
    keys = set()
    for f in TEMPLATES.glob("*.j2"):
        for m in JINJA_CALL.finditer(f.read_text(encoding="utf-8")):
            raw = m.group(1) if m.group(1) is not None else m.group(2)
            keys.add(raw.replace('\\"', '"').replace("\\'", "'"))
    return keys


def python_keys() -> set[str]:
    """_("...") literais no código Python da interface."""
    keys = set()
    for f in (SRC / "dashboard").glob("*.py"):
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_"
                    and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                keys.add(node.args[0].value)
    return keys


def all_keys() -> set[str]:
    kinds = {s for k in KINDS.values() for s in (k.title, k.why)}
    return template_keys() | python_keys() | kinds | set(i18n.EXTRA_KEYS) | set(i18n.js_catalog())


def test_every_marked_string_is_translated():
    missing = sorted(all_keys() - set(EN))
    assert not missing, "sem tradução em tbm/locale_en.py:\n" + "\n".join(missing)


def test_placeholders_match():
    for pt, en in EN.items():
        assert set(re.findall(r"\{(\w+)\}", pt)) == set(re.findall(r"\{(\w+)\}", en)), pt


def test_catalog_has_no_stale_entries():
    stale = sorted(set(EN) - all_keys())
    assert not stale, "traduções que ninguém usa mais:\n" + "\n".join(stale)


def test_language_choice():
    assert i18n.from_accept_language("en-US,en;q=0.9,pt;q=0.8") == "en"
    assert i18n.from_accept_language("pt-BR,pt;q=0.9") == "pt"
    assert i18n.from_accept_language("de-DE,fr") == "pt"
    with i18n.use("en"):
        assert i18n.gettext("{n} porta(s)", n=3) == "3 port(s)"
    assert i18n.gettext("{n} porta(s)", n=3) == "3 porta(s)"


@pytest.fixture
def gui(tmp_path, monkeypatch):
    from tests.test_visual import home_scan

    store = HistoryStore(tmp_path / "h.db")
    store.save(home_scan())
    settings = GuiSettings(port=8770, extra_hosts={"testserver"})
    client = TestClient(create_app(store, gui=settings, runner=JobRunner(store)))
    client.get(f"/?token={settings.token}")
    monkeypatch.setattr("tbm.schedule.status", lambda platform, label: {
        "installed": True, "supported": True, "next": None, "last": None, "result": None, "state": "Ready"})
    return SimpleNamespace(client=client, store=store)


def test_pages_in_english(gui):
    gui.client.cookies.set("tbm-lang", "en")
    home = gui.client.get("/").text
    assert '<html lang="en">' in home and "Network health" in home and "What to do now" in home
    assert "Update the firmware or software of" in home and "Saúde da rede" not in home
    findings = gui.client.get("/findings/casa").text
    assert "What to fix" in findings and "fixes 3 finding(s)" in findings
    assert "New scan" in gui.client.get("/scan").text and "Network map" in gui.client.get("/map/casa").text
    assert "Devices" in gui.client.get("/inventory/casa").text


def test_browser_language_and_switch(gui):
    page = gui.client.get("/", headers={"Accept-Language": "en-US,en"}).text
    assert "Network health" in page
    r = gui.client.get("/lang/pt", headers={"Referer": "http://127.0.0.1:8770/map/casa"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/map/casa"
    assert "tbm-lang=pt" in r.headers["set-cookie"]
    # o Referer nunca leva para outro site
    r = gui.client.get("/lang/en", headers={"Referer": "https://evil.example//x"}, follow_redirects=False)
    assert r.headers["location"].startswith("/") and not r.headers["location"].startswith("//")


def test_every_device_type_is_translated():
    """Tipo novo no classificador precisa entrar em i18n.DEVICE_TYPES (e no catálogo)."""
    text = (SRC / "scout" / "classify.py").read_text(encoding="utf-8")
    types = set(re.findall(r'^\s*\("([^"]+)",\s*\d+,', text, re.M)) | set(re.findall(r'return "([^"]+)"', text))
    assert types and types <= set(i18n.DEVICE_TYPES), sorted(types - set(i18n.DEVICE_TYPES))
