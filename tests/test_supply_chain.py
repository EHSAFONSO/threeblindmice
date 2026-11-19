"""Cadeia de suprimentos: nada entra no CI, no Docker ou no instalador sem versão exata e hash."""

import re
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
REQ = ROOT / "requirements"
LOCKS = sorted(REQ.glob("*.txt"))
WORKFLOWS = sorted((ROOT / ".github").rglob("*.yml"))
DOCKERFILES = [ROOT / "Dockerfile", *sorted((ROOT / "integration").rglob("Dockerfile*"))]


def requirements(lock: Path) -> list[tuple[str, str]]:
    """(linha do requisito, bloco com os hashes) de um lock do uv/pip-compile."""
    blocks = re.split(r"\n(?=[a-z0-9])", lock.read_text(encoding="utf-8"))
    return [(b.splitlines()[0], b) for b in blocks if re.match(r"[a-z0-9]", b)]


def test_locks_exist():
    assert {p.name for p in LOCKS} == {"bootstrap.txt", "dev.txt", "runtime.txt", "desktop.txt"}


@pytest.mark.parametrize("lock", LOCKS, ids=lambda p: p.name)
def test_every_locked_package_has_exact_version_and_hash(lock):
    reqs = requirements(lock)
    assert reqs
    for line, block in reqs:
        assert re.match(r"[a-z0-9][a-z0-9._-]*==[\w.]+( ;|\s*\\|$)", line), line
        assert "--hash=sha256:" in block, f"{line} sem hash"


def test_locks_cover_every_declared_dependency():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    declared = list(project["dependencies"])
    for extra in project["optional-dependencies"].values():
        declared += [d for d in extra if not d.startswith("threeblindmice")]
    locked = {line.split("==")[0] for line, _ in requirements(REQ / "desktop.txt")}
    for dep in declared:
        name = re.split(r"[<>=\[; ]", dep)[0].lower().replace("_", "-")
        assert name in locked, f"{name} está no pyproject.toml mas não no lock (rode python requirements/lock.py)"


def test_pip_policy_only_wheels_and_minimum_age():
    conf = (REQ / "pip.conf").read_text(encoding="utf-8")
    assert re.search(r"^only-binary = :all:$", conf, re.M)
    assert re.search(r"^uploaded-prior-to = P\d+D$", conf, re.M)
    days = int(re.search(r"P(\d+)D", conf).group(1))
    assert days >= 3
    # a única exceção a "só wheels" é explícita e única
    assert re.findall(r"^no-binary = (.+)$", conf, re.M) == ["proxy-tools"]
    uv = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["uv"]["pip"]
    assert uv["only-binary"] == [":all:"] and uv["no-binary"] == ["proxy-tools"] and uv["generate-hashes"]
    assert int(uv["exclude-newer"].split()[0]) >= 3


def _steps(doc):
    if isinstance(doc, dict):
        if "steps" in doc:
            yield from doc["steps"]
        for v in doc.values():
            yield from _steps(v)
    elif isinstance(doc, list):
        for v in doc:
            yield from _steps(v)


@pytest.mark.parametrize("wf", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_yaml_is_valid(wf):
    """Um `:all: ` solto num `run:` vira chave de mapa e derruba o job inteiro."""
    doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
    assert isinstance(doc, dict) and ("jobs" in doc or "runs" in doc)


@pytest.mark.parametrize("wf", WORKFLOWS, ids=lambda p: p.name)
def test_actions_pinned_by_commit_sha(wf):
    for line in wf.read_text(encoding="utf-8").splitlines():
        m = re.search(r"uses:\s*([^\s#]+)", line)
        if not m or m.group(1).startswith("./"):
            continue
        assert re.search(r"@[0-9a-f]{40}$", m.group(1)), f"{wf.name}: {m.group(1)} não está fixada por SHA"


@pytest.mark.parametrize("wf", WORKFLOWS, ids=lambda p: p.name)
def test_no_loose_pip_install_in_workflows(wf):
    """Pacotes só entram pela action de instalação, que usa os locks."""
    if wf.parent.name == "install":
        return
    doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
    for step in _steps(doc):
        assert "pip install" not in str(step.get("run", "")), f"{wf.name}: {step}"


@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_docker_images_pinned_by_digest(dockerfile):
    text = dockerfile.read_text(encoding="utf-8")
    froms = re.findall(r"^FROM\s+(\S+)", text, re.M)
    assert froms
    for image in froms:
        assert re.search(r"@sha256:[0-9a-f]{64}$", image), f"{dockerfile.name}: {image} sem digest"
    for cmd in re.findall(r"pip install[^\n]*", text):
        assert "--require-hashes" in cmd or "--no-deps" in cmd, f"{dockerfile.name}: {cmd}"
