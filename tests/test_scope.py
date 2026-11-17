from pathlib import Path

import pytest

from tbm.scope import Scope, ScopeError, expand_target


def test_cidr_expands_to_usable_hosts():
    ips = [t.address for t in expand_target("192.168.1.0/30")]
    assert ips == ["192.168.1.1", "192.168.1.2"]


def test_range_syntax():
    ips = [t.address for t in expand_target("10.0.0.5-7")]
    assert ips == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]


def test_invalid_range():
    with pytest.raises(ScopeError):
        list(expand_target("10.0.0.9-3"))


def test_default_scope_only_private():
    scope = Scope.default()
    assert scope.contains("192.168.0.10")
    assert scope.contains("127.0.0.1")
    assert not scope.contains("8.8.8.8")
    with pytest.raises(ScopeError, match="fora do escopo"):
        scope.resolve(["8.8.8.8"])


def test_huge_network_rejected():
    with pytest.raises(ScopeError, match="limite"):
        list(expand_target("10.0.0.0/8"))


def test_scope_file_requires_authorization(tmp_path: Path):
    f = tmp_path / "scope.yaml"
    f.write_text("allow: [203.0.113.10]\n", encoding="utf-8")
    with pytest.raises(ScopeError, match="authorized"):
        Scope.from_file(f)


def test_scope_file_allow_and_exclude(tmp_path: Path):
    f = tmp_path / "scope.yaml"
    f.write_text(
        "authorized: true\nowner: teste\nallow: [203.0.113.0/29]\nexclude: [203.0.113.3]\n",
        encoding="utf-8",
    )
    scope = Scope.from_file(f)
    ips = [t.address for t in scope.resolve(["203.0.113.0/29"])]
    assert "203.0.113.3" not in ips
    assert len(ips) == 5
    with pytest.raises(ScopeError):
        scope.resolve(["192.168.0.1"])  # privado, mas fora do arquivo de escopo
