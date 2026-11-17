import pytest


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Nenhum teste escreve no ~/.threeblindmice real."""
    monkeypatch.setenv("TBM_HOME", str(tmp_path / "tbm-home"))
