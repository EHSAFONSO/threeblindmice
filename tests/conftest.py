import pytest


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Nenhum teste escreve no ~/.threeblindmice real nem dispara alertas reais.

    Sem o delenv, quem configurou o Telegram (TBM_WEBHOOK) receberia mensagens a
    cada execução da suíte. Também tiramos o NVD_API_KEY para nenhum teste ir à rede.
    """
    monkeypatch.setenv("TBM_HOME", str(tmp_path / "tbm-home"))
    monkeypatch.delenv("TBM_WEBHOOK", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
