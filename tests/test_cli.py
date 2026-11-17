from pathlib import Path

from typer.testing import CliRunner

from tbm.cli import app

runner = CliRunner()


def test_checks_lists_registry():
    result = runner.invoke(app, ["checks"])
    assert result.exit_code == 0
    assert "cve.nvd" in result.output and "http.paths" in result.output


def test_public_target_rejected_without_scope():
    result = runner.invoke(app, ["scan", "8.8.8.8", "--no-cve"])
    assert result.exit_code == 2


def test_secrets_command_exit_code(tmp_path: Path):
    (tmp_path / "a.env").write_text('GITHUB="ghp_' + "a1B2c3D4e5" * 4 + '"\n', encoding="utf-8")
    result = runner.invoke(app, ["secrets", str(tmp_path)])
    assert result.exit_code == 1
    assert "GitHub" in result.output
