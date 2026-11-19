# PyInstaller: dois executáveis (app sem console + CLI) sobre a mesma pasta _internal.
# Não rode direto: use `python packaging/windows/build.py`, que gera o ícone e a
# ficha de versão antes (em packaging/windows/build/).
# ruff: noqa
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

HERE = Path(SPECPATH)
BUILD = HERE / "build"

hidden = (
    collect_submodules("tbm")  # vários módulos são importados só dentro de funções
    + collect_submodules("uvicorn")  # loops/protocolos escolhidos em tempo de execução
    + ["webview.platforms.edgechromium", "webview.platforms.winforms", "pystray._win32", "clr"]
)
datas = collect_data_files("tbm", includes=["**/*.j2", "**/*.css", "**/*.js"])
excludes = ["tkinter", "pytest", "hypothesis", "mypy", "ruff", "IPython", "matplotlib", "numpy"]


def analysis(script):
    return Analysis([str(HERE / script)], pathex=[str(HERE.parent.parent / "src")], hiddenimports=hidden,
                    datas=datas, excludes=excludes, noarchive=False)


gui_a = analysis("launch_gui.py")
cli_a = analysis("launch_cli.py")


def exe(a, name, console):
    return EXE(PYZ(a.pure), a.scripts, [], exclude_binaries=True, name=name, console=console,
               icon=str(BUILD / "threeblindmice.ico"), version=str(BUILD / "version.txt"),
               upx=False)  # UPX dispara alarmes falsos de antivírus


coll = COLLECT(
    exe(gui_a, "threeblindmice", console=False), gui_a.binaries, gui_a.datas,
    exe(cli_a, "tbm", console=True), cli_a.binaries, cli_a.datas,
    name="threeblindmice", upx=False,
)
