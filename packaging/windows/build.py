"""Gera o instalador do Windows: dist/threeblindmice_<versão>_x64-setup.exe (+ .sha256).

    pip install -e ".[desktop]" pyinstaller
    python packaging/windows/build.py              # pacote + instalador (precisa do Inno Setup 6)
    python packaging/windows/build.py --no-installer   # só a pasta do PyInstaller

Etapas: ícone e ficha de versão → PyInstaller (pasta com threeblindmice.exe e
tbm.exe) → teste de fumaça do tbm.exe → Inno Setup → SHA-256.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
BUILD = HERE / "build"
DIST = ROOT / "dist"


def version() -> str:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def write_icon() -> Path:
    from tbm.desktop.icon import make_icon

    path = BUILD / "threeblindmice.ico"
    sizes = [(s, s) for s in (16, 24, 32, 48, 64, 128, 256)]
    make_icon(256).save(path, format="ICO", sizes=sizes)
    return path


def write_version_file(v: str) -> Path:
    """Ficha que aparece em Propriedades → Detalhes do .exe."""
    nums = tuple(int(p) for p in v.split(".")[:3]) + (0,)
    fields = {
        "CompanyName": "threeblindmice",
        "FileDescription": "threeblindmice: segurança da sua rede",
        "FileVersion": v,
        "InternalName": "threeblindmice",
        "LegalCopyright": "MIT License",
        "OriginalFilename": "threeblindmice.exe",
        "ProductName": "threeblindmice",
        "ProductVersion": v,
    }
    strings = ",\n".join(f"          StringStruct({k!r}, {val!r})" for k, val in fields.items())
    content = f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={nums}, prodvers={nums}, mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('041604B0', [
{strings}
    ])]),
    VarFileInfo([VarStruct('Translation', [1046, 1200])])
  ]
)
"""
    path = BUILD / "version.txt"
    path.write_text(content, encoding="utf-8")
    return path


def run(cmd: list[str], **kw) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True, **kw)


def find_iscc() -> str | None:
    found = shutil.which("iscc")
    if found:
        return found
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"),
                 os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs")):
        if base and (candidate := Path(base) / "Inno Setup 6" / "ISCC.exe").exists():
            return str(candidate)
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-installer", action="store_true", help="para depois do PyInstaller")
    args = parser.parse_args()
    if sys.platform != "win32":
        print("o instalador só é gerado no Windows", file=sys.stderr)
        return 2

    v = version()
    BUILD.mkdir(parents=True, exist_ok=True)
    write_icon()
    write_version_file(v)

    run([sys.executable, "-m", "PyInstaller", str(HERE / "threeblindmice.spec"), "--noconfirm", "--clean",
         "--distpath", str(BUILD / "dist"), "--workpath", str(BUILD / "work")])
    bundle = BUILD / "dist" / "threeblindmice"

    # Fumaça: o tbm.exe empacotado responde e enxerga os templates
    env = {**os.environ, "TBM_HOME": str(BUILD / "smoke-home")}
    out = subprocess.run([str(bundle / "tbm.exe"), "--version"], capture_output=True, text=True, env=env,
                         check=True, encoding="utf-8", errors="replace").stdout
    if v not in out:
        print(f"tbm.exe --version não mostrou {v}: {out!r}", file=sys.stderr)
        return 1
    print(f"tbm.exe ok: {out.strip()}")

    if args.no_installer:
        print(f"pacote em {bundle}")
        return 0
    iscc = find_iscc()
    if iscc is None:
        print("Inno Setup 6 (ISCC.exe) não encontrado: https://jrsoftware.org/isdl.php", file=sys.stderr)
        return 1
    DIST.mkdir(exist_ok=True)
    run([iscc, f"/DAppVersion={v}", f"/DSourceDir={bundle}", f"/DOutputDir={DIST}",
         f"/DIconFile={BUILD / 'threeblindmice.ico'}", str(HERE / "threeblindmice.iss")])
    setup = DIST / f"threeblindmice_{v}_x64-setup.exe"
    digest = hashlib.sha256(setup.read_bytes()).hexdigest()
    setup.with_name(setup.name + ".sha256").write_text(f"{digest}  {setup.name}\n", encoding="ascii")
    print(f"\n{setup}  ({setup.stat().st_size / 1e6:.1f} MB)\nSHA-256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
