"""Regenera os locks (versões exatas + hashes) a partir do pyproject.toml.

    pip install uv
    python requirements/lock.py            # mantém as versões já travadas quando possível
    python requirements/lock.py --upgrade  # sobe tudo para o mais novo com 3+ dias

As regras (só wheels, 3 dias de idade mínima, lock universal) ficam em
[tool.uv.pip] no pyproject.toml. Cada lock serve a um uso:

- bootstrap.txt: pip e setuptools, instalados primeiro;
- dev.txt: CI (lint, tipos, testes) e o build do pacote para o PyPI;
- runtime.txt: imagem Docker (interface web, sem as ferramentas de dev);
- desktop.txt: desenvolvimento local completo e o instalador do Windows.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

LOCKS: dict[str, list[str]] = {
    "bootstrap.txt": ["requirements/bootstrap.in"],
    "dev.txt": ["pyproject.toml", "--extra", "dev", "--extra", "web", "requirements/build.in"],
    "runtime.txt": ["pyproject.toml", "--extra", "web", "requirements/build.in"],
    "desktop.txt": ["pyproject.toml", "--extra", "desktop", "--extra", "dev", "requirements/build.in",
                    "requirements/package.in"],
}


def main() -> int:
    uv = shutil.which("uv") or str(Path(sys.executable).with_name("uv.exe" if sys.platform == "win32" else "uv"))
    upgrade = ["--upgrade"] if "--upgrade" in sys.argv else []
    for out, sources in LOCKS.items():
        cmd = [uv, "pip", "compile", *sources, "--quiet", "--custom-compile-command", "python requirements/lock.py",
               *upgrade, "-o", f"requirements/{out}"]
        print("+", " ".join(cmd[1:]), flush=True)
        subprocess.run(cmd, check=True, cwd=ROOT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
