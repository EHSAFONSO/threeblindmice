"""Atalho para abrir o app sem terminal: menu Iniciar (Windows) ou lançador (Linux)."""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from tbm.frozen import GUI_EXE, bundle_exe, is_frozen
from tbm.paths import no_window

NAME = "threeblindmice"


@dataclass
class ShortcutPlan:
    supported: bool
    paths: list[Path] = field(default_factory=list)
    files: dict[Path, str] = field(default_factory=dict)  # Linux: .desktop
    powershell: str | None = None  # Windows: script que cria os .lnk
    message: str = ""


def launcher() -> tuple[str, list[str]]:
    """Executável e argumentos: pythonw (sem console) no Windows."""
    if is_frozen():
        return str(bundle_exe(GUI_EXE)), []
    exe = Path(sys.executable)
    if sys.platform == "win32" and exe.with_name("pythonw.exe").exists():
        exe = exe.with_name("pythonw.exe")
    return str(exe), ["-m", "tbm", "app"]


def windows_folder(name: str, fallback: Path) -> Path:
    """Pasta especial do Windows ("Desktop", "Programs") onde ela realmente está.

    No Windows 11 com OneDrive, a Área de Trabalho costuma ser
    C:\\Users\\<você>\\OneDrive\\Desktop; supor ~/Desktop criaria o atalho numa
    pasta que não aparece na tela.
    """
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", f"[Environment]::GetFolderPath('{name}')"],
            capture_output=True, text=True, timeout=15, check=False, **no_window())
    except (OSError, subprocess.TimeoutExpired):
        return fallback
    value = proc.stdout.strip()
    return Path(value) if value else fallback


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def build_plan(platform: str, *, desktop: bool = False, icon: Path | None = None,
               home: Path | None = None, appdata: str | None = None) -> ShortcutPlan:
    exe, args = launcher()
    real_system = home is None and appdata is None  # testes passam pastas falsas
    home = home or Path.home()
    if platform == "win32":
        appdata = appdata or os.environ.get("APPDATA", str(home / "AppData" / "Roaming"))
        programs = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
        desktop_dir = home / "Desktop"
        if real_system and sys.platform == "win32":
            programs = windows_folder("Programs", programs)
            desktop_dir = windows_folder("Desktop", desktop_dir)
        paths = [programs / f"{NAME}.lnk"]
        if desktop:
            paths.append(desktop_dir / f"{NAME}.lnk")
        lines = ["$s = New-Object -ComObject WScript.Shell"]
        for p in paths:
            lines += [
                f"$l = $s.CreateShortcut({_ps_quote(str(p))})",
                f"$l.TargetPath = {_ps_quote(exe)}",
                f"$l.Arguments = {_ps_quote(' '.join(args))}",
                f"$l.WorkingDirectory = {_ps_quote(str(home))}",
                "$l.Description = 'threeblindmice: segurança da sua rede'",
            ]
            if icon:
                lines.append(f"$l.IconLocation = {_ps_quote(str(icon))}")
            lines.append("$l.Save()")
        return ShortcutPlan(True, paths=paths, powershell="; ".join(lines))
    if platform.startswith("linux"):
        path = home / ".local" / "share" / "applications" / f"{NAME}.desktop"
        entry = (
            "[Desktop Entry]\nType=Application\nName=threeblindmice\n"
            "Comment=Segurança da sua rede\n"
            f"Exec={exe} {' '.join(args)}\n"
            + (f"Icon={icon}\n" if icon else "")
            + "Terminal=false\nCategories=Network;Security;\n"
        )
        return ShortcutPlan(True, paths=[path], files={path: entry})
    return ShortcutPlan(False, message="Atalho automático ainda não suportado neste sistema. "
                                       "Use `tbm app` no terminal.")


def install(plan: ShortcutPlan) -> None:
    for path, content in plan.files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    if plan.powershell:
        for p in plan.paths:
            p.parent.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(["powershell", "-NoProfile", "-Command", plan.powershell],
                              capture_output=True, text=True, check=False, **no_window())
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout).strip() or "falha ao criar o atalho")


def remove(platform: str, home: Path | None = None, appdata: str | None = None) -> list[Path]:
    plan = build_plan(platform, desktop=True, home=home, appdata=appdata)
    removed = []
    for p in plan.paths:
        if p.exists():
            p.unlink()
            removed.append(p)
    return removed
