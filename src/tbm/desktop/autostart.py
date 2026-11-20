"""Iniciar o app com o sistema, minimizado na bandeja. Desligado por padrão.

- Windows: um valor em HKCU\\...\\Run (só o seu usuário, nunca o sistema todo).
- Linux: um .desktop em ~/.config/autostart.

Sempre inicia com --hidden: a janela não abre, só o ícone da bandeja, para o
vigia em tempo real rodar sem atrapalhar. Nada é feito sem você pedir.
"""

from __future__ import annotations

import sys
from pathlib import Path

from tbm.desktop.shortcut import launcher
from tbm.frozen import GUI_EXE, bundle_exe, is_frozen

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE = "threeblindmice"


def _command() -> str:
    if is_frozen() and sys.platform == "win32":
        return f'"{bundle_exe(GUI_EXE)}" --hidden'
    exe, args = launcher()
    return " ".join([f'"{exe}"', *args, "--hidden"])


def _autostart_desktop() -> Path:
    return Path.home() / ".config" / "autostart" / "threeblindmice.desktop"


def is_enabled() -> bool:
    if sys.platform == "win32":
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
                winreg.QueryValueEx(key, VALUE)
            return True
        except OSError:
            return False
    return _autostart_desktop().exists()


def enable() -> None:
    if sys.platform == "win32":
        import winreg

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            winreg.SetValueEx(key, VALUE, 0, winreg.REG_SZ, _command())
        return
    path = _autostart_desktop()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "[Desktop Entry]\nType=Application\nName=threeblindmice\n"
        f"Exec={_command()}\nX-GNOME-Autostart-enabled=true\nTerminal=false\n",
        encoding="utf-8")


def disable() -> None:
    if sys.platform == "win32":
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, VALUE)
        except OSError:
            pass
        return
    _autostart_desktop().unlink(missing_ok=True)


def supported() -> bool:
    return sys.platform in ("win32", "linux")
