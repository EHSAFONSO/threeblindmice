"""`tbm app`: a interface numa janela própria, com ícone na bandeja.

Arquitetura:
- thread principal: a janela (pywebview exige isso em vários sistemas);
- thread "tbm-server": o mesmo servidor do `tbm gui`, numa porta livre;
- thread do pystray: o ícone na bandeja (Windows e Linux).

Fechar a janela com a bandeja ativa só a esconde: scans em andamento
continuam, e a bandeja avisa quando terminarem. "Sair" no menu encerra tudo.
"""

from __future__ import annotations

import sys
import threading
from dataclasses import dataclass, field
from typing import Any

from tbm import __version__
from tbm.dashboard.jobs import Job, JobRunner
from tbm.dashboard.security import GuiSettings
from tbm.desktop.server import (
    ServerThread,
    ask_instance,
    clear_lock,
    free_port,
    running_instance,
    take_over,
    write_lock,
)
from tbm.squeak import HistoryStore

TITLE = f"threeblindmice {__version__}"
APP_ID = "threeblindmice.desktop"


def set_windows_app_id() -> str | None:
    """Dá ao processo uma identidade própria na barra de tarefas do Windows.

    Sem isso, o Windows agrupa a janela sob o pythonw.exe e mostra o ícone do
    Python na barra de tarefas, mesmo com a janela usando o ícone do app.
    Precisa ser chamado antes de criar a janela.
    """
    if sys.platform != "win32":
        return None
    import ctypes

    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
    except (AttributeError, OSError):
        return None
    return APP_ID


def current_windows_app_id() -> str | None:
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    out = wintypes.LPWSTR()
    try:
        hr = ctypes.windll.shell32.GetCurrentProcessExplicitAppUserModelID(ctypes.byref(out))
    except (AttributeError, OSError):
        return None
    if hr != 0 or not out.value:
        return None
    value = out.value
    ctypes.windll.ole32.CoTaskMemFree(out)
    return value


def window_icon_is_custom(title: str) -> bool | None:
    """Para o teste de fumaça: a janela usa um ícone diferente do do pythonw.exe?"""
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    user32.FindWindowW.restype = wintypes.HWND
    user32.SendMessageW.restype = ctypes.c_void_p
    user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    hwnd = user32.FindWindowW(None, title)
    if not hwnd:
        return None
    big = user32.SendMessageW(hwnd, 0x7F, 1, 0)  # WM_GETICON, ICON_BIG
    if not big:
        return False
    if getattr(sys, "frozen", False):  # instalado: o próprio .exe já tem o ícone dos ratos
        return True
    # Compara com o ícone embutido no executável do Python
    shell32 = ctypes.windll.shell32
    shell32.ExtractIconW.restype = ctypes.c_void_p
    py_icon = shell32.ExtractIconW(None, sys.executable, 0)
    try:
        return bool(big) and big != py_icon
    finally:
        if py_icon:
            user32.DestroyIcon(ctypes.c_void_p(py_icon))


def app_icon_path() -> str | None:
    try:
        from tbm.desktop.icon import ensure_ico
    except ImportError:
        return None
    try:
        return str(ensure_ico())
    except OSError:
        return None


SPLASH = """<!doctype html><html><head><meta charset="utf-8"><title>{title}</title><style>
html,body{{margin:0;height:100%;background:#0d1015;color:#e8ebf0;font-family:"Segoe UI Variable","Segoe UI",system-ui,sans-serif}}
body{{display:grid;place-content:center;text-align:center;gap:14px}}
.m{{width:150px;margin:0 auto;animation:b 1.2s ease-in-out infinite}} @keyframes b{{50%{{transform:translateY(-6px)}}}}
.t{{font-size:22px;font-weight:700;letter-spacing:-.01em}} .s{{color:#9aa6b5;font-size:14px}}
.bar{{width:180px;height:4px;border-radius:9px;background:#29313c;overflow:hidden;margin:6px auto 0}}
.bar i{{display:block;width:40%;height:100%;border-radius:9px;background:linear-gradient(90deg,#9b87ff,#5ad480);animation:l 1.1s ease-in-out infinite}}
@keyframes l{{0%{{transform:translateX(-100%)}}100%{{transform:translateX(260%)}}}}
@media (prefers-reduced-motion:reduce){{.m,.bar i{{animation:none}}}}
</style></head><body>
<svg class="m" viewBox="0 0 240 120" aria-hidden="true">{mice}</svg>
<div class="t">threeblindmice</div><div class="s">{subtitle}</div><div class="bar"><i></i></div>
</body></html>"""

_MOUSE = (
    '<g transform="translate({x} 66) scale({s})"><circle cx="-26" cy="-26" r="17" fill="#9b87ff"/>'
    '<circle cx="26" cy="-26" r="17" fill="#9b87ff"/><ellipse cx="0" cy="2" rx="34" ry="30" fill="#9b87ff"/>'
    '<rect x="-27" y="-9" width="22" height="13" rx="6" fill="#0d1015"/><rect x="5" y="-9" width="22" height="13" rx="6" fill="#0d1015"/>'
    '<path d="M-5 -3h10" stroke="#0d1015" stroke-width="3"/><circle cx="0" cy="16" r="5" fill="#ff9a5c"/></g>'
)


def splash_html() -> str:
    mice = "".join(_MOUSE.format(x=x, s=s) for x, s in ((52, 0.82), (120, 1), (188, 0.82)))
    return SPLASH.format(title=TITLE, mice=mice, subtitle="Preparando a interface…")


def windows_dark_mode() -> bool:
    """O Windows está no modo escuro (apps)? Padrão: escuro, como o tema do tbm."""
    if sys.platform != "win32":
        return True
    try:
        import winreg

        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
        value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return not bool(value)
    except OSError:
        return True


def style_titlebar(title: str, dark: bool | None = None) -> bool:
    """Barra de título do Windows com as cores do tbm (Windows 11; no 10, só o modo escuro).

    Mantemos a barra nativa (arrastar, encaixar nas bordas, maximizar com duplo
    clique continuam funcionando) e só pintamos: fundo e texto iguais aos do app.
    """
    if sys.platform != "win32":
        return False
    import ctypes
    from ctypes import wintypes

    user32, dwm = ctypes.windll.user32, ctypes.windll.dwmapi
    user32.FindWindowW.restype = wintypes.HWND
    hwnd = user32.FindWindowW(None, title)
    if not hwnd:
        return False
    dark = windows_dark_mode() if dark is None else dark

    def put(attr: int, value: int) -> None:
        v = ctypes.c_int(value)
        dwm.DwmSetWindowAttribute(wintypes.HWND(hwnd), attr, ctypes.byref(v), ctypes.sizeof(v))

    def colorref(hex_rgb: str) -> int:
        r, g, b = (int(hex_rgb[i:i + 2], 16) for i in (1, 3, 5))
        return r | (g << 8) | (b << 16)

    put(20, int(dark))  # DWMWA_USE_IMMERSIVE_DARK_MODE
    put(35, colorref("#0d1015" if dark else "#f4f5f8"))  # DWMWA_CAPTION_COLOR (Windows 11)
    put(36, colorref("#e8ebf0" if dark else "#161a20"))  # DWMWA_TEXT_COLOR
    put(34, colorref("#29313c" if dark else "#e1e5eb"))  # DWMWA_BORDER_COLOR
    return True


def job_message(job: Job) -> tuple[str, str]:
    """(título, texto) da notificação de fim de scan."""
    if job.status == "error":
        return "Scan falhou", (job.error or "erro desconhecido")[:200]
    s = job.summary or {}
    text = f"Nota {s.get('grade')} ({s.get('score')}/100) · {s.get('hosts')} dispositivo(s)"
    if s.get("previous"):
        text += f" · {s.get('new_findings', 0)} achado(s) novo(s)"
    if s.get("new_devices"):
        text += f" · aparelho inédito: {', '.join(s['new_devices'][:2])}"
    return f"Scan '{s.get('label')}' concluído", text


@dataclass
class DesktopApp:
    tray_enabled: bool = True
    smoke: bool = False  # teste automático: abre, confere a página e fecha
    start_hidden: bool = False  # começa só na bandeja (iniciar com o sistema)
    monitor: Any = None
    window: Any = None
    tray: Any = None
    quitting: bool = False
    hidden_notice_shown: bool = False
    smoke_result: dict[str, Any] = field(default_factory=dict)
    runner: Any = None
    store: Any = None
    base_url: str = ""
    tray_info: dict[str, Any] = field(default_factory=dict)

    # ───────────────────────── bandeja ─────────────────────────

    def notify(self, title: str, text: str) -> None:
        if self.tray is not None:
            try:
                self.tray.notify(text, title)
            except Exception:  # noqa: BLE001,S110 (notificação é opcional)
                pass

    def on_job_done(self, job: Job) -> None:
        self.notify(*job_message(job))
        if job.summary:
            self.set_tray_grade(job.summary.get("grade"), job.summary.get("label"), job.summary.get("score"))

    def set_tray_grade(self, grade: str | None, label: str | None = None, score: int | None = None) -> None:
        """Pinta o selo do ícone da bandeja com a cor da nota mais recente."""
        if self.tray is None:
            return
        self.tray_info.update({"grade": grade, "label": label, "score": score})
        try:
            from tbm.desktop.icon import make_status_icon

            self.tray.icon = make_status_icon(grade)
            self.tray.title = (f"threeblindmice · {label}: nota {grade} ({score}/100)" if grade
                               else "threeblindmice")
        except Exception:  # noqa: BLE001,S110 (cosmético)
            pass

    def _start_tray(self, base_url: str) -> None:
        if not self.tray_enabled or sys.platform == "darwin":  # no macOS, a bandeja exige a thread principal
            return
        try:
            import pystray

            from tbm.desktop.icon import make_icon
        except ImportError:
            return

        def show(path: str | None = None) -> None:
            self.show_window()
            if path:
                self.window.load_url(base_url + path)

        def grade_text(_item: Any) -> str:
            info = self.tray_info
            if not info.get("grade"):
                return "Ainda sem scan"
            return f"Nota {info['grade']} ({info['score']}/100) · {info['label']}"

        def unknown_text(_item: Any) -> str:
            n = self.unknown_devices()
            return f"{n} aparelho(s) não aprovado(s)" if n else "Todos os aparelhos aprovados"

        menu = pystray.Menu(
            pystray.MenuItem(grade_text, lambda: show("/"), enabled=True),
            pystray.MenuItem(unknown_text, lambda: show("/inventory")),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Abrir threeblindmice", lambda: show(), default=True),
            pystray.MenuItem("Escanear agora", lambda: self.scan_now()),
            pystray.MenuItem("Novo scan…", lambda: show("/scan")),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Sair", lambda: self.quit()),
        )
        self.tray = pystray.Icon("threeblindmice", make_icon(64), "threeblindmice", menu)
        self.tray.run_detached()

    def unknown_devices(self) -> int:
        if self.store is None:
            return 0
        try:
            label = self.tray_info.get("label")
            scan = self.store.latest(label) if label else None
            return sum(1 for h in scan.hosts if not h.trusted) if scan else 0
        except Exception:  # noqa: BLE001 (menu nunca quebra)
            return 0

    def scan_now(self) -> None:
        """Repete o scan da rede pela bandeja, com o mesmo rótulo do último."""
        if self.runner is None:
            return
        from tbm.dashboard.jobs import BusyError, ScanParams
        from tbm.scout.discovery import suggested_target

        try:
            self.runner.submit(ScanParams(targets=suggested_target(), label=self.tray_info.get("label") or "casa"))
            self.notify("Scan iniciado", "Você recebe um aviso aqui quando terminar.")
        except BusyError:
            self.notify("Já existe um scan em andamento", "Espere ele terminar.")
        except Exception as exc:  # noqa: BLE001
            self.notify("Não foi possível iniciar o scan", str(exc)[:200])

    # ───────────────────────── janela ─────────────────────────

    def show_window(self) -> None:
        if self.window is None:
            return
        self.window.show()
        self.window.restore()
        try:  # traz para a frente: liga e desliga o "sempre no topo"
            self.window.on_top = True
            self.window.on_top = False
        except Exception:  # noqa: BLE001,S110
            pass

    def _on_closing(self) -> bool:
        if self.quitting or self.tray is None:
            return True  # fecha de verdade
        # Esconde em outra thread: chamar hide() de dentro do evento de fechamento
        # pode travar o loop da janela em alguns backends.
        threading.Thread(target=self.window.hide, daemon=True).start()
        if not self.hidden_notice_shown:
            self.hidden_notice_shown = True
            self.notify("threeblindmice continua rodando",
                        "Scans em andamento continuam. Abra ou saia pelo ícone na bandeja.")
        return False  # cancela o fechamento

    def quit(self) -> None:
        self.quitting = True
        if self.window is not None:
            self.window.destroy()

    def _smoke(self) -> None:
        """Roda depois do boot: espera a interface (não a tela de abertura), lê o que importa e fecha."""
        import time

        end = time.monotonic() + 30
        while time.monotonic() < end:
            try:
                if self.window.evaluate_js("!!document.querySelector('.side-nav')"):
                    break
            except Exception:  # noqa: BLE001,S110 (página trocando)
                pass
            time.sleep(0.2)
        try:
            self.smoke_result = {
                "title": self.window.evaluate_js("document.title"),
                "path": self.window.evaluate_js("location.pathname"),
                "nav": self.window.evaluate_js("document.querySelectorAll('.side-nav a').length"),
                "titlebar": style_titlebar(TITLE),
                "app_id": current_windows_app_id(),
                "window_icon": window_icon_is_custom(TITLE),
            }
        except Exception as exc:  # noqa: BLE001
            self.smoke_result = {"error": repr(exc)}
        self.quit()

    # ───────────────────────── ciclo de vida ─────────────────────────

    def run(self) -> int:
        import webview

        webview.settings["ALLOW_DOWNLOADS"] = True  # botão "Baixar .txt" da carta
        webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True  # links do NVD etc.
        set_windows_app_id()  # antes de qualquer janela: ícone próprio na barra de tarefas
        icon = app_icon_path()  # ícone da janela (canto superior esquerdo)

        existing = running_instance()
        if existing and not self.smoke:
            # Já existe um app aberto. Mesma versão: só trazemos a janela dele para a frente e saímos
            # (antes abríamos outra janela, e ficavam dois processos). Versão diferente, ou uma
            # instância antiga que não sabe se mostrar: pedimos para ela sair e assumimos.
            version = (ask_instance(existing, "/api/app/version", method="GET") or {}).get("version")
            if version == __version__ and ask_instance(existing, "/api/app/show"):
                return 0
            take_over(existing)

        from tbm.dashboard import create_app

        settings = GuiSettings(port=free_port())
        self.store = store = HistoryStore()
        self.runner = JobRunner(store, on_done=self.on_job_done)
        app = create_app(store, gui=settings, runner=self.runner)
        app.state.desktop = {"show": self.show_window, "quit": self.quit}
        server = ServerThread(app, settings.port)
        self.base_url = base_url = f"http://127.0.0.1:{settings.port}"

        def boot() -> None:
            # A janela já está na tela com a abertura; o servidor sobe enquanto isso.
            server.start()
            write_lock(settings.port, settings.token)
            style_titlebar(TITLE)
            self.window.load_url(settings.login_url())
            if self.start_hidden and self.tray is not None:
                threading.Thread(target=self.window.hide, daemon=True).start()  # só a bandeja
            if self.smoke:
                self._smoke()

        try:
            self.window = webview.create_window(TITLE, html=splash_html(), width=1240, height=840,
                                                min_size=(760, 520), background_color="#0d1015",
                                                hidden=self.start_hidden)
            self.window.events.closing += self._on_closing
            self.window.events.shown += lambda: style_titlebar(TITLE)
            if not self.smoke:
                self._start_tray(base_url)
                latest = max(store.labels(), key=lambda r: r["started_at"], default=None)
                if latest is not None:
                    self.set_tray_grade(latest["grade"], latest["label"], latest["score"])
                if self.tray is not None:  # vigia em tempo real só quando há bandeja para avisar
                    from tbm.desktop.monitor import LiveMonitor

                    self.monitor = LiveMonitor(store, self.notify)
                    self.monitor.start()
            # private_mode: o cookie de sessão não sobrevive ao app (o token muda a cada execução).
            webview.start(boot, private_mode=True, icon=icon)
        finally:
            if self.monitor is not None:
                self.monitor.stop()
            if self.tray is not None:
                self.tray.stop()
            server.stop()
            clear_lock(settings.token)
        return 0
