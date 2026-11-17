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
from tbm.desktop.server import ServerThread, clear_lock, free_port, running_instance, write_lock
from tbm.squeak import HistoryStore

TITLE = f"threeblindmice {__version__}"


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
    window: Any = None
    tray: Any = None
    quitting: bool = False
    hidden_notice_shown: bool = False
    smoke_result: dict[str, Any] = field(default_factory=dict)

    # ───────────────────────── bandeja ─────────────────────────

    def notify(self, title: str, text: str) -> None:
        if self.tray is not None:
            try:
                self.tray.notify(text, title)
            except Exception:  # noqa: BLE001,S110 (notificação é opcional)
                pass

    def on_job_done(self, job: Job) -> None:
        self.notify(*job_message(job))

    def _start_tray(self, base_url: str) -> None:
        if not self.tray_enabled or sys.platform == "darwin":  # no macOS, a bandeja exige a thread principal
            return
        try:
            import pystray

            from tbm.desktop.icon import make_icon
        except ImportError:
            return

        def show(path: str | None = None) -> None:
            self.window.show()
            self.window.restore()
            if path:
                self.window.load_url(base_url + path)

        menu = pystray.Menu(
            pystray.MenuItem("Abrir threeblindmice", lambda: show(), default=True),
            pystray.MenuItem("Novo scan", lambda: show("/scan")),
            pystray.MenuItem("Achados", lambda: show("/findings")),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Sair", lambda: self.quit()),
        )
        self.tray = pystray.Icon("threeblindmice", make_icon(64), "threeblindmice", menu)
        self.tray.run_detached()

    # ───────────────────────── janela ─────────────────────────

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
        """Roda dentro do webview.start: espera a página carregar, lê o que importa e fecha."""
        self.window.events.loaded.wait(30)
        try:
            self.smoke_result = {
                "title": self.window.evaluate_js("document.title"),
                "path": self.window.evaluate_js("location.pathname"),
                "nav": self.window.evaluate_js("[...document.querySelectorAll('nav.gui a')].length"),
            }
        except Exception as exc:  # noqa: BLE001
            self.smoke_result = {"error": repr(exc)}
        self.quit()

    # ───────────────────────── ciclo de vida ─────────────────────────

    def run(self) -> int:
        import webview

        webview.settings["ALLOW_DOWNLOADS"] = True  # botão "Baixar .txt" da carta
        webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True  # links do NVD etc.

        existing = running_instance()
        if existing and not self.smoke:
            # Já existe um app aberto: só abrimos outra janela para ele.
            url = f"http://127.0.0.1:{existing['port']}/?token={existing['token']}"
            self.window = webview.create_window(TITLE, url, width=1200, height=820, min_size=(760, 520))
            webview.start(private_mode=True)
            return 0

        from tbm.dashboard import create_app

        settings = GuiSettings(port=free_port())
        store = HistoryStore()
        app = create_app(store, gui=settings, runner=JobRunner(store, on_done=self.on_job_done))
        server = ServerThread(app, settings.port)
        server.start()
        write_lock(settings.port, settings.token)
        base_url = f"http://127.0.0.1:{settings.port}"
        try:
            self.window = webview.create_window(TITLE, settings.login_url(), width=1200, height=820,
                                                min_size=(760, 520))
            self.window.events.closing += self._on_closing
            if not self.smoke:
                self._start_tray(base_url)
            # private_mode: o cookie de sessão não sobrevive ao app (o token muda a cada execução).
            webview.start(self._smoke if self.smoke else None, private_mode=True)
        finally:
            if self.tray is not None:
                self.tray.stop()
            server.stop()
            clear_lock(settings.token)
        return 0
