"""Interfaces: dashboard, gui, app da área de trabalho, demo, autostart e atalhos."""

from __future__ import annotations

import os
import sys
from typing import Annotated

import typer

from tbm import __version__
from tbm.cli.common import BANNER, _fail, app, console, err
from tbm.squeak import HistoryStore


@app.command()
def dashboard(
    host: Annotated[str, typer.Option(help="Interface de escuta. Mantenha 127.0.0.1: o histórico é sensível.")] = "127.0.0.1",
    port: int = 8765,
) -> None:
    """Dashboard web com a evolução da nota e o histórico de scans."""
    try:
        import uvicorn

        from tbm.dashboard import create_app
    except ImportError as exc:
        raise _fail('dependências do dashboard ausentes: pip install -e ".[web]"') from exc
    if host not in ("127.0.0.1", "localhost", "::1"):
        err.print(f"[bold yellow]atenção:[/] escutando em {host}. O dashboard não tem autenticação "
                  "e mostra o inventário da sua rede.")
    console.print(f"Dashboard em [bold]http://{host}:{port}[/] (Ctrl+C para sair)")
    uvicorn.run(create_app(HistoryStore()), host=host, port=port, log_level="warning")


@app.command()
def gui(
    port: Annotated[int, typer.Option(help="Porta local da interface.")] = 8770,
    no_browser: Annotated[bool, typer.Option("--no-browser", help="Não abre o navegador.")] = False,
) -> None:
    """[bold]Interface gráfica[/] no navegador: novo scan, achados, dispositivos e funcionalidades."""
    try:
        import uvicorn

        from tbm.dashboard import create_app
        from tbm.dashboard.security import GuiSettings
    except ImportError as exc:
        raise _fail('dependências da interface ausentes: pip install "threeblindmice[web]"') from exc
    import threading
    import webbrowser

    # Sempre 127.0.0.1 e sem opção de mudar: a interface dispara scans (ver dashboard/security.py).
    settings = GuiSettings(port=port)
    url = settings.login_url()
    console.print(BANNER.format(v=__version__))
    console.print(f"Interface em [bold]{url}[/]")
    console.print("[dim]O link tem um token de sessão: não compartilhe. Ctrl+C para encerrar.[/]")
    if not no_browser:
        threading.Timer(1.2, webbrowser.open, args=(url,)).start()
    uvicorn.run(create_app(HistoryStore(), gui=settings), host="127.0.0.1", port=port, log_level="warning")


@app.command("app")
def desktop_app(
    no_tray: Annotated[bool, typer.Option("--no-tray", help="Sem ícone na bandeja: fechar a janela encerra o app.")] = False,
    hidden: Annotated[bool, typer.Option("--hidden", help="Começa minimizado na bandeja (usado ao iniciar com o sistema).")] = False,
    smoke: Annotated[bool, typer.Option("--smoke", hidden=True)] = False,
) -> None:
    """[bold]Aplicativo de desktop:[/] a interface numa janela própria, com ícone na bandeja."""
    try:
        import webview  # noqa: F401

        from tbm.desktop.app import DesktopApp
    except ImportError as exc:
        raise _fail('dependências do app ausentes: pip install "threeblindmice[desktop]"') from exc
    runner = DesktopApp(tray_enabled=not no_tray, smoke=smoke, start_hidden=hidden)
    code = runner.run()
    if smoke:
        console.print(runner.smoke_result)
    raise typer.Exit(code)


def _dashboard_fn() -> None:
    dashboard()


@app.command("demo")
def demo_cmd(
    dashboard: Annotated[bool, typer.Option("--dashboard", help="Abre o dashboard (somente leitura) em vez da interface completa.")] = False,
) -> None:
    """Abre a interface com uma rede fictícia, para prints e apresentações (não toca no seu histórico)."""

    from tbm.demo import demo_home

    os.environ["TBM_HOME"] = str(demo_home())
    console.print("[bold]Modo demonstração[/]: rede fictícia, histórico temporário.")
    if dashboard:
        _dashboard_fn()
        return
    try:
        import webview  # noqa: F401
    except ImportError:
        _dashboard_fn()
    else:
        desktop_app()


@app.command("autostart")
def autostart_cmd(
    enable: Annotated[bool, typer.Option("--enable", help="Inicia o app com o sistema, minimizado na bandeja.")] = False,
    disable: Annotated[bool, typer.Option("--disable", help="Não inicia mais com o sistema.")] = False,
) -> None:
    """Liga/desliga iniciar o app de desktop junto com o sistema (vigia em tempo real)."""
    from tbm.desktop import autostart

    if not autostart.supported():
        raise _fail("não suportado neste sistema")
    if enable:
        autostart.enable()
    elif disable:
        autostart.disable()
    console.print(f"Iniciar com o sistema: [bold]{'ligado' if autostart.is_enabled() else 'desligado'}[/]")


shortcut_app = typer.Typer(help="Atalho para abrir o app sem terminal (menu Iniciar / lançador).")


app.add_typer(shortcut_app, name="shortcut")


@shortcut_app.command("install")
def shortcut_install(
    desktop: Annotated[bool, typer.Option("--desktop", help="Também cria um atalho na Área de Trabalho.")] = False,
) -> None:
    """Cria o atalho "threeblindmice" no menu Iniciar (Windows) ou no lançador (Linux)."""
    from tbm.desktop import shortcut

    icon = None
    try:
        from tbm.desktop.icon import ensure_ico

        icon = ensure_ico()
    except ImportError:
        pass  # sem Pillow: atalho com o ícone padrão do Python
    plan = shortcut.build_plan(sys.platform, desktop=desktop, icon=icon)
    if not plan.supported:
        raise _fail(plan.message)
    try:
        shortcut.install(plan)
    except RuntimeError as exc:
        raise _fail(str(exc)) from exc
    for p in plan.paths:
        console.print(f"[green]Atalho criado:[/] {p}")


@shortcut_app.command("remove")
def shortcut_remove() -> None:
    """Remove os atalhos criados pelo `tbm shortcut install`."""
    from tbm.desktop import shortcut

    removed = shortcut.remove(sys.platform)
    console.print("\n".join(f"Removido: {p}" for p in removed) or "[dim]Nenhum atalho encontrado.[/]")
