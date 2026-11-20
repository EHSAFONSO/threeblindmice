"""Alertas: teste do destino, configuração do Telegram e resumo semanal."""

from __future__ import annotations

from typing import Annotated

import typer

from tbm.cli.common import LabelOpt, NotifyOpt, _fail, _run, app, console
from tbm.config import config_path, notify_target, persist_notify
from tbm.squeak import HistoryStore
from tbm.squeak.notify import send_test
from tbm.squeak.telegram import TelegramError, bot_username, find_chats, looks_like_token


@app.command("notify-test")
def notify_test(notify: NotifyOpt = None) -> None:
    """Envia uma mensagem de teste para o destino de alertas configurado."""
    target = notify or notify_target()[0]
    if not target:
        raise _fail("nenhum destino configurado: use tbm telegram-setup, a página Alertas do tbm gui ou --notify")
    try:
        status = _run(send_test(target))
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise _fail(f"falha ao enviar: {exc}") from exc
    # Nunca imprimimos o destino: no Telegram, a URL contém o token do bot.
    if 200 <= status < 300:
        console.print("[green]Mensagem de teste enviada.[/] Confira no app.")
    else:
        hint = {401: "token inválido", 400: "chat_id errado ou você ainda não falou com o bot",
                404: "token ou URL inválidos", 403: "o bot foi bloqueado ou removido do chat"}.get(status, "")
        raise _fail(f"o destino respondeu HTTP {status}{f' ({hint})' if hint else ''}")


@app.command("telegram-setup")
def telegram_setup(
    save: Annotated[bool | None, typer.Option("--save/--no-save", help="Grava o destino sem perguntar (ou não grava).")] = None,
) -> None:
    """Conecta o Telegram: valida o token, acha o chat_id, envia um teste e salva o destino dos alertas."""
    console.print("Crie o bot com o [bold]@BotFather[/] (/newbot) e copie o token.\n"
                  "[dim]O token não aparece na tela enquanto você digita ou cola.[/]")
    token = typer.prompt("Token do bot", hide_input=True).strip()
    if not looks_like_token(token):
        raise _fail("isso não parece um token de bot (formato 123456789:AAH…). Copie de novo do @BotFather.")
    try:
        username = _run(bot_username(token))
    except TelegramError as exc:
        raise _fail(str(exc)) from exc
    console.print(f"Bot encontrado: [bold]@{username}[/]")

    chats = []
    for attempt in range(4):
        try:
            chats = _run(find_chats(token))
        except TelegramError as exc:
            raise _fail(str(exc)) from exc
        if chats:
            break
        if attempt == 3:
            raise _fail(f"nenhuma conversa encontrada. Abra https://t.me/{username}, toque em Iniciar "
                        "e rode o comando de novo.")
        typer.prompt(f"Abra https://t.me/{username} no Telegram, toque em Iniciar (ou mande 'oi') "
                     "e pressione Enter aqui", default="", show_default=False)

    chat = chats[0]
    if len(chats) > 1:
        for i, c in enumerate(chats, 1):
            console.print(f"  {i}. {c.title} [dim]({c.kind}, id {c.id})[/]")
        choice = typer.prompt("Qual conversa deve receber os alertas?", default=1, type=int)
        if not 1 <= choice <= len(chats):
            raise _fail("opção inválida")
        chat = chats[choice - 1]
    console.print(f"Conversa: [bold]{chat.title}[/] [dim]({chat.kind}, id {chat.id})[/]")

    url = f"tg://{token}/{chat.id}"
    status = _run(send_test(url))
    if not 200 <= status < 300:
        raise _fail(f"o Telegram recusou a mensagem de teste (HTTP {status}). O bot foi bloqueado?")
    console.print("[green]Mensagem de teste enviada.[/] Confira no Telegram.")

    if save is None:
        save = typer.confirm("Salvar como destino dos alertas (usado pelos scans, pela interface e pelo agendador)?",
                             default=True)
    if not save:
        console.print("[dim]Nada foi salvo. Use --notify tg://<token>/" + str(chat.id) + " nos comandos.[/]")
        return
    # Grava em TBM_HOME/config.json (só o seu usuário lê). O token não aparece na tela.
    notes = persist_notify(url)
    console.print(f"[green]Salvo[/] em {config_path()}.")
    for n in notes:
        console.print(f"[dim]{n}[/]")


@app.command("summary")
def summary_cmd(
    label: LabelOpt = "default",
    send: Annotated[bool, typer.Option("--send", help="Envia agora pelo destino dos alertas.")] = False,
    disable: Annotated[bool, typer.Option("--disable", help="Desliga o resumo semanal automático.")] = False,
    enable: Annotated[bool, typer.Option("--enable", help="Liga o resumo semanal automático.")] = False,
) -> None:
    """Resumo da semana: nota, o que mudou e a próxima ação. Sai sozinho 1x por semana com o vigia."""
    from tbm.squeak import summary

    if disable or enable:
        summary.set_enabled(enable)
        console.print(f"Resumo semanal automático {'ligado' if enable else 'desligado'}.")
        return
    store = HistoryStore()
    text = summary.build_summary(store, label)
    if text is None:
        raise _fail(f"nenhum scan com o rótulo '{label}'")
    console.print(text)
    if send:
        target = notify_target()[0]
        if not target:
            raise _fail("nenhum destino de alertas configurado (tbm telegram-setup ou tbm gui → Alertas)")
        from tbm.squeak.notify import send_text

        _run(send_text(target, text, title=f"threeblindmice: resumo semanal ({label})"))
        summary.mark_sent(store, label)
        console.print("[green]Enviado.[/]")
