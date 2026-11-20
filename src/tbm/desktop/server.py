"""Servidor da interface numa thread, e controle de instância única."""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import uvicorn

from tbm.paths import private_dir, private_file, tbm_home


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class ServerThread:
    """uvicorn rodando em segundo plano, para a janela ficar com a thread principal.

    O uvicorn 0.54 já não instala tratadores de sinal fora da thread principal,
    então basta rodar `Server.run` numa thread e sinalizar `should_exit` para parar.
    """

    def __init__(self, app: Any, port: int) -> None:
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, name="tbm-server", daemon=True)

    def start(self, timeout: float = 15.0) -> None:
        self.thread.start()
        end = time.monotonic() + timeout
        while not self.server.started:
            if not self.thread.is_alive() or time.monotonic() > end:
                raise RuntimeError("o servidor da interface não subiu")
            time.sleep(0.05)

    def stop(self, timeout: float = 5.0) -> None:
        self.server.should_exit = True
        self.thread.join(timeout)


# ───────────────────────────── instância única ─────────────────────────────


def lock_path() -> Path:
    return tbm_home() / "app.lock"


def write_lock(port: int, token: str) -> None:
    private_dir(tbm_home())
    path = lock_path()
    path.write_text(json.dumps({"port": port, "token": token}), encoding="utf-8")
    private_file(path)


def clear_lock(token: str) -> None:
    """Só apaga se o lock for desta instância (outra pode ter assumido)."""
    info = read_lock()
    if info and info.get("token") == token:
        lock_path().unlink(missing_ok=True)


def read_lock() -> dict[str, Any] | None:
    try:
        data = json.loads(lock_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if isinstance(data, dict) and isinstance(data.get("port"), int) and isinstance(data.get("token"), str):
        return data
    return None


def ask_instance(info: dict[str, Any], path: str, method: str = "POST") -> dict[str, Any] | None:
    """Chama uma rota da instância aberta, autenticado como a própria interface (cookie + token + Origin)."""
    base = f"http://127.0.0.1:{info['port']}"
    try:
        r = httpx.request(method, base + path, timeout=3, cookies={"tbm_session": info["token"]},
                          headers={"X-TBM-Token": info["token"], "Origin": base})
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def take_over(info: dict[str, Any], timeout: float = 8.0) -> bool:
    """Pede para a instância antiga sair (ex.: versão diferente) e espera ela soltar o lock."""
    ask_instance(info, "/api/app/quit")
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if running_instance() is None:
            return True
        time.sleep(0.25)
    return False


def running_instance() -> dict[str, Any] | None:
    """Devolve o lock se o servidor dele responde de verdade, senão None.

    Não usamos `os.kill(pid, 0)` para ver se o processo existe: no Windows,
    `os.kill` com qualquer sinal fora CTRL_C/CTRL_BREAK *termina* o processo.
    Em vez disso, perguntamos ao próprio servidor: com o token certo, ele
    responde 303 (o redirecionamento do login). Isso também prova que é o nosso.
    """
    info = read_lock()
    if info is None:
        return None
    try:
        r = httpx.get(f"http://127.0.0.1:{info['port']}/", params={"token": info["token"]},
                      follow_redirects=False, timeout=2)
    except httpx.HTTPError:
        return None
    return info if r.status_code == 303 else None
