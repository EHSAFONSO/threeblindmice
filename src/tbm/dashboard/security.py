"""Proteções da interface gráfica (`tbm gui`).

O dashboard antigo era somente leitura de propósito. A interface gráfica
*dispara scans*, e isso muda o modelo de ameaça: qualquer site aberto no
seu navegador pode tentar mandar requisições para 127.0.0.1. Três camadas:

1. Host: só aceitamos os Hosts esperados (127.0.0.1:porta, localhost:porta).
   Isso bloqueia DNS rebinding, em que um domínio externo passa a resolver
   para 127.0.0.1 depois de carregado.
2. Token de sessão: um segredo aleatório gerado a cada `tbm gui`, entregue
   no link que o próprio comando abre. Ele vira um cookie HttpOnly e
   SameSite=Strict, que outros sites não conseguem ler nem enviar.
3. Ações (POST): exigem também o cabeçalho X-TBM-Token, lido pelo JavaScript
   da própria página, e uma Origin igual à da interface. Isso fecha o CSRF.
   Outro site não lê o token (same-origin policy) e não consegue forjar
   a Origin.

O mesmo controle de escopo da CLI vale aqui: alvos públicos são recusados.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from urllib.parse import urlencode

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

COOKIE = "tbm_session"
HEADER = "x-tbm-token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class GuiSettings:
    token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    port: int = 8770
    extra_hosts: set[str] = field(default_factory=set)  # para testes ("testserver")

    @property
    def allowed_hosts(self) -> set[str]:
        return {f"127.0.0.1:{self.port}", f"localhost:{self.port}", *self.extra_hosts}

    @property
    def allowed_origins(self) -> set[str]:
        return {f"http://{h}" for h in self.allowed_hosts}

    def login_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/?{urlencode({'token': self.token})}"


def _denied(status: int, message: str, html: bool) -> Response:
    if html:
        return HTMLResponse(
            f"<!doctype html><meta charset=utf-8><title>tbm</title><body style='font-family:system-ui;"
            f"max-width:560px;margin:60px auto'><h2>Acesso negado</h2><p>{message}</p></body>",
            status_code=status,
        )
    return JSONResponse({"error": message}, status_code=status)


def check_request(request: Request, gui: GuiSettings) -> Response | None:
    """Devolve uma resposta de bloqueio, ou None se a requisição pode seguir."""
    wants_html = "text/html" in request.headers.get("accept", "")
    host = request.headers.get("host", "")
    if host not in gui.allowed_hosts:
        return _denied(400, "Host não permitido. Abra a interface pelo endereço 127.0.0.1.", wants_html)

    # Primeiro acesso: o token vem na URL e vira cookie; a URL é limpa em seguida.
    url_token = request.query_params.get("token")
    if url_token is not None and request.method in SAFE_METHODS:
        if not secrets.compare_digest(url_token, gui.token):
            return _denied(401, "Link inválido ou expirado. Rode <code>tbm gui</code> de novo.", True)
        resp = RedirectResponse(request.url.remove_query_params("token").path or "/", status_code=303)
        resp.set_cookie(COOKIE, gui.token, httponly=True, samesite="strict", path="/")
        return resp

    cookie = request.cookies.get(COOKIE, "")
    if not cookie or not secrets.compare_digest(cookie, gui.token):
        return _denied(401, "Sessão não autenticada. Abra pelo link que o <code>tbm gui</code> mostrou "
                            "no terminal.", wants_html)

    if request.method not in SAFE_METHODS:
        origin = request.headers.get("origin")
        if origin not in gui.allowed_origins:
            return _denied(403, "Origem não permitida.", False)
        header = request.headers.get(HEADER, "")
        if not header or not secrets.compare_digest(header, gui.token):
            return _denied(403, "Token da ação ausente ou inválido.", False)
    return None
