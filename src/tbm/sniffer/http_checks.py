"""Checks HTTP: headers de segurança, cookies, vazamento de informação e APIs abertas."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from tbm.models import Finding, Host, Service, Severity
from tbm.sniffer.base import Check, CheckContext, register, url_for

SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}
_VERSION_RE = re.compile(r"/\s*\d")
_PASSWORD_INPUT = re.compile(r"<input[^>]+type\s*=\s*['\"]?password", re.IGNORECASE)


def analyze_response(host: str, port: int, url: str, resp: httpx.Response) -> list[Finding]:
    """Análise passiva de uma resposta HTTP. Pura: não faz requisições."""
    out: list[Finding] = []
    is_https = url.startswith("https://")
    h = resp.headers

    def add(cid: str, sev: Severity, title: str, desc: str, ev: str, fix: str, key: str = "") -> None:
        out.append(Finding(check_id=cid, key=key, severity=sev, title=title, host=host,
                           port=port, description=desc, evidence=ev, remediation=fix))

    # Redirecionamentos (ex.: http -> https) não precisam dos headers da página final.
    if not resp.is_redirect:
        missing = [label for name, label in SECURITY_HEADERS.items() if name not in h]
        if "x-frame-options" not in h and "frame-ancestors" not in h.get(
            "content-security-policy", ""
        ):
            missing.append("X-Frame-Options / frame-ancestors")
        if is_https and "strict-transport-security" not in h:
            missing.append("Strict-Transport-Security")
        if missing:
            add("http.headers", Severity.LOW, "Headers de segurança ausentes",
                "Esses headers mitigam XSS, clickjacking, MIME sniffing e downgrade de HTTPS.",
                f"{url} → faltando: " + ", ".join(missing),
                "Adicione os headers no servidor web ou no proxy reverso.")

    for header in ("server", "x-powered-by", "x-aspnet-version"):
        if (value := h.get(header)) and _VERSION_RE.search(value):
            add("http.disclosure", Severity.LOW, f"Versão de software exposta em {header}",
                "Expor a versão facilita para um atacante achar exploits específicos.",
                f"{header}: {value}",
                "Oculte a versão (nginx: server_tokens off; Apache: ServerTokens Prod).",
                key=header)

    for raw in h.get_list("set-cookie"):
        name = raw.split("=", 1)[0].strip()
        attrs = raw.lower()
        problems = []
        if is_https and "secure" not in attrs:
            problems.append("Secure")
        if "httponly" not in attrs:
            problems.append("HttpOnly")
        if "samesite" not in attrs:
            problems.append("SameSite")
        if problems:
            sev = Severity.MEDIUM if "Secure" in problems else Severity.LOW
            add("http.cookies", sev, f"Cookie '{name}' sem flags de segurança",
                "Sem HttpOnly, o cookie fica acessível a scripts (XSS). Sem Secure, ele vaza "
                "por HTTP. Sem SameSite, facilita CSRF.",
                f"Set-Cookie: {raw[:160]} → faltando: {', '.join(problems)}",
                "Defina Secure; HttpOnly; SameSite=Lax (ou Strict) nos cookies de sessão.",
                key=name)

    body = resp.text[:200_000] if resp.content else ""
    if re.search(r"<title>\s*Index of /", body, re.IGNORECASE):
        add("http.listing", Severity.MEDIUM, "Listagem de diretório habilitada",
            "O servidor lista os arquivos do diretório, o que expõe backups, configs e código.",
            url, "Desative o autoindex (nginx) ou 'Options -Indexes' (Apache).")

    if not is_https:
        if _PASSWORD_INPUT.search(body):
            add("http.cleartext-login", Severity.HIGH, "Formulário de senha via HTTP",
                "Senhas digitadas nesta página trafegam em texto puro pela rede.",
                f"{url} contém <input type=password>",
                "Sirva a aplicação só por HTTPS e redirecione o HTTP.")
        elif not (resp.is_redirect and h.get("location", "").startswith("https://")):
            add("http.no-https", Severity.INFO, "HTTP sem redirecionamento para HTTPS",
                "O serviço responde em texto puro.", url,
                "Se o serviço é usado por pessoas, redirecione para HTTPS.")
    return out


@register
class HTTPPassiveCheck(Check):
    id = "http.passive"
    name = "Headers, cookies e exposição HTTP"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        async def one(host: Host, svc: Service) -> list[Finding]:
            url = url_for(host, svc)
            try:
                resp = await ctx.http.get(url)
            except httpx.HTTPError:
                return []
            return analyze_response(host.address, svc.port, url, resp)

        results = await asyncio.gather(*(one(h, s) for h, s in ctx.services(lambda s: s.is_http)))
        return [f for batch in results for f in batch]


@dataclass(frozen=True)
class SensitivePath:
    path: str
    title: str
    severity: Severity
    # Validamos o conteúdo para não cair em "soft 404" (página 200 genérica).
    validator: Callable[[httpx.Response], bool]
    remediation: str


def _contains(*needles: str) -> Callable[[httpx.Response], bool]:
    return lambda r: any(n in r.text[:50_000] for n in needles)


SENSITIVE_PATHS = (
    SensitivePath("/.git/HEAD", "Repositório .git exposto", Severity.HIGH,
                  lambda r: r.text.startswith("ref: refs/"),
                  "Bloqueie /.git no servidor web; o código-fonte e o histórico podem ser "
                  "baixados inteiros."),
    SensitivePath("/.env", "Arquivo .env exposto", Severity.CRITICAL,
                  lambda r: bool(re.search(r"^[A-Z][A-Z0-9_]{2,}=", r.text[:5000], re.M))
                  and "<html" not in r.text[:500].lower(),
                  "Remova o .env da raiz pública e rotacione todas as credenciais contidas nele."),
    SensitivePath("/server-status", "Apache server-status público", Severity.MEDIUM,
                  _contains("Apache Server Status"),
                  "Restrinja o mod_status a localhost."),
    SensitivePath("/phpinfo.php", "phpinfo() exposto", Severity.MEDIUM,
                  _contains("phpinfo()", "PHP Version"),
                  "Remova o arquivo; ele expõe configuração, caminhos e variáveis de ambiente."),
    SensitivePath("/actuator/env", "Spring Boot Actuator /env exposto", Severity.HIGH,
                  _contains("propertySources", "activeProfiles"),
                  "Restrinja os endpoints do actuator (management.endpoints.web.exposure)."),
    SensitivePath("/.DS_Store", "Arquivo .DS_Store exposto", Severity.LOW,
                  lambda r: r.content[:8] == b"\x00\x00\x00\x01Bud1",
                  "Remova os .DS_Store do deploy; eles listam os nomes de arquivos do diretório."),
)


@register
class SensitivePathsCheck(Check):
    id = "http.paths"
    name = "Arquivos sensíveis expostos via HTTP"
    active_only = True

    async def run(self, ctx: CheckContext) -> list[Finding]:
        async def one(host: Host, svc: Service, sp: SensitivePath) -> Finding | None:
            url = url_for(host, svc, sp.path)
            try:
                resp = await ctx.http.get(url)
            except httpx.HTTPError:
                return None
            if resp.status_code != 200 or not sp.validator(resp):
                return None
            return Finding(check_id=self.id, key=sp.path, severity=sp.severity, title=sp.title,
                           host=host.address, port=svc.port, evidence=f"GET {url} → 200",
                           description=f"O caminho {sp.path} está acessível publicamente.",
                           remediation=sp.remediation)

        tasks = [one(h, s, sp) for h, s in ctx.services(lambda s: s.is_http)
                 for sp in SENSITIVE_PATHS]
        return [f for f in await asyncio.gather(*tasks) if f]


@register
class OpenAPIsCheck(Check):
    """Confirma acesso não autenticado a APIs administrativas comuns."""

    id = "http.open-api"
    name = "APIs administrativas sem autenticação"
    active_only = True

    PROBES = (
        # (porta, caminho, chave JSON esperada, título, severidade)
        (2375, "/version", "ApiVersion", "API do Docker acessível sem autenticação",
         Severity.CRITICAL),
        (9200, "/", "cluster_name", "Elasticsearch acessível sem autenticação", Severity.HIGH),
        (5984, "/_all_dbs", None, "CouchDB lista bancos sem autenticação", Severity.HIGH),
    )

    async def run(self, ctx: CheckContext) -> list[Finding]:
        findings = []
        for host, svc in ctx.services():
            for port, path, key, title, sev in self.PROBES:
                if svc.port != port:
                    continue
                url = url_for(host, svc.model_copy(update={"name": svc.name or "http"}), path)
                try:
                    resp = await ctx.http.get(url)
                    data = resp.json() if resp.status_code == 200 else None
                except (httpx.HTTPError, ValueError):
                    continue
                ok = isinstance(data, dict) and key in data if key else isinstance(data, list)
                if ok:
                    findings.append(Finding(
                        check_id=self.id, key=str(port), severity=sev, title=title,
                        host=host.address, port=port, evidence=f"GET {url} → {resp.text[:160]}",
                        description="A API respondeu com dados sem pedir credenciais.",
                        remediation="Exija autenticação e restrinja o acesso pela rede.",
                    ))
        return findings
