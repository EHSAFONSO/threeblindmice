"""Checks da rede como um todo (não de um aparelho): Wi-Fi, DNS, visão de fora e IPv6.

Só rodam quando o scan é da rede local (o Scout achou o gateway). Num scan do
seu VPS não faz sentido olhar o Wi-Fi de quem está escaneando.

- network.wifi: a criptografia da rede Wi-Fi em que este computador está.
- network.ipv6: portas abertas também no IPv6 global (sem NAT para proteger).
- network.dns (externo): o DNS do roteador responde a verdade?
- network.external (externo): o que a internet vê do seu IP público.

Os dois externos falam com serviços de terceiros (Cloudflare e Shodan
InternetDB) e mandam o seu IP público para eles. Por isso só rodam com
`--external` (na interface: "Verificações externas").
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import secrets
import socket
import subprocess
import sys
import unicodedata
from dataclasses import dataclass

import httpx

from tbm.models import Finding, Severity
from tbm.paths import no_window
from tbm.scout import wire
from tbm.scout.udp import udp_exchange
from tbm.sniffer.base import Check, CheckContext, register

WIFI_HOST = "wifi"
RISKY_PORTS = {21, 23, 135, 139, 445, 1433, 2323, 3306, 3389, 5432, 5900, 6379, 7547, 9200, 27017}


def _lan_scan(ctx: CheckContext) -> bool:
    return bool(ctx.scan.gateway)


# ───────────────────────────── Wi-Fi ─────────────────────────────


@dataclass
class WifiInfo:
    ssid: str | None
    auth: str  # como o sistema descreve: "WPA2-Personal", "Aberta", "WPA3"...
    cipher: str | None = None


def _ascii_key(key: str) -> str:
    return unicodedata.normalize("NFKD", key).encode("ascii", "ignore").decode().strip().lower()


def parse_netsh_wlan(text: str) -> WifiInfo | None:
    """`netsh wlan show interfaces`, em português ou inglês (a saída é traduzida)."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        k, v = _ascii_key(key), value.strip()
        if k == "ssid":
            fields.setdefault("ssid", v)
        elif k.startswith(("autentica", "authentication")):
            fields.setdefault("auth", v)
        elif k.startswith(("codifica", "cipher", "criptografia")):
            fields.setdefault("cipher", v)
        elif k.startswith(("estado", "state")) and v.lower() not in ("conectado", "connected"):
            return None  # interface sem conexão ("desconectado" contém "conectado": comparação exata)
    if "auth" not in fields:
        return None
    return WifiInfo(fields.get("ssid"), fields["auth"], fields.get("cipher"))


def parse_nmcli(text: str) -> WifiInfo | None:
    """`nmcli -t -f ACTIVE,SSID,SECURITY dev wifi` (Linux)."""
    for line in text.splitlines():
        parts = re.split(r"(?<!\\):", line)
        if len(parts) >= 3 and parts[0] in ("yes", "sim"):
            security = parts[2].strip()
            return WifiInfo(parts[1].replace("\\:", ":"), security if security not in ("", "--") else "aberta")
    return None


def parse_airport(text: str) -> WifiInfo | None:
    """`system_profiler SPAirPortDataType` (macOS): bloco "Current Network Information"."""
    m = re.search(r"Current Network Information:\s*\n\s*(.+?):\s*\n(.*?)(?:\n\s*\n|Other Local)", text, re.S)
    if not m:
        return None
    sec = re.search(r"Security:\s*(.+)", m.group(2))
    return WifiInfo(m.group(1).strip(), sec.group(1).strip() if sec else "desconhecida")


def wifi_command() -> tuple[list[str], object] | None:
    if sys.platform == "win32":
        return ["netsh", "wlan", "show", "interfaces"], parse_netsh_wlan
    if sys.platform == "darwin":
        return ["system_profiler", "SPAirPortDataType"], parse_airport
    return ["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY", "dev", "wifi"], parse_nmcli


def read_wifi() -> WifiInfo | None:
    spec = wifi_command()
    if spec is None:
        return None
    cmd, parse = spec
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=20, check=False, **no_window())
    except (OSError, subprocess.TimeoutExpired):
        return None
    # netsh escreve na página de código do console (cp850 no Brasil), não em UTF-8
    text = proc.stdout.decode("utf-8", errors="replace")
    if "�" in text and sys.platform == "win32":
        text = proc.stdout.decode("cp850", errors="replace")
    return parse(text)  # type: ignore[operator]


def classify_wifi(info: WifiInfo) -> tuple[Severity, str, str, str] | None:
    """(severidade, chave, título, explicação) ou None quando está bom (WPA2-AES/WPA3)."""
    auth = info.auth.lower()
    cipher = (info.cipher or "").lower()
    if any(w in auth for w in ("aberta", "open", "none", "nenhuma")) and "wpa" not in auth:
        return (Severity.HIGH, "open", "Wi-Fi sem senha",
                "Qualquer pessoa ao alcance do sinal entra na sua rede e vê o tráfego que não é criptografado.")
    if "wep" in auth or "wep" in cipher:
        return (Severity.HIGH, "wep", "Wi-Fi com WEP (quebrado)",
                "O WEP é quebrado em minutos com ferramentas gratuitas. Na prática, é uma rede aberta.")
    if "tkip" in cipher or re.search(r"\bwpa\b(?![23])|wpa-personal|wpa - personal", auth):
        return (Severity.MEDIUM, "wpa1", "Wi-Fi com WPA/TKIP (obsoleto)",
                "O WPA original e a cifra TKIP têm falhas conhecidas e foram aposentados em 2012.")
    if "wpa3" in auth or "sae" in auth:
        return None
    if "wpa2" in auth:
        return (Severity.INFO, "wpa2", "Wi-Fi com WPA2 (pode subir para WPA3)",
                "WPA2 com AES é seguro com uma senha forte. Se o roteador e os aparelhos aceitarem, o WPA3 "
                "protege contra a adivinhação de senha por quem capturou o handshake.")
    return None


@register
class WifiCheck(Check):
    id = "network.wifi"
    name = "Criptografia do Wi-Fi"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        if not _lan_scan(ctx):
            return []
        info = await asyncio.to_thread(read_wifi)
        if info is None:
            return []  # cabo, sem Wi-Fi ou comando indisponível
        verdict = classify_wifi(info)
        if verdict is None:
            return []
        sev, key, title, why = verdict
        evidence = f"rede {info.ssid or '?'} · autenticação {info.auth}"
        if info.cipher:
            evidence += f" · cifra {info.cipher}"
        return [Finding(
            check_id=self.id, title=title, severity=sev, host=WIFI_HOST, key=key, port=None,
            description=why + " O teste olha a rede em que ESTE computador está conectado.",
            evidence=evidence,
            remediation=("Na página do roteador (Wi-Fi / Wireless → Segurança), escolha WPA2-PSK com AES, ou "
                         "WPA2/WPA3 se aparecer, e uma senha longa (12+ caracteres). Aproveite para desligar o WPS: "
                         "o PIN de 8 dígitos dele é adivinhado em horas."),
            references=["https://www.wi-fi.org/discover-wi-fi/security"],
        )]


# ───────────────────────────── IPv6 ─────────────────────────────


@register
class IPv6ExposureCheck(Check):
    id = "network.ipv6"
    name = "Portas abertas no IPv6 global"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        if not _lan_scan(ctx):
            return []
        findings: list[Finding] = []
        with_v6 = [h for h in ctx.scan.hosts if h.ipv6]
        for h in with_v6:
            if not h.ipv6_services:
                continue
            risky = sorted(set(h.ipv6_services) & RISKY_PORTS)
            findings.append(Finding(
                check_id=self.id, host=h.address, key="services",
                severity=Severity.HIGH if risky else Severity.MEDIUM,
                title=f"Portas abertas também no IPv6 público ({', '.join(map(str, h.ipv6_services[:8]))})",
                description=("No IPv6 não existe NAT: o endereço deste aparelho é alcançável da internet, e só o "
                             "firewall IPv6 do roteador impede que essas portas fiquem expostas. Alguns modems de "
                             "operadora vêm com esse firewall desligado."),
                evidence=f"IPv6 {h.ipv6[0]} · portas {', '.join(map(str, h.ipv6_services))}",
                remediation=("Confira na página do roteador (IPv6 → Firewall ou Segurança) se o firewall IPv6 "
                             "está ligado, bloqueando conexões de entrada. Se não houver essa opção, peça ao "
                             "provedor. No próprio aparelho, feche os serviços que não usa."),
                references=["https://www.rfc-editor.org/rfc/rfc6092"],
            ))
        if with_v6 and ctx.scan.gateway:
            findings.append(Finding(
                check_id=self.id, host=ctx.scan.gateway, key="prefix", severity=Severity.INFO,
                title="Rede com IPv6 público: confira o firewall IPv6 do roteador",
                description=(f"{len(with_v6)} aparelho(s) têm endereço IPv6 global, roteável na internet. Daqui de "
                             "dentro não dá para testar o firewall do roteador; isso precisa de um teste de fora."),
                evidence=", ".join(f"{h.address} → {h.ipv6[0]}" for h in with_v6[:5]),
                remediation=("Na página do roteador, procure IPv6 → Firewall e deixe bloqueadas as conexões de "
                             "entrada. Um teste de fora: abra https://ipv6-test.com/ pelo celular no 4G."),
            ))
        return findings


# ───────────────────────────── DNS ─────────────────────────────

# Nomes com respostas fixas e conhecidas: se o DNS devolver outra coisa, está mentindo.
STABLE_NAMES = {
    "one.one.one.one": {"1.1.1.1", "1.0.0.1"},
    "dns.google": {"8.8.8.8", "8.8.4.4"},
}


async def ask_dns(server: str, name: str, timeout: float = 2.0) -> tuple[int, set[str]] | None:
    """(rcode, IPs A) perguntando direto a um servidor DNS por UDP."""
    data = await udp_exchange(server, 53, wire.build_query(name, wire.TYPE_A), timeout)
    if not data:
        return None
    try:
        resp = wire.parse_response(data[:4096])
    except wire.ParseError:
        return None
    return resp.rcode, set(resp.a_records().values())


async def ask_doh(http: httpx.AsyncClient, name: str) -> set[str] | None:
    try:
        resp = await http.get("https://cloudflare-dns.com/dns-query", params={"name": name, "type": "A"},
                              headers={"Accept": "application/dns-json"}, timeout=8)
        data = resp.json()
    except (httpx.HTTPError, ValueError):
        return None
    return {a["data"] for a in data.get("Answer", []) if a.get("type") == 1}


async def ask_system(name: str) -> set[str] | None:
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(name, None, family=socket.AF_INET)
    except OSError:
        return None
    return {str(i[4][0]) for i in infos}


@register
class DNSHijackCheck(Check):
    id = "network.dns"
    name = "DNS sequestrado"

    def enabled(self, options) -> bool:
        return super().enabled(options) and options.external

    async def run(self, ctx: CheckContext) -> list[Finding]:
        gw = ctx.scan.gateway
        if not gw:
            return []
        findings: list[Finding] = []
        lies: list[str] = []
        for name, expected in STABLE_NAMES.items():
            truth = await ask_doh(ctx.http, name) or expected
            router, system = await asyncio.gather(ask_dns(gw, name), ask_system(name))
            for source, answer in (("roteador", router[1] if router else None), ("sistema", system)):
                if answer and not answer & truth:
                    got, right = ", ".join(sorted(answer)), ", ".join(sorted(truth))
                    lies.append(f"{source}: {name} → {got} (o certo é {right})")
        if lies:
            findings.append(Finding(
                check_id=self.id, host=gw, key="hijack", severity=Severity.CRITICAL,
                title="DNS devolvendo endereços falsos",
                description=("Nomes com resposta fixa e conhecida voltaram com outros endereços. É o sinal típico de "
                             "roteador invadido (o atacante troca o DNS para mandar você a sites falsos de banco) ou "
                             "de um programa malicioso neste computador."),
                evidence="\n".join(lies),
                remediation=("Entre na página do roteador e confira os servidores DNS (em WAN/Internet e em DHCP/LAN): "
                             "deixe automático ou use 1.1.1.1 e 8.8.8.8. Troque a senha de administração do roteador e "
                             "atualize o firmware. Se continuar, restaure o roteador de fábrica."),
                references=["https://www.cisa.gov/news-events/alerts/2019/01/22/dns-infrastructure-hijacking-campaign"],
            ))
        bogus = f"tbm-{secrets.token_hex(6)}.com"
        router_nx = await ask_dns(gw, bogus)
        if router_nx and router_nx[0] == 0 and router_nx[1]:
            findings.append(Finding(
                check_id=self.id, host=gw, key="nxdomain", severity=Severity.LOW,
                title="DNS redireciona endereços inexistentes",
                description=("Um nome que não existe recebeu um endereço em vez de 'não encontrado'. Provedores fazem "
                             "isso para mostrar propaganda; atrapalha programas e abre espaço para phishing."),
                evidence=f"{bogus} → {', '.join(sorted(router_nx[1]))}",
                remediation=("Troque o DNS do roteador para 1.1.1.1 / 8.8.8.8 ou desligue a 'página de erro' "
                             "do provedor."),
            ))
        return findings


# ───────────────────────────── visão de fora ─────────────────────────────


async def public_ip(http: httpx.AsyncClient) -> str | None:
    try:
        resp = await http.get("https://1.1.1.1/cdn-cgi/trace", timeout=8)
    except httpx.HTTPError:
        return None
    m = re.search(r"^ip=(\S+)$", resp.text, re.M)
    if not m:
        return None
    try:
        ip = ipaddress.ip_address(m.group(1))
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


@register
class ExternalViewCheck(Check):
    id = "network.external"
    name = "O que a internet vê (Shodan InternetDB)"

    def enabled(self, options) -> bool:
        return super().enabled(options) and options.external

    async def run(self, ctx: CheckContext) -> list[Finding]:
        gw = ctx.scan.gateway
        if not gw:
            return []
        ip = await public_ip(ctx.http)
        if ip is None or ":" in ip:
            return []
        try:
            resp = await ctx.http.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        except httpx.HTTPError:
            return []
        if resp.status_code == 404:
            return []  # o Shodan não viu nada aberto: ótimo
        try:
            data = resp.json()
        except ValueError:
            return []
        ports = sorted(int(p) for p in data.get("ports", []) if str(p).isdigit())
        vulns = [str(v) for v in data.get("vulns", [])][:20]
        findings = []
        note = ("Dados do Shodan, que varre a internet de tempos em tempos (podem ter alguns dias). "
                "Se a sua operadora usa CGNAT, o IP é compartilhado e os dados podem ser de outro cliente.")
        for port in ports:
            findings.append(Finding(
                check_id=self.id, host=gw, key=f"wan:{port}",
                severity=Severity.HIGH if port in RISKY_PORTS else Severity.MEDIUM,
                title=f"Porta {port} visível da internet no seu IP público",
                description=("Qualquer pessoa na internet consegue se conectar a esta porta. Pode ser o próprio "
                             "roteador (página de administração, TR-069) ou um redirecionamento para um aparelho. "
                             + note),
                evidence=f"IP público {ip} · portas vistas: {', '.join(map(str, ports))}",
                remediation=("Na página do roteador, desligue a administração remota e confira 'Redirecionamento de "
                             "portas'/'Virtual Server' e o UPnP. Se a porta for do provedor (ex.: 7547), peça para "
                             "fechar."),
                references=[f"https://www.shodan.io/host/{ip}"],
            ))
        if vulns:
            findings.append(Finding(
                check_id=self.id, host=gw, key="vulns", severity=Severity.HIGH,
                title=f"Shodan associa {len(vulns)} vulnerabilidade(s) ao seu IP público",
                description="O Shodan deduziu CVEs pela versão dos serviços expostos. " + note,
                evidence=", ".join(vulns),
                remediation="Feche as portas expostas e atualize o firmware do roteador e dos aparelhos expostos.",
                references=[f"https://www.shodan.io/host/{ip}"],
            ))
        return findings
