"""Checks de exposição de serviços, baseados no que o Scout encontrou."""

from __future__ import annotations

import asyncio
import re
from contextlib import suppress
from typing import NamedTuple

from tbm.models import Finding, Severity
from tbm.sniffer.base import Check, CheckContext, register


class Exposure(NamedTuple):
    severity: Severity
    title: str
    description: str
    remediation: str


_DB_FIX = "Faça bind só em localhost/rede interna, exija autenticação forte e filtre no firewall."

EXPOSURES: dict[int, Exposure] = {
    23: Exposure(Severity.HIGH, "Telnet exposto",
                 "O Telnet transmite credenciais e toda a sessão em texto puro.",
                 "Desative o Telnet e use SSH."),
    21: Exposure(Severity.MEDIUM, "FTP sem criptografia",
                 "O FTP envia usuário e senha em texto claro pela rede.",
                 "Migre para SFTP/FTPS ou desative o serviço."),
    445: Exposure(Severity.MEDIUM, "SMB exposto",
                  "O SMB é alvo histórico de worms e ransomware (ex.: EternalBlue/WannaCry).",
                  "Restrinja o SMB às máquinas que precisam dele, desative o SMBv1 e mantenha os "
                  "patches em dia."),
    139: Exposure(Severity.LOW, "NetBIOS exposto",
                  "O NetBIOS vaza nomes de máquina e de domínio e amplia a superfície do SMB.",
                  "Desative o NetBIOS sobre TCP/IP se não for necessário."),
    3389: Exposure(Severity.MEDIUM, "RDP exposto",
                   "O RDP é alvo constante de força bruta e já teve falhas críticas (BlueKeep).",
                   "Exija NLA, coloque o RDP atrás de VPN ou gateway e ative MFA."),
    5900: Exposure(Severity.MEDIUM, "VNC exposto",
                   "O VNC costuma ter autenticação fraca e tráfego sem criptografia.",
                   "Use o VNC só por túnel SSH ou VPN, com senha forte."),
    2375: Exposure(Severity.CRITICAL, "API do Docker sem TLS",
                   "A porta 2375 expõe a API do Docker sem autenticação: quem acessa vira root "
                   "no host.",
                   "Feche a porta ou use 2376 com TLS mútuo."),
    5555: Exposure(Severity.CRITICAL, "Android Debug Bridge (ADB) exposto",
                   "Com o ADB aberto na rede, qualquer um instala apps e executa comandos no "
                   "dispositivo.",
                   "Desative a depuração por rede no dispositivo."),
    11211: Exposure(Severity.HIGH, "Memcached exposto",
                    "O Memcached não tem autenticação e já foi usado em ataques DDoS de "
                    "amplificação.",
                    _DB_FIX),
    9200: Exposure(Severity.MEDIUM, "Elasticsearch exposto",
                   "Instâncias abertas do Elasticsearch são uma das maiores fontes de vazamento "
                   "de dados.",
                   _DB_FIX),
    27017: Exposure(Severity.MEDIUM, "MongoDB exposto", "Banco de dados acessível pela rede.",
                    _DB_FIX),
    3306: Exposure(Severity.MEDIUM, "MySQL/MariaDB exposto", "Banco de dados acessível pela rede.",
                   _DB_FIX),
    5432: Exposure(Severity.MEDIUM, "PostgreSQL exposto", "Banco de dados acessível pela rede.",
                   _DB_FIX),
    1433: Exposure(Severity.MEDIUM, "MS SQL Server exposto",
                   "Banco de dados acessível pela rede.", _DB_FIX),
    6379: Exposure(Severity.MEDIUM, "Redis exposto", "Banco de dados acessível pela rede.",
                   _DB_FIX),
    5984: Exposure(Severity.MEDIUM, "CouchDB exposto", "Banco de dados acessível pela rede.",
                   _DB_FIX),
    1883: Exposure(Severity.MEDIUM, "MQTT sem TLS",
                   "Brokers MQTT abertos permitem ler e injetar comandos em dispositivos IoT.",
                   "Exija autenticação e use MQTT sobre TLS (8883)."),
    873: Exposure(Severity.MEDIUM, "rsync exposto",
                  "Módulos rsync sem senha permitem baixar ou sobrescrever arquivos.",
                  "Exija autenticação no rsyncd ou feche a porta."),
    2049: Exposure(Severity.MEDIUM, "NFS exposto",
                   "Exports NFS mal configurados expõem sistemas de arquivos inteiros.",
                   "Restrinja os exports por IP e use root_squash."),
    7547: Exposure(Severity.MEDIUM, "TR-069 (CWMP) exposto",
                   "É a interface de gerência remota de roteadores e já foi explorada em massa "
                   "(Mirai).",
                   "Peça ao provedor para restringir o acesso ou desative o serviço, se possível."),
    8009: Exposure(Severity.MEDIUM, "Tomcat AJP exposto",
                   "O conector AJP aberto pode permitir a leitura de arquivos (Ghostcat, "
                   "CVE-2020-1938).",
                   "Desative o AJP ou faça bind em localhost com 'secret' configurado."),
}


@register
class ExposedServicesCheck(Check):
    id = "service.exposed"
    name = "Serviços de risco expostos"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        findings = []
        for host, svc in ctx.services():
            exp = EXPOSURES.get(svc.port)
            if exp is None:
                continue
            # 2375 com TLS de verdade não é o cenário "sem TLS"
            if svc.port == 2375 and svc.tls is not None:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=exp.title,
                    severity=exp.severity,
                    host=host.address,
                    port=svc.port,
                    description=exp.description,
                    evidence=f"Porta {svc.port}/tcp aberta ({svc.label})",
                    remediation=exp.remediation,
                )
            )
        return findings


@register
class BannerWeaknessCheck(Check):
    id = "service.banner"
    name = "Fraquezas visíveis no banner"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        findings = []
        for host, svc in ctx.services():
            if svc.name == "redis" and svc.extra.get("auth") == "none":
                findings.append(Finding(
                    check_id=self.id, key="redis-noauth", severity=Severity.CRITICAL,
                    title="Redis sem autenticação", host=host.address, port=svc.port,
                    description="O Redis respondeu ao comando INFO sem pedir senha. Um atacante "
                                "pode ler e alterar dados e, com CONFIG SET, frequentemente "
                                "executar código no servidor.",
                    evidence=(svc.banner or "")[:200],
                    remediation="Configure 'requirepass' ou ACLs, ative o 'protected-mode' e "
                                "faça bind em localhost.",
                ))
            if svc.extra.get("ssh_protocol") == "1":
                findings.append(Finding(
                    check_id=self.id, key="sshv1", severity=Severity.HIGH,
                    title="SSH protocolo 1 habilitado", host=host.address, port=svc.port,
                    description="O SSHv1 tem falhas criptográficas conhecidas e está obsoleto "
                                "há mais de 20 anos.",
                    evidence=svc.banner or "",
                    remediation="Use apenas o 'Protocol 2' no sshd_config ou atualize o servidor.",
                ))
        return findings


_REPLY = re.compile(rb"^(\d{3}) ", re.MULTILINE)


async def _ftp_reply(reader: asyncio.StreamReader, timeout: float) -> int | None:
    """Lê uma resposta FTP (possivelmente multilinha '220-...') e devolve o código."""
    buf = b""
    while len(buf) < 8192:
        line = await asyncio.wait_for(reader.readline(), timeout)
        if not line:
            return None
        buf += line
        if m := _REPLY.match(line):
            return int(m.group(1))
    return None


async def ftp_allows_anonymous(host: str, port: int, timeout: float = 5.0) -> bool:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        if await _ftp_reply(reader, timeout) != 220:
            return False
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        code = await _ftp_reply(reader, timeout)
        if code == 230:
            return True
        if code != 331:
            return False
        writer.write(b"PASS tbm@example.invalid\r\n")
        await writer.drain()
        return await _ftp_reply(reader, timeout) == 230
    finally:
        with suppress(Exception):
            writer.write(b"QUIT\r\n")
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()


@register
class AnonymousFTPCheck(Check):
    id = "service.ftp-anon"
    name = "FTP com login anônimo"
    active_only = True

    async def run(self, ctx: CheckContext) -> list[Finding]:
        targets = list(ctx.services(lambda s: s.name == "ftp" and s.tls is None))

        async def one(host, svc) -> Finding | None:
            # Servidores FTP às vezes demoram a mandar o 220 (fork, DNS reverso, carga).
            # Uma segunda tentativa evita falso negativo por um timeout isolado.
            allowed = False
            for _ in range(2):
                try:
                    allowed = await ftp_allows_anonymous(host.address, svc.port)
                    break
                except (TimeoutError, OSError, asyncio.IncompleteReadError):
                    continue
            if not allowed:
                return None
            return Finding(
                check_id=self.id, severity=Severity.HIGH, title="FTP aceita login anônimo",
                host=host.address, port=svc.port,
                description="O servidor aceitou USER anonymous. Dependendo das permissões, "
                            "qualquer pessoa pode listar, baixar ou enviar arquivos.",
                evidence="USER anonymous -> 230 Login successful",
                remediation="Desative o acesso anônimo (no vsftpd: anonymous_enable=NO).",
            )

        results = await asyncio.gather(*(one(h, s) for h, s in targets))
        return [f for f in results if f]
