"""Banner grabbing e fingerprint de serviços.

Estratégia por porta:
1. Portas HTTP: manda um GET imediatamente.
2. Demais: espera o servidor falar primeiro (SSH, FTP, SMTP, MySQL...);
   se ele ficar calado, manda uma sonda.
3. Se a resposta em texto puro for vazia ou parecer um alerta TLS, tenta de
   novo com TLS: pega HTTPS em portas não padrão.
"""

from __future__ import annotations

import asyncio
import re
import ssl
from contextlib import suppress
from dataclasses import dataclass, field

from tbm import USER_AGENT
from tbm.models import Service, TLSInfo
from tbm.scout.ports import HTTP_PORTS, SERVICE_NAMES, TLS_PORTS
from tbm.scout.tls import insecure_context, probe_legacy_protocols, tls_info_from_ssl_object


@dataclass(frozen=True)
class Signature:
    service: str
    pattern: re.Pattern[str]
    product: str | None = None


def _sig(service: str, pattern: str, product: str | None = None) -> Signature:
    return Signature(service, re.compile(pattern, re.IGNORECASE | re.MULTILINE), product)


# A ordem importa: a primeira assinatura que bater vence.
# Se o padrão tem um grupo de captura, ele é a versão.
SIGNATURES: tuple[Signature, ...] = (
    _sig("ssh", r"^SSH-[\d.]+-OpenSSH_([\w.]+)", "OpenSSH"),
    _sig("ssh", r"^SSH-[\d.]+-dropbear_([\w.]+)", "Dropbear SSH"),
    _sig("ssh", r"^SSH-[\d.]+-"),
    _sig("ftp", r"^220.*vsFTPd ([\d.]+)", "vsftpd"),
    _sig("ftp", r"^220.*ProFTPD ([\d.]+)", "ProFTPD"),
    _sig("ftp", r"^220.*FileZilla Server(?: version)? ([\d.]+)", "FileZilla Server"),
    _sig("smtp", r"^220.*ESMTP Postfix", "Postfix"),
    _sig("smtp", r"^220.*Exim ([\d.]+)", "Exim"),
    _sig("smtp", r"^220.*E?SMTP"),
    _sig("ftp", r"^220[ -].*FTP"),
    _sig("redis", r"redis_version:([\d.]+)", "Redis"),
    _sig("redis", r"^-NOAUTH", "Redis"),
    _sig("vnc", r"^RFB (\d{3}\.\d{3})", "VNC"),
    _sig("pop3", r"^\+OK"),
    _sig("imap", r"^\* OK"),
)

HTTP_SERVER_SIGNATURES: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(p, re.IGNORECASE), product)
    for p, product in (
        (r"nginx/([\d.]+)", "nginx"),
        (r"openresty/([\d.]+)", "OpenResty"),
        (r"Apache/([\d.]+)", "Apache httpd"),
        (r"Microsoft-IIS/([\d.]+)", "Microsoft IIS"),
        (r"lighttpd/([\d.]+)", "lighttpd"),
        (r"Jetty\(([\d.]+)", "Jetty"),
        (r"(?:^|\s)Caddy", "Caddy"),
        (r"(?:^|\s)nginx", "nginx"),
        (r"(?:^|\s)Apache", "Apache httpd"),
    )
)

_SERVER_HEADER = re.compile(r"^server:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_TITLE = re.compile(r"<title[^>]*>([^<]{1,200})</title>", re.IGNORECASE)


@dataclass
class Identification:
    name: str | None
    product: str | None = None
    version: str | None = None
    extra: dict[str, str] = field(default_factory=dict)


def _mysql_greeting(data: bytes) -> str | None:
    """Handshake v10 do MySQL: 3 bytes de tamanho, 1 de seq, 0x0a, versão terminada em \\0."""
    if len(data) > 6 and data[4] == 0x0A:
        end = data.find(b"\x00", 5)
        if end > 5:
            version = data[5:end].decode("ascii", "replace")
            if re.match(r"^\d+\.\d+", version):
                return version
    return None


def identify(port: int, data: bytes, tls: bool) -> Identification:
    text = data.decode("latin-1", errors="replace")
    ident = Identification(name=SERVICE_NAMES.get(port))

    if len(data) >= 3 and data[0] == 0xFF and data[1] in (0xFB, 0xFC, 0xFD, 0xFE):
        ident.name = "telnet"
        return ident

    if mysql_version := _mysql_greeting(data):
        ident.name = "mysql"
        ident.product = "MariaDB" if "mariadb" in mysql_version.lower() else "MySQL"
        ident.version = re.match(r"[\d.]+", mysql_version).group(0)  # type: ignore[union-attr]
        return ident

    if text.startswith("HTTP/"):
        ident.name = "https" if tls else "http"
        if m := _TITLE.search(text):
            ident.extra["title"] = " ".join(m.group(1).split())[:120]
        if m := _SERVER_HEADER.search(text):
            server = m.group(1)
            ident.extra["server"] = server
            for pattern, product in HTTP_SERVER_SIGNATURES:
                if pm := pattern.search(server):
                    ident.product = product
                    ident.version = pm.group(1) if pm.groups() else None
                    break
        return ident

    for sig in SIGNATURES:
        if m := sig.pattern.search(text):
            ident.name = sig.service
            ident.product = sig.product
            ident.version = m.group(1) if m.groups() else None
            break

    if ident.name == "redis":
        if "redis_version" in text:
            ident.extra["auth"] = "none"
        elif "NOAUTH" in text:
            ident.extra["auth"] = "required"
    if ident.name == "ssh" and re.match(r"^SSH-1\.(?!99)", text):
        ident.extra["ssh_protocol"] = "1"

    if tls and ident.name in (None, "http"):
        ident.name = "https"
    return ident


def _probe_for(port: int, host: str, tls: bool) -> bytes:
    if port == 6379:
        return b"INFO server\r\n"
    if tls or port in HTTP_PORTS:
        return (
            f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        ).encode()
    return b"\r\n"


async def _read(reader: asyncio.StreamReader, timeout: float, limit: int = 4096) -> bytes:
    buf = b""
    with suppress(TimeoutError, ConnectionError, OSError, ssl.SSLError):
        while len(buf) < limit:
            chunk = await asyncio.wait_for(reader.read(limit - len(buf)), timeout)
            if not chunk:
                break
            buf += chunk
            timeout = min(timeout, 0.3)  # depois do 1º pedaço, só esperamos o resto
    return buf


async def _exchange(
    host: str, port: int, timeout: float, ctx: ssl.SSLContext | None, sni: str | None
) -> tuple[bytes, TLSInfo | None]:
    connect_timeout = max(timeout, 3.0) if ctx else timeout
    kwargs = {"ssl": ctx, "server_hostname": sni} if ctx and sni else {"ssl": ctx}
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, **kwargs), connect_timeout
    )
    try:
        sslobj = writer.get_extra_info("ssl_object")
        tls_info = tls_info_from_ssl_object(sslobj) if sslobj else None
        data = b""
        speaks_first = port not in HTTP_PORTS and port != 6379
        if speaks_first:
            # Quem fala primeiro (SSH, FTP, SMTP, MySQL) responde em milissegundos.
            data = await _read(reader, min(timeout, 1.5))
        if not data:
            writer.write(_probe_for(port, sni or host, ctx is not None))
            await writer.drain()
            data = await _read(reader, timeout)
        return data, tls_info
    finally:
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()


_TEXT_BYTES = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def _clean_banner(data: bytes, limit: int = 400) -> str | None:
    """Banner legível. Só ASCII imprimível passa: bytes Latin-1 como '¼æ' são
    "imprimíveis" para o Python, mas são lixo binário (ex.: o KEXINIT do SSH)."""
    if not data:
        return None
    text = "".join(chr(b) if b in _TEXT_BYTES else "." for b in data[:limit])
    return text.strip() or None


def _protocol_banner(name: str | None, data: bytes) -> bytes:
    """Protocolos que mandam binário logo depois da linha de texto: guardamos só a linha."""
    if name == "ssh":
        return data.split(b"\n", 1)[0]
    return data


def _needs_tls_retry(data: bytes) -> bool:
    return not data or data[:1] == b"\x15" or b"HTTPS port" in data or b"https://" in data[:300]


# Protocolos binários que nunca mandam banner de texto nem falam TLS direto.
# Sondar essas portas custava ~9s cada (espera passiva + sonda + tentativa TLS)
# sem ganhar nada; quem analisa SMB/RDP de verdade são os checks do Sniffer.
BINARY_PORTS = frozenset({88, 111, 135, 139, 445, 2049, 3389, 5357, 62078})


async def grab_service(
    host: str, port: int, *, hostname: str | None, timeout: float, legacy_tls: bool
) -> Service:
    if port in BINARY_PORTS:
        return Service(port=port, name=SERVICE_NAMES.get(port))

    data: bytes = b""
    tls: TLSInfo | None = None
    first_try_tls = port in TLS_PORTS
    # Importante contra DNS rebinding: conectamos sempre no IP já validado
    # pelo escopo. O hostname só vai no SNI/Host, nunca é resolvido de novo.
    with suppress(TimeoutError, OSError, ssl.SSLError):
        data, tls = await _exchange(
            host, port, timeout, insecure_context() if first_try_tls else None, hostname
        )

    if not first_try_tls and _needs_tls_retry(data):
        with suppress(TimeoutError, OSError, ssl.SSLError):
            tls_data, tls_info = await _exchange(host, port, timeout, insecure_context(), hostname)
            if tls_info is not None:
                data, tls = tls_data, tls_info

    if tls is not None and legacy_tls:
        tls.legacy_protocols, tls.legacy_untestable = await probe_legacy_protocols(
            host, port, timeout
        )

    ident = identify(port, data, tls is not None)
    return Service(
        port=port,
        name=ident.name,
        product=ident.product,
        version=ident.version,
        banner=_clean_banner(_protocol_banner(ident.name, data)),
        tls=tls,
        extra=ident.extra,
    )
