"""Nome do aparelho quando o DNS reverso não sabe: NetBIOS e LLMNR.

Em casa, o roteador raramente registra nomes no DNS. Mas PCs Windows, Samba
(NAS, TVs) e muitos IoT respondem a duas perguntas diretas, por UDP unicast:

- NetBIOS "node status" (NBSTAT, RFC 1002 §4.2.18), porta 137: o aparelho
  devolve a lista de nomes que registrou. O nome com sufixo 0x00 e sem a flag
  de grupo é o nome da máquina ("DESKTOP-ABC123").
- LLMNR (RFC 4795), porta 5355: um DNS local; a pergunta PTR
  "<ip invertido>.in-addr.arpa" devolve o nome do host.

Só perguntas de leitura, endereçadas ao próprio aparelho (nada de multicast
para a rede inteira). Os pacotes de resposta vêm da rede e são tratados como
hostis: limites de tamanho e nenhum parser que confie em comprimentos.
"""

from __future__ import annotations

import asyncio
import secrets
import struct

from tbm.scout import wire
from tbm.scout.udp import udp_exchange

NBNS_PORT = 137
LLMNR_PORT = 5355
_NAME_FLAG_GROUP = 0x8000


def nbstat_query(txid: int | None = None) -> bytes:
    txid = secrets.randbelow(0xFFFF) if txid is None else txid
    header = struct.pack("!HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    # Nome "*" (curinga), codificado em "first-level encoding": cada byte vira 2 letras.
    raw = b"*" + b"\x00" * 15
    encoded = bytes(c for b in raw for c in (ord("A") + (b >> 4), ord("A") + (b & 0x0F)))
    question = bytes([32]) + encoded + b"\x00" + struct.pack("!HH", 0x0021, 0x0001)  # NBSTAT, IN
    return header + question


def parse_nbstat(data: bytes) -> str | None:
    """Nome da máquina numa resposta NBSTAT, ou None."""
    try:
        if len(data) < 12 or struct.unpack("!H", data[6:8])[0] < 1:
            return None
        offset = 12
        # nome da resposta: rótulos até o zero (é o "*" que perguntamos)
        while offset < len(data) and data[offset] != 0:
            offset += 1 + data[offset]
        offset += 1 + 2 + 2 + 4 + 2  # zero, tipo, classe, TTL, RDLENGTH
        count = data[offset]
        offset += 1
        names = []
        for _ in range(min(count, 64)):
            entry = data[offset:offset + 18]
            if len(entry) < 18:
                break
            name = entry[:15].decode("ascii", errors="ignore").rstrip(" \x00")
            suffix = entry[15]
            flags = struct.unpack("!H", entry[16:18])[0]
            names.append((name, suffix, flags))
            offset += 18
    except (IndexError, struct.error):
        return None
    for name, suffix, flags in names:
        if suffix == 0x00 and not flags & _NAME_FLAG_GROUP and _printable(name):
            return name
    return None


def _printable(name: str) -> bool:
    return bool(name) and all(32 < ord(c) < 127 for c in name)


def reverse_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def parse_llmnr_ptr(data: bytes) -> str | None:
    try:
        response = wire.parse_response(data)
    except wire.ParseError:
        return None
    targets = [t.rstrip(".") for t in response.ptr_targets() if t]
    return targets[0] if targets else None


async def netbios_name(ip: str, timeout: float = 1.0) -> str | None:
    data = await udp_exchange(ip, NBNS_PORT, nbstat_query(), timeout)
    return parse_nbstat(data[:2048]) if data else None


async def llmnr_name(ip: str, timeout: float = 1.0) -> str | None:
    query = wire.build_query(reverse_name(ip), wire.TYPE_PTR, recursion=False)
    data = await udp_exchange(ip, LLMNR_PORT, query, timeout)
    return parse_llmnr_ptr(data[:2048]) if data else None


async def local_name(ip: str, timeout: float = 1.0) -> tuple[str, str] | None:
    """(nome, protocolo) pelo primeiro que responder. As duas perguntas saem juntas."""
    if ":" in ip:
        return None
    nb, ll = await asyncio.gather(netbios_name(ip, timeout), llmnr_name(ip, timeout))
    if nb:
        return nb, "netbios"
    if ll:
        return ll, "llmnr"
    return None
