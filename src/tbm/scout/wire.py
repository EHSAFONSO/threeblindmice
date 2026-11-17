"""Codificação e decodificação mínimas de protocolos binários (DNS e SNMP/BER).

Implementado à mão de propósito: são formatos pequenos e é um ótimo exercício
para entender como os pacotes são de verdade, sem depender de dnspython/pysnmp.
"""

from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass, field

# ───────────────────────────── DNS (RFC 1035) ─────────────────────────────

TYPE_A, TYPE_PTR = 1, 12
CLASS_IN = 1


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if label else b""
        if len(raw) > 63:
            raise ValueError(f"label DNS longo demais: {label}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name: str, qtype: int, *, recursion: bool = True, txid: int | None = None) -> bytes:
    txid = secrets.randbelow(0xFFFF) if txid is None else txid
    flags = 0x0100 if recursion else 0x0000  # bit RD
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", qtype, CLASS_IN)


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Lê um nome com suporte a ponteiros de compressão. Retorna (nome, próximo offset)."""
    labels: list[str] = []
    jumped = False
    end = offset
    hops = 0
    while True:
        if offset >= len(data):
            raise ValueError("nome DNS truncado")
        length = data[offset]
        if length & 0xC0 == 0xC0:  # ponteiro de 14 bits
            if offset + 1 >= len(data):
                raise ValueError("ponteiro DNS truncado")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset, jumped = pointer, True
            hops += 1
            if hops > 32:
                raise ValueError("loop de compressão DNS")
            continue
        if length == 0:
            if not jumped:
                end = offset + 1
            return ".".join(labels), end
        labels.append(data[offset + 1: offset + 1 + length].decode("utf-8", "replace"))
        offset += 1 + length


@dataclass
class DNSRecord:
    name: str
    rtype: int
    data: bytes
    rdata_offset: int


@dataclass
class DNSResponse:
    txid: int
    flags: int
    answers: list[DNSRecord] = field(default_factory=list)
    raw: bytes = b""

    @property
    def recursion_available(self) -> bool:
        return bool(self.flags & 0x0080)

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F

    def ptr_targets(self) -> list[str]:
        return [decode_name(self.raw, r.rdata_offset)[0] for r in self.answers if r.rtype == TYPE_PTR]


def parse_response(data: bytes) -> DNSResponse:
    if len(data) < 12:
        raise ValueError("resposta DNS curta demais")
    txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    if not flags & 0x8000:
        raise ValueError("não é uma resposta DNS (bit QR zerado)")
    offset = 12
    for _ in range(qd):
        _, offset = decode_name(data, offset)
        offset += 4
    resp = DNSResponse(txid=txid, flags=flags, raw=data)
    for _ in range(an):
        name, offset = decode_name(data, offset)
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[offset: offset + 10])
        offset += 10
        resp.answers.append(DNSRecord(name, rtype, data[offset: offset + rdlen], offset))
        offset += rdlen
    return resp


# ───────────────────────────── SNMP / ASN.1 BER ─────────────────────────────

SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def ber_int(value: int) -> bytes:
    body = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True)
    return tlv(0x02, body)


def ber_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.insert(0, 0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(chunk)
    return tlv(0x06, body)


def snmp_get(community: str, oid: str = SYS_DESCR_OID, request_id: int = 0x7B6D) -> bytes:
    """SNMPv1 GetRequest: SEQUENCE { versão, community, GetRequest-PDU }."""
    varbind = tlv(0x30, ber_oid(oid) + b"\x05\x00")  # OID + NULL
    pdu = tlv(0xA0, ber_int(request_id) + ber_int(0) + ber_int(0) + tlv(0x30, varbind))
    return tlv(0x30, ber_int(0) + tlv(0x04, community.encode()) + pdu)


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[offset: offset + n], "big")
        offset += n
    return tag, data[offset: offset + length], offset + length


def snmp_response_value(data: bytes, oid: str = SYS_DESCR_OID) -> str | None:
    """Procura o OID na resposta e devolve a OCTET STRING que vem logo depois."""
    encoded = ber_oid(oid)
    idx = data.find(encoded)
    if idx < 0:
        return None
    try:
        tag, value, _ = _read_tlv(data, idx + len(encoded))
    except IndexError:
        return None
    if tag != 0x04:  # noSuchObject etc.
        return None
    return value.decode("utf-8", "replace")
