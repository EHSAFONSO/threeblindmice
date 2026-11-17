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


class ParseError(ValueError):
    """Pacote malformado. Os parsers só levantam isto, seja qual for a entrada."""


def build_query(name: str, qtype: int, *, recursion: bool = True, txid: int | None = None) -> bytes:
    return build_multi_query([name], qtype, recursion=recursion, txid=txid)


def build_multi_query(
    names: list[str], qtype: int, *, recursion: bool = False, txid: int | None = None,
    unicast_response: bool = False,
) -> bytes:
    """Várias perguntas num pacote. Com `unicast_response`, liga o bit QU (RFC 6762 §5.4):
    em mDNS, isso pede que os aparelhos respondam direto para nós, não para o grupo."""
    txid = secrets.randbelow(0xFFFF) if txid is None else txid
    flags = 0x0100 if recursion else 0x0000  # bit RD
    qclass = CLASS_IN | (0x8000 if unicast_response else 0)
    header = struct.pack("!HHHHHH", txid, flags, len(names), 0, 0, 0)
    return header + b"".join(encode_name(n) + struct.pack("!HH", qtype, qclass) for n in names)


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Lê um nome com suporte a ponteiros de compressão. Retorna (nome, próximo offset)."""
    labels: list[str] = []
    jumped = False
    end = offset
    hops = 0
    while True:
        if offset >= len(data):
            raise ParseError("nome DNS truncado")
        length = data[offset]
        if length & 0xC0 == 0xC0:  # ponteiro de 14 bits
            if offset + 1 >= len(data):
                raise ParseError("ponteiro DNS truncado")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset, jumped = pointer, True
            hops += 1
            if hops > 32:
                raise ParseError("loop de compressão DNS")
            continue
        if length & 0xC0:  # 0x40/0x80: tipos de label reservados
            raise ParseError("tipo de label DNS inválido")
        if length == 0:
            if not jumped:
                end = offset + 1
            return ".".join(labels), end
        if offset + 1 + length > len(data):
            raise ParseError("label DNS truncado")
        labels.append(data[offset + 1: offset + 1 + length].decode("utf-8", "replace"))
        offset += 1 + length
        if len(labels) > 128:
            raise ParseError("nome DNS longo demais")


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
    # authority + additional: no mDNS é aqui que vêm os registros A (nome → IP)
    extra: list[DNSRecord] = field(default_factory=list)
    raw: bytes = b""

    @property
    def recursion_available(self) -> bool:
        return bool(self.flags & 0x0080)

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F

    @property
    def records(self) -> list[DNSRecord]:
        return self.answers + self.extra

    def ptr_targets(self) -> list[str]:
        out = []
        for r in self.answers:
            if r.rtype == TYPE_PTR:
                try:
                    out.append(decode_name(self.raw, r.rdata_offset)[0])
                except ValueError:
                    continue
        return out

    def a_records(self) -> dict[str, str]:
        """nome → IPv4, de todas as seções."""
        return {r.name: ".".join(str(b) for b in r.data) for r in self.records
                if r.rtype == TYPE_A and len(r.data) == 4}


def _parse_records(data: bytes, offset: int, count: int) -> tuple[list[DNSRecord], int]:
    records = []
    for _ in range(count):
        name, offset = decode_name(data, offset)
        if offset + 10 > len(data):
            raise ParseError("registro DNS truncado")
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[offset: offset + 10])
        offset += 10
        if offset + rdlen > len(data):
            raise ParseError("rdata DNS truncado")
        records.append(DNSRecord(name, rtype, data[offset: offset + rdlen], offset))
        offset += rdlen
    return records, offset


def parse_response(data: bytes) -> DNSResponse:
    """Interpreta uma resposta DNS/mDNS. Entrada não confiável: só levanta ParseError."""
    try:
        if len(data) < 12:
            raise ParseError("resposta DNS curta demais")
        txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        if not flags & 0x8000:
            raise ParseError("não é uma resposta DNS (bit QR zerado)")
        offset = 12
        for _ in range(qd):
            _, offset = decode_name(data, offset)
            offset += 4
        resp = DNSResponse(txid=txid, flags=flags, raw=data)
        resp.answers, offset = _parse_records(data, offset, an)
        authority, offset = _parse_records(data, offset, ns)
        additional, _ = _parse_records(data, offset, ar)
        resp.extra = authority + additional
        return resp
    except ParseError:
        raise
    except (ValueError, struct.error, IndexError) as exc:
        raise ParseError(str(exc)) from exc


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
    if offset + 2 > len(data):
        raise ParseError("TLV truncado")
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or offset + n > len(data):
            raise ParseError("tamanho BER inválido")
        length = int.from_bytes(data[offset: offset + n], "big")
        offset += n
    if offset + length > len(data):
        raise ParseError("valor BER truncado")
    return tag, data[offset: offset + length], offset + length


def snmp_response_value(data: bytes, oid: str = SYS_DESCR_OID) -> str | None:
    """Procura o OID na resposta e devolve a OCTET STRING que vem logo depois."""
    encoded = ber_oid(oid)
    idx = data.find(encoded)
    if idx < 0:
        return None
    try:
        tag, value, _ = _read_tlv(data, idx + len(encoded))
    except ParseError:
        return None
    if tag != 0x04:  # noSuchObject etc.
        return None
    return value.decode("utf-8", "replace")
