"""SMB: SMBv1 habilitado e assinatura de pacotes (signing) não obrigatória.

Só fazemos o NEGOTIATE, que é a primeira mensagem de qualquer cliente SMB e
vem antes de qualquer autenticação. Os pacotes são montados à mão com
`struct` (MS-SMB e MS-SMB2), sem dependências.

- SMBv1: oferecemos *apenas* o dialeto "NT LM 0.12". Um servidor com SMBv1
  desligado fecha a conexão; um com SMBv1 ligado responde com \\xffSMB.
- Signing: no NEGOTIATE do SMB2 o servidor informa SecurityMode. O bit 0x02
  indica que a assinatura é obrigatória. Sem ela, ataques de NTLM relay
  ficam viáveis.
"""

from __future__ import annotations

import asyncio
import os
import struct
from contextlib import suppress
from dataclasses import dataclass

from tbm.models import Finding, Severity
from tbm.sniffer.base import Check, CheckContext, register

SMB2_DIALECTS = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}
SIGNING_ENABLED, SIGNING_REQUIRED = 0x01, 0x02


def _netbios(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def smb1_negotiate_request() -> bytes:
    header = struct.pack(
        "<4sBIBHH8sHHHHH",
        b"\xffSMB",
        0x72,  # SMB_COM_NEGOTIATE
        0,  # status
        0x18,  # flags: caseless + canonicalized paths
        0xC001,  # flags2: unicode + NT status + long names
        0,  # PIDHigh
        b"\x00" * 8,  # SecurityFeatures
        0,  # reserved
        0,  # TID
        0xFEFF,  # PIDLow
        0,  # UID
        0,  # MID
    )
    dialects = b"\x02NT LM 0.12\x00"
    body = b"\x00" + struct.pack("<H", len(dialects)) + dialects  # WordCount=0, ByteCount
    return _netbios(header + body)


def smb2_negotiate_request() -> bytes:
    header = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB", 64, 0, 0,
        0,  # command NEGOTIATE
        1,  # credits
        0, 0, 0, 0xFEFF, 0, 0, b"\x00" * 16,
    )
    # Sem 3.1.1: exigiria negotiate contexts (pré-autenticação), irrelevante aqui.
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    body = struct.pack(
        "<HHHHI16sQ", 36, len(dialects), SIGNING_ENABLED, 0, 0, os.urandom(16), 0
    ) + struct.pack(f"<{len(dialects)}H", *dialects)
    return _netbios(header + body)


async def _exchange(host: str, port: int, packet: bytes, timeout: float) -> bytes:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        writer.write(packet)
        await writer.drain()
        nb = await asyncio.wait_for(reader.readexactly(4), timeout)
        length = int.from_bytes(nb[1:], "big")
        return await asyncio.wait_for(reader.readexactly(min(length, 65536)), timeout)
    finally:
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()


def parse_smb1_response(data: bytes) -> bool:
    """True se o servidor aceitou negociar SMBv1."""
    if len(data) < 37 or data[:4] != b"\xffSMB":
        return False
    (status,) = struct.unpack("<I", data[5:9])
    if status != 0:
        return False
    word_count = data[32]
    if word_count == 0:
        return False
    (dialect_index,) = struct.unpack("<H", data[33:35])
    return dialect_index != 0xFFFF


@dataclass
class SMB2Info:
    dialect: str
    signing_enabled: bool
    signing_required: bool


def parse_smb2_response(data: bytes) -> SMB2Info | None:
    if len(data) < 70 or data[:4] != b"\xfeSMB":
        return None
    (status,) = struct.unpack("<I", data[8:12])
    if status != 0:
        return None
    _size, mode, dialect = struct.unpack("<HHH", data[64:70])
    return SMB2Info(
        dialect=SMB2_DIALECTS.get(dialect, hex(dialect)),
        signing_enabled=bool(mode & SIGNING_ENABLED),
        signing_required=bool(mode & SIGNING_REQUIRED),
    )


async def probe_smb(host: str, port: int = 445, timeout: float = 4.0) -> tuple[bool, SMB2Info | None]:
    smb1 = False
    with suppress(TimeoutError, OSError, asyncio.IncompleteReadError):
        smb1 = parse_smb1_response(await _exchange(host, port, smb1_negotiate_request(), timeout))
    smb2 = None
    with suppress(TimeoutError, OSError, asyncio.IncompleteReadError):
        smb2 = parse_smb2_response(await _exchange(host, port, smb2_negotiate_request(), timeout))
    return smb1, smb2


@register
class SMBCheck(Check):
    id = "smb.negotiate"
    name = "SMBv1 e assinatura SMB"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        async def one(host, svc) -> list[Finding]:
            smb1, smb2 = await probe_smb(host.address, svc.port)
            out = []
            if smb2:
                svc.extra["smb_dialect"] = smb2.dialect
            if smb1:
                out.append(Finding(
                    check_id=self.id, key="smbv1", severity=Severity.HIGH, host=host.address,
                    port=svc.port, title="SMBv1 habilitado",
                    description="O SMBv1 é o protocolo explorado pelo EternalBlue (WannaCry, "
                                "NotPetya). A Microsoft o considera obsoleto desde 2014.",
                    evidence="Servidor aceitou o dialeto 'NT LM 0.12'",
                    remediation="Windows: Disable-WindowsOptionalFeature -Online -FeatureName "
                                "SMB1Protocol. Samba: server min protocol = SMB2.",
                    references=["https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"],
                ))
            if smb2 and not smb2.signing_required:
                out.append(Finding(
                    check_id=self.id, key="signing", severity=Severity.MEDIUM, host=host.address,
                    port=svc.port, title="Assinatura SMB não é obrigatória",
                    description="Sem signing obrigatório, um atacante na rede pode retransmitir "
                                "autenticações NTLM capturadas (NTLM relay) para este servidor.",
                    evidence=f"SMB {smb2.dialect} · signing "
                             f"{'habilitado' if smb2.signing_enabled else 'desabilitado'}, não exigido",
                    remediation="GPO: 'Microsoft network server: Digitally sign communications "
                                "(always)' = Enabled. Samba: server signing = mandatory.",
                ))
            return out

        results = await asyncio.gather(
            *(one(h, s) for h, s in ctx.services(lambda s: s.port in (445, 139) and s.name != "netbios-ssn"))
        )
        return [f for batch in results for f in batch]
