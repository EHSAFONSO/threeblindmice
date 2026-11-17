"""Auditoria de SSH: algoritmos fracos (KEXINIT), Terrapin e métodos de autenticação.

Passivo: logo depois da troca de banners, o servidor manda o SSH_MSG_KEXINIT
em texto claro, com tudo o que ele aceita (kex, hostkey, cifras, MACs). Basta
ler esse pacote; nenhuma autenticação é tentada.

Ativo (--active): com o paramiko, fechamos o key exchange e mandamos um
userauth "none". A resposta lista os métodos aceitos (password, publickey...).
Isso aparece no log do servidor como uma tentativa de login sem credencial.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
import struct
from contextlib import suppress
from dataclasses import dataclass

from tbm import __version__
from tbm.models import Finding, Severity
from tbm.sniffer.base import Check, CheckContext, register

KEXINIT_FIELDS = (
    "kex", "hostkey", "enc_c2s", "enc_s2c", "mac_c2s", "mac_s2c",
    "comp_c2s", "comp_s2c", "lang_c2s", "lang_s2c",
)
SSH_MSG_KEXINIT = 20
CLIENT_BANNER = f"SSH-2.0-threeblindmice_{__version__}\r\n".encode()


class SSHProtocolError(ValueError):
    pass


def parse_kexinit(payload: bytes) -> dict[str, list[str]]:
    """payload = byte msg_type + 16 bytes de cookie + 10 name-lists (uint32 len + ascii)."""
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        raise SSHProtocolError("pacote não é KEXINIT")
    offset = 17
    result: dict[str, list[str]] = {}
    for name in KEXINIT_FIELDS:
        if offset + 4 > len(payload):
            raise SSHProtocolError("KEXINIT truncado")
        (length,) = struct.unpack("!I", payload[offset: offset + 4])
        offset += 4
        raw = payload[offset: offset + length].decode("ascii", "replace")
        offset += length
        result[name] = [x for x in raw.split(",") if x]
    return result


def build_kexinit_payload(lists: dict[str, list[str]]) -> bytes:
    """Inverso do parse; usado nos testes e em servidores falsos."""
    out = bytes([SSH_MSG_KEXINIT]) + b"\x00" * 16
    for name in KEXINIT_FIELDS:
        raw = ",".join(lists.get(name, [])).encode()
        out += struct.pack("!I", len(raw)) + raw
    return out + b"\x00" + b"\x00" * 4  # first_kex_packet_follows + reserved


async def fetch_kexinit(host: str, port: int, timeout: float = 5.0) -> tuple[str, dict[str, list[str]]]:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        banner = ""
        for _ in range(20):  # RFC 4253: o servidor pode mandar linhas antes do banner
            line = await asyncio.wait_for(reader.readline(), timeout)
            if not line:
                raise SSHProtocolError("conexão fechada antes do banner")
            if line.startswith(b"SSH-"):
                banner = line.decode("latin-1").strip()
                break
        else:
            raise SSHProtocolError("banner SSH não encontrado")
        writer.write(CLIENT_BANNER)
        await writer.drain()
        header = await asyncio.wait_for(reader.readexactly(5), timeout)
        packet_len, padding = struct.unpack("!IB", header)
        if not 16 <= packet_len <= 65536:
            raise SSHProtocolError(f"tamanho de pacote inválido: {packet_len}")
        body = await asyncio.wait_for(reader.readexactly(packet_len - 1), timeout)
        return banner, parse_kexinit(body[: packet_len - 1 - padding])
    finally:
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()


@dataclass(frozen=True)
class Weakness:
    field: str
    pattern: re.Pattern[str]


def _rx(p: str) -> re.Pattern[str]:
    return re.compile(p)


WEAK_KEX = _rx(r"(sha1$|group1-|^diffie-hellman-group-exchange-sha1$|^gss-.*sha1)")
WEAK_HOSTKEY = _rx(r"^(ssh-dss|ssh-rsa)$")  # ssh-rsa = assinatura com SHA-1
WEAK_CIPHER = _rx(r"(-cbc$|^arcfour|^3des|^blowfish|^cast128|^none$|^des)")
WEAK_MAC = _rx(r"(^hmac-md5|^hmac-sha1|^umac-64|^hmac-ripemd160|^none$)")


def _weak(values: list[str], pattern: re.Pattern[str]) -> list[str]:
    return [v for v in values if pattern.search(v)]


def terrapin_vulnerable(algos: dict[str, list[str]]) -> bool:
    """CVE-2023-48795: ChaCha20-Poly1305 ou (CBC + EtM), sem o 'strict kex' do servidor."""
    if "kex-strict-s-v00@openssh.com" in algos.get("kex", []):
        return False
    ciphers = algos.get("enc_s2c", []) + algos.get("enc_c2s", [])
    macs = algos.get("mac_s2c", []) + algos.get("mac_c2s", [])
    chacha = "chacha20-poly1305@openssh.com" in ciphers
    cbc_etm = any(c.endswith("-cbc") for c in ciphers) and any("-etm@openssh.com" in m for m in macs)
    return chacha or cbc_etm


def analyze_kexinit(host: str, port: int, algos: dict[str, list[str]]) -> list[Finding]:
    out: list[Finding] = []

    def add(key: str, sev: Severity, title: str, desc: str, items: list[str], fix: str,
            refs: list[str] | None = None) -> None:
        out.append(Finding(check_id="ssh.algorithms", key=key, severity=sev, title=title,
                           host=host, port=port, description=desc,
                           evidence=", ".join(items), remediation=fix, references=refs or []))

    if items := _weak(algos.get("kex", []), WEAK_KEX):
        add("kex", Severity.MEDIUM, "SSH aceita key exchange fraco",
            "Grupos DH de 1024 bits e kex com SHA-1 estão ao alcance de atacantes com recursos "
            "(Logjam).", items,
            "Remova-os em KexAlgorithms; prefira curve25519-sha256 e sntrup761x25519-sha512.")
    if items := _weak(algos.get("hostkey", []), WEAK_HOSTKEY):
        sev = Severity.MEDIUM if "ssh-dss" in items else Severity.LOW
        add("hostkey", sev, "SSH oferece assinaturas de host fracas",
            "ssh-dss (DSA) é obsoleto e ssh-rsa usa SHA-1. O OpenSSH 8.8+ já desativa os dois "
            "por padrão.",
            items, "Use ssh-ed25519 ou rsa-sha2-512/256 em HostKeyAlgorithms.")
    ciphers = sorted(set(_weak(algos.get("enc_s2c", []) + algos.get("enc_c2s", []), WEAK_CIPHER)))
    if ciphers:
        add("ciphers", Severity.MEDIUM, "SSH aceita cifras fracas",
            "Modo CBC, RC4 (arcfour) e 3DES têm ataques conhecidos.", ciphers,
            "Deixe só cifras AEAD/CTR: chacha20-poly1305, aes256-gcm, aes128-gcm e aes*-ctr.")
    macs = sorted(set(_weak(algos.get("mac_s2c", []) + algos.get("mac_c2s", []), WEAK_MAC)))
    if macs:
        add("macs", Severity.LOW, "SSH aceita MACs fracos",
            "MD5 e SHA-1 não são recomendados, e MACs de 64 bits são curtos demais.", macs,
            "Use hmac-sha2-256-etm@openssh.com ou hmac-sha2-512-etm@openssh.com.")
    if terrapin_vulnerable(algos):
        add("terrapin", Severity.MEDIUM, "SSH vulnerável ao Terrapin (CVE-2023-48795)",
            "Um atacante em posição de MITM consegue truncar mensagens do handshake e desativar "
            "proteções (ex.: extensões de keystroke timing).",
            ["sem kex-strict-s-v00@openssh.com"],
            "Atualize para OpenSSH 9.6+ (ou equivalente com 'strict kex'). Como paliativo, "
            "desative chacha20-poly1305 e os MACs *-etm junto com CBC.",
            ["https://terrapin-attack.com", "https://nvd.nist.gov/vuln/detail/CVE-2023-48795"])
    return out


@register
class SSHAlgorithmsCheck(Check):
    id = "ssh.algorithms"
    name = "Algoritmos SSH (KEXINIT) e Terrapin"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        async def one(host, svc) -> list[Finding]:
            try:
                _, algos = await fetch_kexinit(host.address, svc.port)
            except (TimeoutError, OSError, SSHProtocolError, asyncio.IncompleteReadError):
                return []
            return analyze_kexinit(host.address, svc.port, algos)

        results = await asyncio.gather(*(one(h, s) for h, s in ctx.services(lambda s: s.name == "ssh")))
        return [f for batch in results for f in batch]


def ssh_auth_methods(host: str, port: int, timeout: float = 8.0) -> list[str] | None:
    """Faz o kex completo e pergunta quais métodos de auth o servidor aceita.

    Retorna ["none"] se o servidor aceitou login SEM credencial (gravíssimo),
    a lista de métodos se recusou, ou None se não foi possível descobrir.
    """
    import paramiko  # import tardio: só quem usa --active paga o custo

    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    sock = socket.create_connection((host, port), timeout=timeout)
    transport = paramiko.Transport(sock)
    transport.banner_timeout = timeout
    try:
        transport.start_client(timeout=timeout)
        try:
            transport.auth_none("tbm-probe")
            return ["none"]
        except paramiko.BadAuthenticationType as exc:
            return list(exc.allowed_types)
        except paramiko.SSHException:
            return None
    except (paramiko.SSHException, OSError, EOFError):
        return None
    finally:
        transport.close()


@register
class SSHAuthMethodsCheck(Check):
    id = "ssh.auth"
    name = "Métodos de autenticação SSH"
    active_only = True

    async def run(self, ctx: CheckContext) -> list[Finding]:
        async def one(host, svc) -> Finding | None:
            methods = await asyncio.to_thread(ssh_auth_methods, host.address, svc.port)
            if not methods:
                return None
            if methods == ["none"]:
                return Finding(
                    check_id=self.id, key="none", severity=Severity.CRITICAL, host=host.address,
                    port=svc.port, title="SSH aceita login sem credencial",
                    description="O servidor autenticou o método 'none'. Qualquer um entra.",
                    evidence="userauth none → SUCCESS",
                    remediation="Revise o sshd_config (PermitEmptyPasswords no, UsePAM) com urgência.",
                )
            password_like = [m for m in methods if m in ("password", "keyboard-interactive")]
            if not password_like:
                return None
            return Finding(
                check_id=self.id, key="password", severity=Severity.MEDIUM, host=host.address,
                port=svc.port, title="SSH aceita autenticação por senha",
                description="Senhas permitem ataques de força bruta e credential stuffing, que "
                            "são constantes contra qualquer SSH exposto.",
                evidence="Métodos aceitos: " + ", ".join(methods),
                remediation="Use só chaves: PasswordAuthentication no e "
                            "KbdInteractiveAuthentication no. Se precisar de senha, use fail2ban e MFA.",
            )

        results = await asyncio.gather(*(one(h, s) for h, s in ctx.services(lambda s: s.name == "ssh")))
        return [f for f in results if f]
