"""Coleta de informações TLS: certificado, protocolo, cifra e protocolos legados."""

from __future__ import annotations

import asyncio
import ssl
from contextlib import suppress
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID

from tbm.models import TLSInfo


def insecure_context(
    minimum: ssl.TLSVersion | None = None, maximum: ssl.TLSVersion | None = None
) -> ssl.SSLContext:
    """Contexto que aceita *qualquer* certificado.

    Aqui isso é intencional: queremos inspecionar certificados ruins
    (autoassinados, expirados), não confiar neles. Nunca use este contexto
    para trafegar dados de verdade.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with suppress(ssl.SSLError):
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    if minimum is not None:
        ctx.minimum_version = minimum
    if maximum is not None:
        ctx.maximum_version = maximum
    return ctx


def _key_info(cert: x509.Certificate) -> tuple[str | None, int | None]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC ({key.curve.name})", key.curve.key_size
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456
    return type(key).__name__, None


def parse_certificate(der: bytes) -> TLSInfo:
    cert = x509.load_der_x509_certificate(der)
    sans: list[str] = []
    with suppress(x509.ExtensionNotFound):
        ext = cast(
            x509.SubjectAlternativeName,
            cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value,
        )
        sans = [*ext.get_values_for_type(x509.DNSName)]
        sans += [str(ip) for ip in ext.get_values_for_type(x509.IPAddress)]

    try:
        hash_alg = cert.signature_hash_algorithm
        sig = hash_alg.name if hash_alg else cert.signature_algorithm_oid._name
    except Exception:  # algoritmos que a lib não reconhece
        sig = cert.signature_algorithm_oid.dotted_string

    key_type, key_bits = _key_info(cert)
    return TLSInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        sans=sans,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        key_type=key_type,
        key_bits=key_bits,
        signature_algorithm=sig,
        self_signed=cert.issuer == cert.subject,
    )


def tls_info_from_ssl_object(sslobj: ssl.SSLObject) -> TLSInfo:
    der = sslobj.getpeercert(binary_form=True)
    info = TLSInfo()
    if der:
        with suppress(ValueError):
            info = parse_certificate(der)
    info.protocol = sslobj.version()
    if cipher := sslobj.cipher():
        info.cipher = cipher[0]
    return info


LEGACY_VERSIONS = (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1))


# Motivos de erro que indicam limitação do OpenSSL *local*, e não recusa do servidor.
_LOCAL_LIMITATION_REASONS = {
    "NO_PROTOCOLS_AVAILABLE",
    "NO_CIPHERS_AVAILABLE",
    "NO_SUITABLE_SIGNATURE_ALGORITHM",
    "UNSUPPORTED_SSL_VERSION",
}
_HAS_FLAG = {"TLSv1.0": "HAS_TLSv1", "TLSv1.1": "HAS_TLSv1_1"}


async def probe_legacy_protocols(host: str, port: int, timeout: float) -> tuple[list[str], list[str]]:
    """Tenta handshakes forçando TLS 1.0 e 1.1.

    Retorna (aceitos, não_testáveis). Se o OpenSSL local foi compilado sem
    essas versões, não dá para afirmar nada sobre o servidor. Nesse caso o
    protocolo vai para `não_testáveis`, em vez de virar um falso "não aceita".
    """
    supported: list[str] = []
    untestable: list[str] = []
    for label, version in LEGACY_VERSIONS:
        if not getattr(ssl, _HAS_FLAG[label], True):
            untestable.append(label)
            continue
        try:
            ctx = insecure_context(version, version)
        except (ValueError, ssl.SSLError):
            untestable.append(label)
            continue
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), max(timeout, 3.0)
            )
        except ssl.SSLError as exc:
            if getattr(exc, "reason", None) in _LOCAL_LIMITATION_REASONS:
                untestable.append(label)
            continue
        except (TimeoutError, OSError, ValueError):
            continue
        supported.append(label)
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()
    return supported, untestable
