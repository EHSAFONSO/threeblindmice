"""Checks de certificado e configuração TLS."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tbm.models import Finding, Severity, TLSInfo
from tbm.sniffer.base import Check, CheckContext, register

CHECK_ID = "tls.config"
EXPIRY_WARNING = timedelta(days=30)
WEAK_HASHES = {"md5", "sha1"}


def analyze_tls(
    host: str, port: int, tls: TLSInfo, now: datetime | None = None
) -> list[Finding]:
    """Função pura, para facilitar os testes: recebe o TLSInfo e devolve os achados."""
    now = now or datetime.now(UTC)
    out: list[Finding] = []

    def add(key: str, sev: Severity, title: str, desc: str, evidence: str, fix: str) -> None:
        out.append(Finding(check_id=CHECK_ID, key=key, severity=sev, title=title, host=host,
                           port=port, description=desc, evidence=evidence, remediation=fix))

    if tls.not_after:
        if tls.not_after < now:
            add("expired", Severity.HIGH, "Certificado TLS expirado",
                "Clientes vão exibir erro, e os usuários acabam aprendendo a ignorar avisos de "
                "segurança.",
                f"Válido até {tls.not_after:%Y-%m-%d}", "Renove o certificado (ex.: Let's Encrypt).")
        elif tls.not_after - now < EXPIRY_WARNING:
            days = (tls.not_after - now).days
            add("expiring", Severity.LOW, f"Certificado TLS expira em {days} dias",
                "O certificado está perto de expirar.", f"Válido até {tls.not_after:%Y-%m-%d}",
                "Automatize a renovação (certbot, Caddy, cert-manager).")

    if tls.self_signed:
        add("self-signed", Severity.MEDIUM, "Certificado TLS autoassinado",
            "Sem uma CA confiável, clientes não conseguem distinguir este servidor de um "
            "atacante fazendo MITM.",
            f"Emissor = sujeito = {tls.subject}",
            "Use um certificado de uma CA pública ou de uma CA interna distribuída aos clientes.")

    if tls.key_type == "RSA" and tls.key_bits and tls.key_bits < 2048:
        add("weak-key", Severity.HIGH, f"Chave RSA fraca ({tls.key_bits} bits)",
            "Chaves RSA abaixo de 2048 bits são consideradas quebráveis.",
            f"{tls.key_type} {tls.key_bits} bits", "Gere uma nova chave RSA ≥ 2048 bits ou ECDSA P-256.")

    if tls.signature_algorithm and tls.signature_algorithm.lower() in WEAK_HASHES:
        add("weak-signature", Severity.MEDIUM,
            f"Certificado assinado com {tls.signature_algorithm.upper()}",
            "MD5 e SHA-1 têm colisões práticas, o que permite forjar certificados.",
            f"Assinatura: {tls.signature_algorithm}", "Reemita o certificado com SHA-256 ou superior.")

    legacy = set(tls.legacy_protocols)
    if tls.protocol in {"TLSv1", "TLSv1.1", "SSLv3"}:
        legacy.add(tls.protocol)
    if legacy:
        add("legacy-protocols", Severity.MEDIUM, "Protocolos TLS obsoletos aceitos",
            "TLS 1.0 e 1.1 foram descontinuados pela RFC 8996 e são vulneráveis a ataques de "
            "downgrade (BEAST, POODLE etc.).",
            "Aceita: " + ", ".join(sorted(legacy)),
            "Configure o mínimo como TLS 1.2 (de preferência, TLS 1.3).")
    if tls.legacy_untestable and not legacy:
        add("legacy-untestable", Severity.INFO, "Não foi possível testar TLS 1.0/1.1",
            "O OpenSSL desta máquina não suporta esses protocolos, então não dá para afirmar se "
            "o servidor os aceita. Ausência de achado aqui não é garantia.",
            "Não testados: " + ", ".join(tls.legacy_untestable),
            "Confirme com outra ferramenta, ex.: testssl.sh ou `openssl s_client -tls1`.")
    return out


@register
class TLSCheck(Check):
    id = CHECK_ID
    name = "Certificados e protocolos TLS"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        for host, svc in ctx.services(lambda s: s.tls is not None):
            findings += analyze_tls(host.address, svc.port, svc.tls)  # type: ignore[arg-type]
        return findings
