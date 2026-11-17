from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tbm.models import Host, ScanResult, Service, Severity
from tbm.scout.tls import parse_certificate
from tbm.sniffer import Sniffer, SnifferOptions
from tbm.sniffer.cve import cpe_candidates, parse_nvd_response
from tbm.sniffer.http_checks import analyze_response
from tbm.sniffer.secrets import mask, scan_path, shannon_entropy
from tbm.sniffer.tls_checks import analyze_tls


def _resp(url: str, status=200, headers=None, text="") -> httpx.Response:
    return httpx.Response(status, headers=headers or [], text=text,
                          request=httpx.Request("GET", url))


def test_http_missing_headers_and_disclosure():
    r = _resp("https://10.0.0.2/", headers=[("Server", "nginx/1.18.0"),
                                            ("Set-Cookie", "session=abc; Path=/")])
    findings = analyze_response("10.0.0.2", 443, "https://10.0.0.2/", r)
    ids = {f.check_id for f in findings}
    assert {"http.headers", "http.disclosure", "http.cookies"} <= ids
    cookie = next(f for f in findings if f.check_id == "http.cookies")
    assert cookie.severity is Severity.MEDIUM  # falta Secure em HTTPS
    assert "Strict-Transport-Security" in next(
        f for f in findings if f.check_id == "http.headers").evidence


def test_http_cleartext_login_is_high():
    r = _resp("http://10.0.0.2/", text='<form><input type="password" name="p"></form>')
    findings = analyze_response("10.0.0.2", 80, "http://10.0.0.2/", r)
    assert any(f.check_id == "http.cleartext-login" and f.severity is Severity.HIGH
               for f in findings)


def test_http_hardened_response_is_clean():
    r = _resp("https://x/", headers=[
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Strict-Transport-Security", "max-age=63072000"),
        ("Server", "nginx"),
        ("Set-Cookie", "s=1; Secure; HttpOnly; SameSite=Lax"),
    ])
    assert analyze_response("x", 443, "https://x/", r) == []


def _make_cert(days_valid: int, key_size: int = 2048) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tbm.test")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=400))
        .not_valid_after(now + timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_tls_expired_selfsigned_weak():
    info = parse_certificate(_make_cert(days_valid=-1, key_size=1024))
    assert info.self_signed and info.key_bits == 1024
    info.legacy_protocols = ["TLSv1.0"]
    keys = {f.key for f in analyze_tls("10.0.0.3", 443, info)}
    assert keys == {"expired", "self-signed", "weak-key", "legacy-protocols"}


def test_tls_expiring_soon():
    info = parse_certificate(_make_cert(days_valid=10))
    keys = {f.key for f in analyze_tls("h", 443, info)}
    assert "expiring" in keys and "expired" not in keys


def test_secrets_detection(tmp_path: Path):
    (tmp_path / "config.py").write_text(
        'AWS_KEY = "AKIAQWERTYUIOPASDFGH"\n'
        'password = "changeme"\n'
        'api_key = "q8Zr2Lm9Xv4Tn7Bw1Ks6"\n'
        'DATABASE_URL = "postgres://app:S3cr3tPass@db:5432/app"\n',
        encoding="utf-8",
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text('token="AKIAQWERTYUIOPASDFGH"')
    findings = scan_path(tmp_path)
    rules = sorted(f.key.rsplit(":", 1)[1] for f in findings)
    assert rules == ["aws-access-key", "connection-string", "generic-secret"]
    assert all("AKIAQWERTYUIOPASDFGH" not in f.evidence for f in findings)  # mascarado


def test_entropy_and_mask():
    assert shannon_entropy("aaaaaaaa") == 0
    assert shannon_entropy("q8Zr2Lm9Xv4Tn7Bw") > 3.5
    assert mask("AKIAQWERTYUIOPASDFGH").startswith("AKIA") and "*" in mask("AKIAQWERTYUIOPASDFGH")


def test_cpe_candidates():
    assert cpe_candidates("OpenSSH", "8.2p1") == [
        "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*"
    ]
    assert len(cpe_candidates("nginx", "1.18.0")) == 2
    assert cpe_candidates("Desconhecido", "1.0") == []
    assert cpe_candidates("nginx", None) == []


def test_parse_nvd_response():
    payload = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2023-38408", "vulnStatus": "Analyzed",
                     "descriptions": [{"lang": "en", "value": "ssh-agent RCE"}],
                     "metrics": {"cvssMetricV31": [{"type": "Primary",
                                                    "cvssData": {"baseScore": 9.8}}]},
                     "cisaExploitAdd": "2024-01-01"}},
            {"cve": {"id": "CVE-0000-0001", "vulnStatus": "Rejected"}},
        ]
    }
    [rec] = parse_nvd_response(payload)
    assert rec.id == "CVE-2023-38408" and rec.score == 9.8 and rec.kev


async def test_sniffer_engine_offline():
    scan = ScanResult(hosts=[Host(address="10.0.0.9", services=[
        Service(port=23, name="telnet"),
        Service(port=6379, name="redis", extra={"auth": "none"}),
    ])])
    findings, errors = await Sniffer(SnifferOptions(cve=False)).run(scan)
    assert errors == []
    titles = [f.title for f in findings]
    assert titles[0] == "Redis sem autenticação"  # ordenado: crítico primeiro
    assert "Telnet exposto" in titles
