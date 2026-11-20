"""Modelos de dados compartilhados entre os três módulos.

Fluxo: Scout produz `Host`s com `Service`s. Sniffer lê esses hosts e produz
`Finding`s. Squeak consome o `ScanResult` completo (nota, diff, relatório).
Tudo é pydantic, então serializa para JSON e volta sem perda.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field, computed_field


def utcnow() -> datetime:
    return datetime.now(UTC)


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def from_cvss(cls, score: float | None) -> Severity:
        """Faixas qualitativas oficiais do CVSS v3/v4."""
        if score is None:
            return cls.MEDIUM
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class TLSInfo(BaseModel):
    protocol: str | None = None
    cipher: str | None = None
    subject: str | None = None
    issuer: str | None = None
    sans: list[str] = Field(default_factory=list)
    not_before: datetime | None = None
    not_after: datetime | None = None
    key_type: str | None = None
    key_bits: int | None = None
    signature_algorithm: str | None = None
    self_signed: bool = False
    legacy_protocols: list[str] = Field(default_factory=list)
    # Protocolos que o OpenSSL *local* não consegue testar (evita falso negativo silencioso).
    legacy_untestable: list[str] = Field(default_factory=list)


class Service(BaseModel):
    port: int
    transport: str = "tcp"
    name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    tls: TLSInfo | None = None
    extra: dict[str, str] = Field(default_factory=dict)

    @property
    def is_http(self) -> bool:
        return self.transport == "tcp" and self.name in {"http", "https"}

    @property
    def label(self) -> str:
        product = " ".join(p for p in (self.product, self.version) if p)
        return product or self.name or "desconhecido"


class Host(BaseModel):
    address: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    device_type: str | None = None  # "roteador/modem", "celular Apple", "impressora"...
    device_name: str | None = None  # nome anunciado via mDNS/SSDP (ex.: "iPhone-de-Ana")
    discovery: dict[str, str] = Field(default_factory=dict)  # mdns, ssdp, http_title, como foi achado
    ipv6: list[str] = Field(default_factory=list)  # endereços IPv6 *globais* (roteáveis na internet)
    ipv6_services: list[int] = Field(default_factory=list)  # portas TCP abertas também via IPv6 global
    # Do cadastro de aparelhos conhecidos (tbm devices / interface), não da rede:
    alias: str | None = None  # nome que você deu ("TV da sala")
    trusted: bool = False  # você aprovou: aparelho conhecido da casa
    category: str | None = None  # familia, visitas, casa-inteligente, trabalho, infraestrutura
    note: str | None = None  # anotação livre
    services: list[Service] = Field(default_factory=list)

    def service(self, port: int, transport: str = "tcp") -> Service | None:
        return next((s for s in self.services if s.port == port and s.transport == transport), None)

    @property
    def identity(self) -> str:
        """Identidade estável entre scans, independente do IP que o DHCP deu.

        MAC primeiro: mesmo o MAC "aleatório" de celulares é fixo por rede Wi-Fi
        (iOS/Android usam um endereço privado por SSID). Sem MAC (host atrás de
        roteador), o nome anunciado. Em último caso, o IP.
        """
        if self.mac:
            return f"mac:{self.mac}"
        if self.device_name:
            return f"name:{self.device_name.lower()}"
        return f"ip:{self.address}"

    @property
    def name(self) -> str | None:
        """Melhor nome: o que você deu, o anunciado pelo aparelho ou o do DNS/NetBIOS."""
        return self.alias or self.device_name or self.hostname

    @property
    def display(self) -> str:
        extras = [x for x in (self.name, self.device_type, self.vendor) if x]
        return f"{self.address} ({' · '.join(dict.fromkeys(extras))})" if extras else self.address


class Finding(BaseModel):
    check_id: str
    title: str
    severity: Severity
    host: str
    port: int | None = None
    transport: str = "tcp"
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    cvss: float | None = None
    epss: float | None = None  # probabilidade de exploração em 30 dias (FIRST.org)
    kev: bool = False  # no catálogo CISA de vulnerabilidades exploradas ativamente
    file: str | None = None  # para achados em arquivos (segredos)
    line: int | None = None
    # Discriminador para achados repetidos do mesmo check no mesmo alvo
    # (ex.: o ID do CVE, ou o arquivo:linha de um segredo).
    key: str = ""
    # Identidade do dispositivo (Host.identity). Com ela, o fingerprint não muda
    # quando o DHCP troca o IP do aparelho.
    device: str | None = None
    accepted: bool = False  # risco aceito com `tbm accept`: aparece, mas não conta na nota
    acceptance: str | None = None  # motivo e validade da aceitação

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fingerprint(self) -> str:
        """ID estável entre scans. É o que o diff usa para saber se é novo ou resolvido."""
        raw = f"{self.check_id}|{self.device or self.host}|{self.port}|{self.key}"
        return hashlib.sha1(raw.encode()).hexdigest()[:16]

    @property
    def location(self) -> str:
        if self.file:
            return f"{self.file}:{self.line}" if self.line else self.file
        if self.port is None:
            return self.host
        suffix = "/udp" if self.transport == "udp" else ""
        return f"{self.host}:{self.port}{suffix}"

    def sort_key(self) -> tuple[int, int, float, str, int]:
        return (-self.severity.rank, -int(self.kev), -(self.epss or 0.0), self.host, self.port or 0)


PortKey = tuple[str, int, str]  # (host, porta, transporte)


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    label: str = "default"
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    targets: list[str] = Field(default_factory=list)
    scope: str = ""
    ports_scanned: list[int] = Field(default_factory=list)
    udp_ports_scanned: list[int] = Field(default_factory=list)
    gateway: str | None = None  # roteador padrão da máquina que escaneou (base do mapa da rede)
    hosts: list[Host] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    score: int | None = None
    grade: str | None = None

    def severity_counts(self) -> dict[Severity, int]:
        counts = {sev: 0 for sev in sorted(Severity, key=lambda s: -s.rank)}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    def host(self, address: str) -> Host | None:
        return next((h for h in self.hosts if h.address == address), None)

    @property
    def open_ports(self) -> set[PortKey]:
        return {(h.address, s.port, s.transport) for h in self.hosts for s in h.services}
