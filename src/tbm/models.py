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
        return self.name in {"http", "https"}

    @property
    def label(self) -> str:
        product = " ".join(p for p in (self.product, self.version) if p)
        return product or self.name or "desconhecido"


class Host(BaseModel):
    address: str
    hostname: str | None = None
    services: list[Service] = Field(default_factory=list)

    def service(self, port: int) -> Service | None:
        return next((s for s in self.services if s.port == port), None)

    @property
    def display(self) -> str:
        return f"{self.address} ({self.hostname})" if self.hostname else self.address


class Finding(BaseModel):
    check_id: str
    title: str
    severity: Severity
    host: str
    port: int | None = None
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    cvss: float | None = None
    # Discriminador para achados repetidos do mesmo check no mesmo alvo
    # (ex.: o ID do CVE, ou o arquivo:linha de um segredo).
    key: str = ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fingerprint(self) -> str:
        """ID estável entre scans. É o que o diff usa para saber se é novo ou resolvido."""
        raw = f"{self.check_id}|{self.host}|{self.port}|{self.key}"
        return hashlib.sha1(raw.encode()).hexdigest()[:16]

    @property
    def location(self) -> str:
        return f"{self.host}:{self.port}" if self.port is not None else self.host

    def sort_key(self) -> tuple[int, str, int]:
        return (-self.severity.rank, self.host, self.port or 0)


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    label: str = "default"
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    targets: list[str] = Field(default_factory=list)
    scope: str = ""
    ports_scanned: list[int] = Field(default_factory=list)
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
    def open_ports(self) -> set[tuple[str, int]]:
        return {(h.address, s.port) for h in self.hosts for s in h.services}
