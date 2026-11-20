"""Achados agrupados pela *correção*: "1 ação resolve 5 achados".

Uma lista de 17 achados soltos esconde o que importa: muitos somem com uma
única providência (ex.: atualizar o firmware do modem resolve os CVEs e os
algoritmos fracos do SSH dele). Aqui cada achado é classificado num "tipo de
correção" e agrupado por dispositivo. A prioridade usa o mesmo peso da nota,
que já considera KEV e EPSS, então as primeiras ações são as que mais reduzem
risco real.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from urllib.parse import quote

from tbm.models import Finding, Host, ScanResult, Severity
from tbm.squeak.scoring import weight


@dataclass(frozen=True)
class FixKind:
    key: str
    title: str  # com {dev} no lugar do dispositivo
    why: str
    isp: bool = False  # costuma depender do provedor/fabricante (sugere a carta)


KINDS: dict[str, FixKind] = {k.key: k for k in (
    FixKind("update", "Atualizar o firmware ou software de {dev}",
            "Corrige vulnerabilidades conhecidas (CVEs) e algoritmos de criptografia fracos de uma vez.",
            isp=True),
    FixKind("telnet", "Desativar o Telnet em {dev}",
            "O Telnet transmite senhas sem criptografia e dá acesso de terminal ao aparelho.",
            isp=True),
    FixKind("ftp", "Desativar ou proteger o FTP em {dev}", "O FTP envia usuário e senha em texto puro."),
    FixKind("remote", "Restringir o acesso remoto (RDP/VNC) em {dev}",
            "Acesso remoto exposto é alvo constante de força bruta."),
    FixKind("smb", "Ajustar o compartilhamento de arquivos (SMB) de {dev}",
            "SMB mal configurado é porta de entrada para ransomware."),
    FixKind("database", "Proteger o banco de dados em {dev}", "Bancos acessíveis pela rede vazam ou perdem dados."),
    FixKind("tr069", "Restringir a gerência remota (TR-069) de {dev}",
            "É a interface que o provedor usa para controlar o aparelho; já foi explorada em massa.", isp=True),
    FixKind("https", "Ativar HTTPS na administração de {dev}",
            "Senhas digitadas na página de administração trafegam sem criptografia.", isp=True),
    FixKind("webconf", "Ajustar a configuração do servidor web de {dev}",
            "Headers de segurança, cookies e versão exposta: configurações básicas contra ataques web."),
    FixKind("webfiles", "Remover arquivos sensíveis do site em {dev}",
            "Arquivos como .git e .env expõem código e senhas."),
    FixKind("api", "Fechar a API administrativa sem senha em {dev}", "Quem acessa a API controla o serviço."),
    FixKind("tls", "Renovar ou ajustar o certificado TLS de {dev}",
            "Certificado ruim ensina a ignorar avisos de segurança."),
    FixKind("upnp", "Desativar o UPnP em {dev}",
            "Com UPnP, qualquer programa da rede abre portas para a internet sem pedir permissão.", isp=True),
    FixKind("snmp", "Desativar o SNMP ou trocar a senha padrão em {dev}",
            "Com a senha padrão 'public', qualquer um lê a configuração completa do aparelho.", isp=True),
    FixKind("secret", "Remover a credencial de {dev}", "Senhas em código acabam em backups e repositórios."),
    FixKind("wifi", "Reforçar a segurança da {dev}",
            "Criptografia fraca no Wi-Fi deixa vizinhos entrarem na rede e lerem o tráfego."),
    FixKind("ipv6fw", "Conferir o firewall IPv6 de {dev}",
            "Sem NAT no IPv6, só o firewall do roteador separa os aparelhos da internet.", isp=True),
    FixKind("dns", "Corrigir o DNS de {dev}",
            "DNS adulterado manda você para sites falsos mesmo digitando o endereço certo.", isp=True),
    FixKind("exposure", "Fechar o que a internet vê em {dev}",
            "Portas visíveis da internet são varridas por robôs o tempo todo.", isp=True),
    FixKind("camera", "Proteger o vídeo da {dev}",
            "Câmera sem senha deixa qualquer um assistir ao vivo, de dentro ou de fora da rede."),
    FixKind("mqtt", "Exigir senha no MQTT de {dev}",
            "Sem senha, qualquer um na rede lê o estado da casa inteligente e manda comandos."),
    FixKind("password", "Conferir a senha de administração de {dev}",
            "Senha de fábrica é pública e é um dos primeiros alvos numa rede doméstica."),
)}

_PORT_KIND = {23: "telnet", 21: "ftp", 3389: "remote", 5900: "remote", 445: "smb", 139: "smb", 7547: "tr069",
              2375: "api", 5555: "api", 1433: "database", 3306: "database", 5432: "database", 5984: "database",
              6379: "database", 9200: "database", 11211: "database", 27017: "database"}


def classify(f: Finding) -> str | None:
    """Tipo de correção de um achado (None = vira uma ação própria)."""
    cid = f.check_id
    if cid in ("cve.nvd", "ssh.algorithms") or (cid == "service.banner" and f.key == "sshv1"):
        return "update"
    if cid == "service.banner" and f.key == "redis-noauth":
        return "database"
    if cid in ("service.exposed", "service.ajp") and f.port in _PORT_KIND:
        return _PORT_KIND[f.port]
    if cid == "service.ftp-anon":
        return "ftp"
    if cid == "smb.negotiate":
        return "smb"
    if cid in ("http.cleartext-login", "http.no-https"):
        return "https"
    if cid in ("http.headers", "http.cookies", "http.disclosure", "http.listing", "http.passive"):
        return "webconf"
    if cid == "http.paths":
        return "webfiles"
    if cid == "http.open-api":
        return "api"
    if cid == "tls.config":
        return "tls"
    if cid == "upnp.igd" or (cid == "udp.services" and f.key == "ssdp"):
        return "upnp"
    if cid == "udp.services" and f.key == "snmp-public":
        return "snmp"
    if cid == "secrets.local":
        return "secret"
    if cid == "network.wifi":
        return "wifi"
    if cid == "network.ipv6":
        return "ipv6fw"
    if cid == "network.dns":
        return "dns"
    if cid == "network.external":
        return "exposure"
    if cid == "iot.rtsp":
        return "camera"
    if cid == "iot.mqtt":
        return "mqtt"
    if cid == "network.default-pass":
        return "password"
    for extra in CLASSIFIERS:  # tipos de correção registrados por plugins (tbm.plugin)
        if (kind := extra(f)) in KINDS:
            return kind
    return None


# Classificadores extras (plugins): recebem o achado e devolvem a chave de um KINDS, ou None.
CLASSIFIERS: list[Callable[[Finding], str | None]] = []


@dataclass
class Action:
    key: str
    kind: str | None
    title: str
    why: str
    host: str
    device: str
    device_type: str | None
    findings: list[Finding] = field(default_factory=list)
    accepted: list[Finding] = field(default_factory=list)
    isp: bool = False

    @property
    def severity(self) -> Severity:
        return max((f.severity for f in self.findings), key=lambda s: s.rank, default=Severity.INFO)

    @property
    def priority(self) -> float:
        # peso da nota (já ajustado por KEV/EPSS) + leve bônus por resolver vários de uma vez
        return sum(weight(f) for f in self.findings) + 0.5 * len(self.findings)

    @property
    def kev(self) -> bool:
        return any(f.kev for f in self.findings)

    @property
    def max_epss(self) -> float | None:
        values = [f.epss for f in self.findings if f.epss is not None]
        return max(values) if values else None

    def letter_url(self, label: str) -> str | None:
        if not self.isp or self.host == "local":
            return None
        return f"/letter?label={quote(label)}&host={quote(self.host)}"


PSEUDO_HOSTS = {"wifi": "rede Wi-Fi", "local": "este computador"}


def device_label(h: Host | None, fallback: str) -> str:
    if h is None:
        return PSEUDO_HOSTS.get(fallback, fallback)
    name = h.name
    if name and h.device_type:
        return f"{name} ({h.device_type})"
    return name or (f"{h.device_type} {h.address}" if h.device_type else h.address)


def build_actions(scan: ScanResult, include_info: bool = False) -> list[Action]:
    hosts = {h.address: h for h in scan.hosts}
    groups: dict[str, Action] = {}
    for f in scan.findings:
        if f.severity is Severity.INFO and not include_info:
            continue
        kind_key = classify(f)
        h = hosts.get(f.host)
        is_router = bool(h and h.device_type == "roteador/modem")
        if f.host == "local" and f.file:
            dev = f.file
        else:
            dev = device_label(h, f.host)
        if kind_key is None:
            gkey = f"single|{f.fingerprint}"
            title, why, isp = f.title, (f.description.split("\n")[0][:200] if f.description else ""), False
        else:
            kind = KINDS[kind_key]
            gkey = f"{kind_key}|{f.device or f.host}|{f.file or ''}"
            title, why, isp = kind.title.format(dev=dev), kind.why, kind.isp and is_router
        action = groups.get(gkey)
        if action is None:
            action = groups[gkey] = Action(
                key=hashlib.sha1(gkey.encode()).hexdigest()[:10], kind=kind_key, title=title, why=why,
                host=f.host, device=dev, device_type=h.device_type if h else None, isp=isp,
            )
        (action.accepted if f.accepted else action.findings).append(f)
    actions = [a for a in groups.values() if a.findings]
    return sorted(actions, key=lambda a: (-a.priority, -a.severity.rank, a.title))


@dataclass
class Projection:
    score: int
    grade: str
    gain: int


def project(scan: ScanResult, actions: Iterable[Action]) -> Projection:
    """Nota que o scan teria sem os achados destas ações (o que acontece se você fizer todas)."""
    from tbm.squeak.scoring import grade_for, score_findings

    gone = {f.fingerprint for a in actions for f in a.findings}
    score = score_findings([f for f in scan.findings if f.fingerprint not in gone])
    return Projection(score=score, grade=grade_for(score), gain=score - (scan.score or 0))


def impacts(scan: ScanResult, actions: list[Action]) -> dict[str, int]:
    """Quantos pontos cada ação, sozinha, soma à nota."""
    return {a.key: project(scan, [a]).gain for a in actions}


def accepted_only(scan: ScanResult) -> list[Action]:
    """Ações cujos achados estão todos aceitos (aparecem à parte, sem pesar)."""
    hosts = {h.address: h for h in scan.hosts}
    out: dict[str, Action] = {}
    for f in scan.findings:
        if not f.accepted:
            continue
        h = hosts.get(f.host)
        key = f.fingerprint
        out[key] = Action(key=key[:10], kind=classify(f), title=f.title, why=f.acceptance or "", host=f.host,
                          device=device_label(h, f.host), device_type=h.device_type if h else None, accepted=[f])
    return list(out.values())


@dataclass
class Progress:
    resolved: int
    open: int
    accepted: int

    @property
    def total(self) -> int:
        return self.resolved + self.open

    @property
    def percent(self) -> int:
        return round(100 * self.resolved / self.total) if self.total else 100


def progress(history: Iterable[ScanResult], current: ScanResult) -> Progress:
    """Quanto do que já apareceu no histórico recente foi resolvido."""
    def relevant(scan: ScanResult) -> set[str]:
        return {f.fingerprint for f in scan.findings if f.severity is not Severity.INFO}

    seen: set[str] = set()
    for scan in history:
        seen |= relevant(scan)
    now = relevant(current)
    seen |= now
    accepted = {f.fingerprint for f in current.findings if f.accepted and f.severity is not Severity.INFO}
    return Progress(resolved=len(seen - now), open=len(now - accepted), accepted=len(accepted))
