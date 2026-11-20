"""UPnP IGD: quais portas o roteador abriu para a internet, e para quem.

Com o UPnP ligado, qualquer programa da rede (jogo, torrent, câmera,
malware) pode pedir ao roteador para redirecionar uma porta da internet para
si, sem pedir permissão a ninguém. O próprio protocolo permite *listar* esses
redirecionamentos: é a melhor resposta para "o que da minha casa está exposto?".

Passos:
1. SSDP unicast para o roteador procurando o InternetGatewayDevice → LOCATION
2. GET no XML de descrição → controlURL do serviço WANIPConnection/WANPPPConnection
3. SOAP GetGenericPortMappingEntry(0, 1, 2…) até dar erro, e GetExternalIPAddress

Só leitura: nenhuma ação que altere o roteador é chamada.

Segurança: o LOCATION e o controlURL vêm do aparelho. Só seguimos URLs que
apontam para o mesmo IP do roteador (já validado pelo escopo); do contrário,
um aparelho malicioso poderia fazer o tbm requisitar outros hosts (SSRF).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from tbm.models import Finding, Host, Severity
from tbm.scout.udp import udp_exchange
from tbm.sniffer.base import Check, CheckContext, register

IGD_SEARCH = (
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\nMX: 1\r\n'
    b"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
)
WAN_SERVICES = ("WANIPConnection", "WANPPPConnection")
MAX_XML = 512 * 1024
MAX_MAPPINGS = 128
# Serviços que, se expostos à internet por UPnP, são graves.
RISKY_INTERNAL_PORTS = {21, 22, 23, 139, 445, 1433, 2375, 3306, 3389, 5432, 5555, 5900,
                        6379, 9200, 11211, 27017}


@dataclass
class PortMapping:
    external_port: int
    protocol: str
    internal_client: str
    internal_port: int
    enabled: bool
    description: str
    remote_host: str
    lease: int


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def same_host(url: str, address: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and parsed.hostname == address


def find_control_url(xml_text: str, base_url: str) -> tuple[str, str] | None:
    """Devolve (serviceType, controlURL absoluto) do serviço WAN, se houver."""
    try:
        root = ET.fromstring(xml_text)  # expat do Python 3.11+ já barra "billion laughs"
    except ET.ParseError:
        return None
    for el in root.iter():
        if _local(el.tag) != "service":
            continue
        fields = {_local(c.tag): (c.text or "").strip() for c in el}
        stype = fields.get("serviceType", "")
        if any(w in stype for w in WAN_SERVICES) and fields.get("controlURL"):
            return stype, urljoin(base_url, fields["controlURL"])
    return None


def soap_body(service_type: str, action: str, args: dict[str, str] | None = None) -> str:
    inner = "".join(f"<{k}>{v}</{k}>" for k, v in (args or {}).items())
    return (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
        f'<u:{action} xmlns:u="{service_type}">{inner}</u:{action}>'
        "</s:Body></s:Envelope>"
    )


def soap_fields(xml_text: str) -> dict[str, str]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}
    return {_local(el.tag): (el.text or "").strip() for el in root.iter() if _local(el.tag).startswith("New")}


async def _soap(http: httpx.AsyncClient, url: str, stype: str, action: str,
                args: dict[str, str] | None = None) -> dict[str, str] | None:
    try:
        resp = await http.post(url, content=soap_body(stype, action, args), headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{stype}#{action}"',
        })
    except httpx.HTTPError:
        return None
    if resp.status_code != 200 or len(resp.content) > MAX_XML:
        return None  # 500 + UPnPError 713 (índice inválido) encerra a listagem
    return soap_fields(resp.text)


def _int(value: str | None, default: int = 0) -> int:
    try:
        return int(value or default)
    except ValueError:
        return default


async def list_port_mappings(http: httpx.AsyncClient, control_url: str, stype: str) -> list[PortMapping]:
    mappings = []
    for index in range(MAX_MAPPINGS):
        f = await _soap(http, control_url, stype, "GetGenericPortMappingEntry",
                        {"NewPortMappingIndex": str(index)})
        if not f or "NewExternalPort" not in f:
            break
        mappings.append(PortMapping(
            external_port=_int(f.get("NewExternalPort")),
            protocol=(f.get("NewProtocol") or "?").upper(),
            internal_client=f.get("NewInternalClient", "?"),
            internal_port=_int(f.get("NewInternalPort")),
            enabled=f.get("NewEnabled", "1") in ("1", "true", "yes"),
            description=f.get("NewPortMappingDescription", "")[:120],
            remote_host=f.get("NewRemoteHost", ""),
            lease=_int(f.get("NewLeaseDuration")),
        ))
    return mappings


async def locate_igd(host: Host) -> str | None:
    data = await udp_exchange(host.address, 1900, IGD_SEARCH, 2.0)
    if data:
        if m := re.search(rb"^location:\s*(\S+)", data, re.I | re.M):
            url = m.group(1).decode("latin-1")
            if same_host(url, host.address):
                return url
    known = host.discovery.get("ssdp_location")
    return known if known and same_host(known, host.address) else None


def mapping_finding(check_id: str, host: Host, m: PortMapping) -> Finding:
    risky = m.internal_port in RISKY_INTERNAL_PORTS
    restricted = m.remote_host not in ("", "*", "0.0.0.0")
    severity = Severity.HIGH if risky and not restricted else Severity.MEDIUM
    if not m.enabled:
        severity = Severity.LOW
    who = f"somente de {m.remote_host}" if restricted else "de qualquer lugar da internet"
    return Finding(
        check_id=check_id, key=f"map:{m.protocol}:{m.external_port}", severity=severity,
        host=host.address,
        title=f"UPnP abriu {m.external_port}/{m.protocol} da internet → {m.internal_client}:{m.internal_port}",
        description=f"O roteador está encaminhando a porta {m.external_port}/{m.protocol} {who} para "
                    f"{m.internal_client}:{m.internal_port}. Esse redirecionamento foi criado por um "
                    "programa da rede via UPnP, não pela configuração manual do roteador."
                    + (" O serviço de destino costuma ser alvo de ataques automatizados." if risky else ""),
        evidence=f"descrição: {m.description or '—'} · ativo: {'sim' if m.enabled else 'não'} · "
                 f"lease: {m.lease or 'permanente'}s",
        remediation="Confirme se o programa em "
                    f"{m.internal_client} realmente precisa estar acessível da internet. Se não, "
                    "feche-o e desative o UPnP no roteador; se sim, prefira um redirecionamento "
                    "manual documentado ou uma VPN (WireGuard/Tailscale).",
    )


@register
class UPnPIGDCheck(Check):
    id = "upnp.igd"
    name = "UPnP: portas abertas para a internet pelo roteador"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        candidates = [h for h in ctx.scan.hosts if
                      h.service(1900, "udp") or h.discovery.get("ssdp_location")
                      or h.device_type == "roteador/modem"]
        for host in candidates:
            location = await locate_igd(host)
            if not location:
                continue
            try:
                resp = await ctx.http.get(location)
            except httpx.HTTPError:
                continue
            if resp.status_code != 200 or len(resp.content) > MAX_XML:
                continue
            found = find_control_url(resp.text, location)
            if not found or not same_host(found[1], host.address):
                continue
            stype, control = found
            mappings = await list_port_mappings(ctx.http, control, stype)
            external = (await _soap(ctx.http, control, stype, "GetExternalIPAddress") or {}).get(
                "NewExternalIPAddress", "?")
            findings.append(Finding(
                check_id=self.id, key="igd", severity=Severity.LOW, host=host.address,
                title="Roteador aceita redirecionamentos automáticos via UPnP",
                description="Qualquer programa da rede pode abrir portas para a internet sem "
                            "autenticação. É conveniente para jogos e videochamadas, mas também "
                            "para malware.",
                evidence=f"{len(mappings)} redirecionamento(s) ativo(s) · IP externo: {external}",
                remediation="Se ninguém da casa depende de UPnP, desative-o na administração do roteador.",
            ))
            findings += [mapping_finding(self.id, host, m) for m in mappings]
            if nat := nat_finding(self.id, host, external):
                findings.append(nat)
        return findings


def nat_finding(check_id: str, host: Host, external: str) -> Finding | None:
    """O IP "externo" do roteador não é público? Então há outro NAT na frente (modem ou CGNAT)."""
    import ipaddress

    try:
        ip = ipaddress.ip_address(external)
    except ValueError:
        return None
    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return Finding(
            check_id=check_id, key="cgnat", severity=Severity.INFO, host=host.address,
            title="Sua operadora usa CGNAT (IP público compartilhado)",
            description=("O IP do lado de fora do roteador é da faixa 100.64.0.0/10, reservada para CGNAT: a "
                         "operadora divide um IP público entre vários clientes. Isso esconde a sua rede da "
                         "internet (bom), mas impede abrir portas para acesso remoto e pode fazer o seu IP "
                         "público aparecer em listas de bloqueio por causa de outros clientes."),
            evidence=f"IP externo do roteador: {external}",
            remediation="Nada a corrigir. Para acesso remoto, use uma VPN de saída (Tailscale, WireGuard).",
        )
    if ip.is_private:
        return Finding(
            check_id=check_id, key="double-nat", severity=Severity.INFO, host=host.address,
            title="NAT duplo confirmado: há outro roteador entre este e a internet",
            description=("O IP do lado de fora deste roteador é privado, então outro aparelho (normalmente o "
                         "modem da operadora) faz NAT antes dele. Funciona, mas complica jogos, chamadas e "
                         "redirecionamentos de porta, e as configurações de segurança precisam ser revistas "
                         "nos DOIS aparelhos."),
            evidence=f"IP externo do roteador: {external}",
            remediation=("Peça à operadora para colocar o modem em modo bridge, ou ligue o seu roteador na "
                         "DMZ do modem. Confira UPnP e acesso remoto nos dois."),
        )
    return None
