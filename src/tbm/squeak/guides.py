"""Passo a passo por marca de roteador: "onde fica essa opção no MEU modem?".

A correção genérica ("desative o Telnet") trava muita gente na hora de achar
o menu. Aqui a marca é deduzida do que o próprio aparelho revelou (fabricante
pelo MAC, título da página de administração, servidor SSDP) e cada tipo de
correção ganha o caminho de menu mais comum nessa marca.

Os menus mudam entre modelos e versões de firmware, e os modems de operadora
costumam vir com uma conta "user" que esconde opções avançadas. Por isso os
passos falam em "geralmente" e sempre terminam no plano B: pedir ao provedor.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from tbm.models import Host


@dataclass(frozen=True)
class Brand:
    key: str
    name: str
    patterns: tuple[str, ...]  # regex (minúsculas) contra fabricante, título, SSDP e nome
    login: str  # onde costuma estar a senha
    menus: dict[str, str] = field(default_factory=dict)  # tipo de correção → caminho de menu


_OPERATOR_NOTE = ("Se o menu não aparecer, a conta que veio na etiqueta é limitada pelo provedor: "
                  "peça a eles (a 'Carta para o provedor' já explica o pedido).")

BRANDS: tuple[Brand, ...] = (
    Brand("zte", "ZTE", (r"\bzte\b", r"zxhn", r"f6[0-9]{2}"),
          "etiqueta embaixo do aparelho (usuário 'user' ou 'admin')",
          {"telnet": "Internet → Segurança → Controle de serviço (Service Control): desmarque Telnet na WAN e na LAN",
           "upnp": "Aplicação → UPnP (ou Rede → UPnP): desmarque 'Ativar UPnP'",
           "tr069": "Gerência → TR-069 / ACS: normalmente bloqueado pelo provedor",
           "https": "Internet → Segurança → Controle de serviço: permita só HTTPS na LAN",
           "update": "Gerência → Atualização de software (em ONTs de operadora, quem atualiza é o provedor)",
           "wifi": "Rede → WLAN → Segurança: WPA2-PSK/AES (ou WPA2/WPA3) e desligue o WPS em WLAN → WPS",
           "ipv6fw": "Internet → Segurança → Firewall IPv6 (ou Filtro IPv6): ative",
           "dns": "Rede → LAN → Servidor DHCP: DNS automático; e Internet → WAN: DNS do provedor",
           "exposure": "Internet → Segurança → Controle de serviço (desmarque WAN) e Aplicação → Redirecionamento de porta"}),
    Brand("huawei", "Huawei", (r"huawei", r"hg8\d{3}", r"eg8\d{3}", r"echolife"),
          "etiqueta embaixo do aparelho (usuário 'telecomadmin' costuma ser só do provedor)",
          {"telnet": "Segurança → Controle de acesso do dispositivo (ONT Access Control): desmarque Telnet",
           "upnp": "Rede → UPnP (ou Aplicação de rede → UPnP): desative",
           "tr069": "Gerência → TR-069: costuma ser controlado pelo provedor",
           "https": "Segurança → Controle de acesso: deixe só HTTPS na LAN",
           "update": "Ferramentas do sistema → Atualização de firmware (em ONTs de operadora, quem atualiza é o provedor)",
           "wifi": "WLAN → Configuração básica: WPA2-PSK/AES; desligue o WPS em WLAN → WPS",
           "ipv6fw": "Segurança → Firewall: marque o nível alto também para IPv6",
           "dns": "LAN → Servidor DHCP: servidores DNS automáticos",
           "exposure": "Segurança → Controle de acesso (desmarque WAN) e Encaminhamento → Mapeamento de porta"}),
    Brand("nokia", "Nokia", (r"nokia", r"alcatel", r"g-?140w", r"g-?240w", r"g-?1425"),
          "etiqueta embaixo do aparelho",
          {"telnet": "Segurança → Controle de acesso (ACL): desmarque Telnet",
           "upnp": "Rede → UPnP e DLNA: desative o UPnP",
           "https": "Segurança → Controle de acesso: deixe só HTTPS",
           "update": "Manutenção → Atualização de firmware (normalmente feito pelo provedor)",
           "wifi": "Rede → Wireless (2.4/5 GHz): WPA2-PSK/AES e WPS desligado",
           "ipv6fw": "Segurança → Firewall: nível alto (inclui IPv6)",
           "dns": "Rede → LAN: DNS automático",
           "exposure": "Aplicação → Encaminhamento de porta e Segurança → Controle de acesso (WAN)"}),
    Brand("tplink", "TP-Link", (r"tp-?link", r"archer", r"deco\b"),
          "a senha que você criou no primeiro acesso (tplinkwifi.net)",
          {"telnet": "TP-Link raramente tem Telnet; se aparecer, Avançado → Ferramentas do sistema",
           "upnp": "Avançado → NAT Forwarding → UPnP: desligue",
           "https": "Avançado → Sistema → Administração: ative HTTPS e desligue o acesso remoto",
           "update": "Avançado → Sistema → Atualização de firmware (ou atualização online)",
           "wifi": "Avançado → Wireless → Configurações: WPA2/WPA3-Personal; desligue o WPS em Avançado → Wireless → WPS",
           "ipv6fw": "Avançado → IPv6: confira o firewall/filtro de entrada",
           "dns": "Avançado → Rede → Internet (DNS) e → DHCP Server: DNS automático ou 1.1.1.1",
           "exposure": "Avançado → Sistema → Administração (desligue acesso remoto) e NAT Forwarding → Virtual Servers"}),
    Brand("intelbras", "Intelbras", (r"intelbras", r"\bactionrf?\b", r"\bw[45]-?\d{3,4}"),
          "a senha criada no primeiro acesso (etiqueta para o padrão)",
          {"upnp": "Configurações avançadas → UPnP: desative",
           "https": "Sistema → Gerenciamento: desligue o acesso remoto pela internet",
           "update": "Sistema → Atualização de firmware",
           "wifi": "Wi-Fi → Segurança: WPA2-PSK/AES (ou WPA3); desligue o WPS",
           "dns": "Rede → WAN/LAN: DNS automático ou 1.1.1.1",
           "exposure": "Configurações avançadas → Redirecionamento de portas e Sistema → Gerenciamento remoto"}),
    Brand("fiberhome", "Fiberhome", (r"fiberhome", r"\ban5506", r"hg6\d{3}"),
          "etiqueta embaixo do aparelho",
          {"telnet": "Segurança → Controle de serviço: desmarque Telnet",
           "upnp": "Aplicação → UPnP: desative",
           "update": "Gerência → Atualização (normalmente feito pelo provedor)",
           "wifi": "Rede → WLAN → Segurança: WPA2-PSK/AES; WPS desligado",
           "ipv6fw": "Segurança → Firewall: ative o filtro IPv6",
           "exposure": "Aplicação → Encaminhamento de porta / DMZ (confira se há DMZ ligada)"}),
    Brand("tenda", "Tenda", (r"\btenda\b",),
          "a senha criada no primeiro acesso (tendawifi.com)",
          {"upnp": "Configurações avançadas → UPnP: desligue",
           "update": "Sistema → Atualização de firmware",
           "wifi": "Wi-Fi → Nome e senha: WPA2-PSK; desligue o WPS",
           "exposure": "Configurações avançadas → Encaminhamento de porta e Gerenciamento remoto"}),
    Brand("dlink", "D-Link", (r"d-?link", r"\bdir-\d+"),
          "a senha criada no primeiro acesso",
          {"upnp": "Avançado → Rede avançada → UPnP: desative",
           "https": "Ferramentas → Administração: desligue o gerenciamento remoto",
           "update": "Ferramentas → Firmware",
           "wifi": "Configuração → Wireless: WPA2-Personal/AES; desligue o WPS",
           "exposure": "Avançado → Encaminhamento de porta e Ferramentas → Administração (remoto)"}),
    Brand("mercusys", "Mercusys", (r"mercusys",),
          "a senha criada no primeiro acesso (mwlogin.net)",
          {"upnp": "Avançado → NAT Forwarding → UPnP: desligue",
           "update": "Avançado → Sistema → Atualização de firmware",
           "wifi": "Wireless → WPA2-PSK/AES e WPS desligado",
           "exposure": "Avançado → NAT Forwarding → Virtual Servers e Sistema → Administração remota"}),
)


def evidence_text(h: Host) -> str:
    parts = [h.vendor, h.device_name, h.hostname, *h.discovery.values()]
    return " ".join(p for p in parts if p).lower()


def detect_brand(h: Host | None) -> Brand | None:
    if h is None:
        return None
    text = evidence_text(h)
    return next((b for b in BRANDS if any(re.search(p, text) for p in b.patterns)), None)


@dataclass
class Guide:
    brand: str | None  # None = passos genéricos
    steps: list[str]


def guide_for(kind: str | None, h: Host | None, gateway: str | None = None) -> Guide | None:
    """Passos para um tipo de correção num aparelho (só faz sentido para roteadores)."""
    if kind is None:
        return None
    is_router = h is not None and h.device_type == "roteador/modem"
    router_kinds = {"telnet", "upnp", "tr069", "https", "update", "wifi", "ipv6fw", "dns", "exposure", "snmp"}
    if kind not in router_kinds or not (is_router or kind == "wifi"):
        return None
    address = h.address if (h is not None and is_router) else (gateway or "o endereço do roteador")
    brand = detect_brand(h) if is_router else None
    steps = [f"Abra http://{address} no navegador, conectado à rede de casa."]
    steps.append(f"Entre com a senha de administração: {brand.login}." if brand
                 else "Entre com a senha de administração (costuma estar na etiqueta embaixo do aparelho).")
    menu = brand.menus.get(kind) if brand else None
    if menu:
        steps.append(f"Geralmente em: {menu}.")
    else:
        steps.append(GENERIC.get(kind, "Procure a opção correspondente nos menus de segurança ou avançado."))
    steps.append("Salve e, se o aparelho pedir, reinicie. Depois rode um novo scan para confirmar.")
    steps.append(_OPERATOR_NOTE)
    return Guide(brand.name if brand else None, steps)


GENERIC = {
    "telnet": "Procure 'Controle de serviço', 'Controle de acesso' ou 'Administração' e desmarque Telnet.",
    "upnp": "Procure 'UPnP' (em Avançado, Rede ou NAT) e desligue.",
    "tr069": "Procure 'TR-069' ou 'ACS' em Gerência; em modems de operadora, só o provedor muda isso.",
    "https": "Em 'Administração', ative HTTPS e desligue o acesso remoto (pela internet).",
    "update": "Procure 'Atualização de firmware' em Sistema/Ferramentas/Manutenção.",
    "wifi": "Em Wi-Fi/Wireless → Segurança, escolha WPA2-PSK com AES (ou WPA2/WPA3) e desligue o WPS.",
    "ipv6fw": "Em IPv6 ou Segurança → Firewall, ative o bloqueio de conexões de entrada no IPv6.",
    "dns": "Em WAN/Internet e em LAN/DHCP, deixe o DNS automático (ou 1.1.1.1 e 8.8.8.8).",
    "exposure": "Desligue o 'acesso remoto' e confira 'Redirecionamento de portas', 'Virtual Server' e 'DMZ'.",
    "snmp": "Procure 'SNMP' em Gerência/Avançado e desligue (ou troque a comunidade 'public').",
}
