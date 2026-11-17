"""Classificação do tipo de dispositivo a partir de evidências fracas combinadas.

Nenhuma evidência sozinha é conclusiva. Por isso cada regra soma pontos para
um tipo, e vence o tipo com mais pontos. É o mesmo princípio de ferramentas
de fingerprint como o p0f, numa versão simples o suficiente para estudar.
"""

from __future__ import annotations

import re
from collections import Counter

from tbm.models import Host

# (tipo, pontos, predicado sobre as evidências)
Evidence = dict[str, object]

RULES: list[tuple[str, int, str, object]] = [
    # serviços mDNS
    ("TV/Chromecast", 5, "service", "_googlecast._tcp"),
    ("TV/streaming", 4, "service", "_amzn-wplay._tcp"),
    ("TV/streaming", 4, "service", "_androidtvremote2._tcp"),
    ("dispositivo Apple", 4, "service", "_companion-link._tcp"),
    ("dispositivo Apple", 3, "service", "_airplay._tcp"),
    ("caixa de som/AirPlay", 3, "service", "_raop._tcp"),
    ("caixa de som", 3, "service", "_spotify-connect._tcp"),
    ("casa inteligente (HomeKit)", 4, "service", "_hap._tcp"),
    ("impressora", 5, "service", "_ipp._tcp"),
    ("impressora", 5, "service", "_printer._tcp"),
    ("impressora", 5, "service", "_pdl-datastream._tcp"),
    ("casa inteligente (Matter)", 4, "service", "_matterd._udp"),
    ("casa inteligente (Matter)", 4, "service", "_matter._tcp"),
    ("caixa de som/tela Google", 3, "port", 8009),  # Google Cast (Nest, Chromecast)
    ("caixa de som/tela Google", 2, "port", 8008),
    ("computador", 3, "service", "_workstation._tcp"),
    ("computador", 2, "service", "_smb._tcp"),
    # portas TCP
    ("roteador/modem", 5, "port", 7547),  # TR-069: gerência remota do provedor
    ("roteador/modem", 2, "port", 53),
    ("computador Windows", 4, "port", 135),
    ("computador Windows", 3, "port", 445),
    ("impressora", 5, "port", 9100),
    ("impressora", 4, "port", 631),
    ("câmera/DVR", 4, "port", 554),
    ("câmera/DVR", 5, "port", 37777),
    ("dispositivo Apple", 4, "port", 62078),  # sincronização iPhone/iPad
    ("roteador/modem", 4, "port", 8291),  # MikroTik Winbox
    ("servidor de mídia", 4, "port", 32400),  # Plex
    # banners e nomes
    ("roteador/modem", 3, "ssdp", r"InternetGatewayDevice|WANIPConnection"),
    ("TV/streaming", 3, "ssdp", r"MediaRenderer|DIAL|Roku|SmartTV|Tizen|webOS"),
    ("dispositivo embarcado (Linux)", 2, "banner", r"dropbear|busybox"),
    ("celular Apple", 4, "name", r"iphone"),
    ("tablet Apple", 4, "name", r"ipad"),
    ("computador Apple", 4, "name", r"macbook|imac|mac-?mini"),
    ("celular Android", 4, "name", r"android|galaxy|pixel|redmi|xiaomi|moto"),
    ("impressora", 4, "name", r"epson|hp-?[a-z]*jet|brother|canon|printer"),
    ("TV/streaming", 4, "name", r"tv|chromecast|roku|fire-?tv|bravia"),
    ("celular/notebook", 1, "random_mac", True),  # MAC privado é típico de celulares
]


def _matches(kind: str, expected: object, ev: Evidence) -> bool:
    if kind == "service":
        return expected in ev["services"]  # type: ignore[operator]
    if kind == "port":
        return expected in ev["ports"]  # type: ignore[operator]
    if kind == "random_mac":
        return bool(ev["random_mac"])
    text = str(ev.get(kind) or "")
    return bool(text and re.search(str(expected), text, re.I))


def evidence_for(host: Host, *, is_gateway: bool = False) -> Evidence:
    banners = " ".join(s.banner or "" for s in host.services)
    names = " ".join(x for x in (host.device_name, host.hostname, host.discovery.get("mdns_names")) if x)
    return {
        "services": set(filter(None, host.discovery.get("mdns_services", "").split(","))),
        "ports": {s.port for s in host.services if s.transport == "tcp"},
        "ssdp": " ".join(x for x in (host.discovery.get("ssdp_server"), host.discovery.get("ssdp_types")) if x),
        "banner": banners,
        "name": names,
        "random_mac": host.vendor == "MAC aleatório (privacidade)",
        "gateway": is_gateway,
    }


def classify(host: Host, *, is_gateway: bool = False) -> str | None:
    ev = evidence_for(host, is_gateway=is_gateway)
    scores: Counter[str] = Counter()
    for dtype, points, kind, expected in RULES:
        if _matches(kind, expected, ev):
            scores[dtype] += points
    if is_gateway:
        scores["roteador/modem"] += 6
    if not scores:
        return None
    dtype, points = scores.most_common(1)[0]
    return dtype if points >= 3 else None
