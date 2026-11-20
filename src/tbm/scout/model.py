"""Modelo exato do aparelho: fabricante, modelo e firmware que ele mesmo anuncia.

Fontes, sem nenhuma tentativa de login:
- descrição UPnP (o XML do LOCATION do SSDP): manufacturer, modelName,
  modelNumber, friendlyName e, às vezes, a versão do software;
- SNMP sysDescr (quando a comunidade 'public' responde): costuma trazer
  modelo e versão do firmware em texto livre.

Com o modelo em mãos, os guias de correção ficam específicos e a página do
aparelho mostra exatamente o que ele é.

Segurança: o LOCATION vem da rede. Só seguimos URLs do próprio aparelho
(mesmo IP) e limitamos o tamanho do XML, como no check UPnP.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import httpx

from tbm import USER_AGENT
from tbm.models import Host

MAX_XML = 256 * 1024
FIELDS = {"manufacturer": "upnp_manufacturer", "modelName": "upnp_model", "modelNumber": "upnp_model_number",
          "friendlyName": "upnp_name", "softwareVersion": "firmware", "firmwareVersion": "firmware"}
_FW_RE = re.compile(r"(?:firmware|fw|version|ver)[\s:=./]*([A-Za-z]?[0-9][\w.\-]{1,40})", re.I)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_description(xml_text: str) -> dict[str, str]:
    """Campos do primeiro <device> da descrição UPnP (os de dentro são subdispositivos)."""
    try:
        root = ET.fromstring(xml_text)  # o expat do Python 3.11+ barra entidades recursivas
    except ET.ParseError:
        return {}
    device = next((el for el in root.iter() if _local(el.tag) == "device"), None)
    if device is None:
        return {}
    out: dict[str, str] = {}
    for child in device:
        key = FIELDS.get(_local(child.tag))
        value = (child.text or "").strip()
        if key and value and key not in out:
            out[key] = value[:120]
    return out


def firmware_from_text(text: str | None) -> str | None:
    if not text:
        return None
    m = _FW_RE.search(text)
    return m.group(1) if m else None


def model_label(h: Host) -> str | None:
    """Texto curto para mostrar: "Huawei EG8145V5 · firmware V5R020C10"."""
    d = h.discovery
    maker = d.get("upnp_manufacturer")
    model = d.get("upnp_model") or d.get("upnp_model_number")
    name = " ".join(x for x in (maker, model) if x and (not maker or not model or maker.lower() not in model.lower()))
    if not name:
        name = model or maker or ""
    fw = d.get("firmware")
    return (name + (f" · firmware {fw}" if fw else "")).strip(" ·") or None


async def enrich(hosts: list[Host], timeout: float = 4.0) -> None:
    """Preenche h.discovery com fabricante/modelo/firmware anunciados."""
    targets = []
    for h in hosts:
        loc = h.discovery.get("ssdp_location")
        if loc and urlparse(loc).hostname == h.address and urlparse(loc).scheme in ("http", "https"):
            targets.append((h, loc))
        snmp = next((s for s in h.services if s.transport == "udp" and s.port == 161), None)
        if snmp and (descr := snmp.extra.get("sysdescr")):
            h.discovery["snmp_descr"] = descr
            if fw := firmware_from_text(descr):
                h.discovery.setdefault("firmware", fw)
    if not targets:
        return
    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False,  # noqa: S501 (aparelho local)
                                 headers={"User-Agent": USER_AGENT}) as http:
        for h, loc in targets:
            try:
                resp = await http.get(loc)
            except httpx.HTTPError:
                continue
            if resp.status_code != 200 or len(resp.content) > MAX_XML:
                continue
            for key, value in parse_description(resp.text).items():
                h.discovery.setdefault(key, value)
