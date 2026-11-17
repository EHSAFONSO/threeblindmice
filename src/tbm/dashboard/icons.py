"""Tipo de dispositivo → ícone do conjunto em templates/_icons.svg.j2."""

from __future__ import annotations

DEVICE_ICONS = {
    "roteador/modem": "router",
    "computador Windows": "desktop",
    "computador": "desktop",
    "computador Apple": "laptop",
    "celular Apple": "phone",
    "celular Android": "phone",
    "celular/notebook": "phone",
    "dispositivo Apple": "phone",
    "tablet Apple": "tablet",
    "TV/Chromecast": "tv",
    "TV/streaming": "tv",
    "caixa de som": "speaker",
    "caixa de som/AirPlay": "speaker",
    "caixa de som/tela Google": "speaker",
    "casa inteligente (HomeKit)": "home",
    "casa inteligente (Matter)": "home",
    "impressora": "printer",
    "câmera/DVR": "camera",
    "servidor de mídia": "server",
    "dispositivo embarcado (Linux)": "chip",
}


def device_icon(device_type: str | None) -> str:
    return DEVICE_ICONS.get(device_type or "", "device")
