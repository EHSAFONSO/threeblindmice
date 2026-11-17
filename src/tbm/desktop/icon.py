"""Ícone do aplicativo, desenhado com Pillow (sem arquivo binário no repositório).

Três ratinhos estilizados (o nome do projeto) sobre um círculo roxo, a cor da
interface. Gerado em vários tamanhos para o .ico do atalho e para a bandeja.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tbm.paths import tbm_home

ACCENT = (91, 63, 208, 255)
MOUSE = (240, 240, 245, 255)
EAR = (255, 182, 193, 255)


def make_icon(size: int = 256) -> Any:
    from PIL import Image, ImageDraw

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((0, 0, size - 1, size - 1), fill=ACCENT)
    s = size / 256
    # três ratinhos: corpo, duas orelhas e um olho cada
    for cx in (70, 128, 186):
        cy = 150 if cx != 128 else 128
        r = 30
        d.ellipse(((cx - 26) * s, (cy - 46) * s, (cx - 6) * s, (cy - 24) * s), fill=EAR)
        d.ellipse(((cx + 6) * s, (cy - 46) * s, (cx + 26) * s, (cy - 24) * s), fill=EAR)
        d.ellipse(((cx - r) * s, (cy - r) * s, (cx + r) * s, (cy + r) * s), fill=MOUSE)
        d.ellipse(((cx - 4) * s, (cy - 6) * s, (cx + 4) * s, (cy + 2) * s), fill=(40, 30, 60, 255))
    return img


def ico_path() -> Path:
    return tbm_home() / "threeblindmice.ico"


def ensure_ico() -> Path:
    """Gera o .ico (16 a 256 px) uma vez, em TBM_HOME."""
    path = ico_path()
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        make_icon(256).save(path, format="ICO", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64),
                                                         (128, 128), (256, 256)])
    return path
