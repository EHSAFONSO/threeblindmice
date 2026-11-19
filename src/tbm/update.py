"""Aviso de nova versão: só avisa, nunca baixa nem instala sozinho.

Um atualizador automático é um alvo de cadeia de suprimentos clássico: quem
controlar o canal de atualização controla todas as máquinas. Aqui o app só
pergunta à API pública do GitHub qual é a release mais recente, no máximo
uma vez por dia, e mostra:

- o link da página da release (você baixa pelo navegador);
- o SHA-256 publicado no `.sha256` da release, para conferir o arquivo;
- o comando `gh attestation verify`, que prova que o arquivo saiu do CI deste
  repositório.

Desligue com `tbm update --disable` ou no aviso da interface. Nenhum dado da
sua rede é enviado: é um GET anônimo para api.github.com.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any

import httpx

from tbm import USER_AGENT, __version__, config
from tbm.models import utcnow
from tbm.paths import tbm_home

REPO = "EHSAFONSO/threeblindmice"
API = f"https://api.github.com/repos/{REPO}/releases/latest"
CHECK_EVERY = timedelta(days=1)
CONFIG_KEY = "update_check"


@dataclass
class Release:
    version: str
    url: str
    published: str | None = None
    setup_name: str | None = None
    sha256: str | None = None

    @property
    def verify_command(self) -> str | None:
        if not self.setup_name:
            return None
        return f"gh attestation verify {self.setup_name} --repo {REPO}"


def parse_version(text: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", text.split("+")[0])
    return tuple(int(n) for n in nums[:3]) or (0,)


def newer(remote: str, local: str = __version__) -> bool:
    return parse_version(remote) > parse_version(local)


def enabled() -> bool:
    return bool(config.load().get(CONFIG_KEY, True))


def set_enabled(value: bool) -> None:
    data = config.load()
    data[CONFIG_KEY] = value
    config.save(data)


def _cache_path():
    return tbm_home() / "update.json"


def _read_cache() -> dict[str, Any]:
    try:
        data = json.loads(_cache_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def parse_release(data: dict[str, Any]) -> Release | None:
    tag = str(data.get("tag_name") or "")
    url = str(data.get("html_url") or "")
    if not tag or not url.startswith(f"https://github.com/{REPO}/"):
        return None  # só confiamos em links do próprio repositório
    setup = next((a for a in data.get("assets", []) if str(a.get("name", "")).endswith("-setup.exe")), None)
    return Release(version=tag.lstrip("v"), url=url, published=data.get("published_at"),
                   setup_name=setup["name"] if setup else None)


async def fetch_latest(transport: httpx.AsyncBaseTransport | None = None) -> Release | None:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    async with httpx.AsyncClient(timeout=10, headers=headers, transport=transport, follow_redirects=True) as http:
        try:
            resp = await http.get(API)
            if resp.status_code != 200:
                return None
            data = resp.json()
        except (httpx.HTTPError, ValueError):
            return None
        release = parse_release(data)
        if release is None or release.setup_name is None:
            return release
        sha_asset = next((a for a in data.get("assets", [])
                          if a.get("name") == f"{release.setup_name}.sha256"), None)
        if sha_asset and str(sha_asset.get("browser_download_url", "")).startswith(f"https://github.com/{REPO}/"):
            try:
                text = (await http.get(sha_asset["browser_download_url"])).text
            except httpx.HTTPError:
                text = ""
            if m := re.match(r"\s*([0-9a-f]{64})\b", text):
                release.sha256 = m.group(1)
    return release


async def check(force: bool = False, now: datetime | None = None,
                transport: httpx.AsyncBaseTransport | None = None) -> Release | None:
    """A release mais recente, se for mais nova que esta. Usa um cache diário."""
    if not enabled() and not force:
        return None
    now = now or utcnow()
    cache = _read_cache()
    release: Release | None = None
    try:
        fresh = now - datetime.fromisoformat(cache["checked_at"]) < CHECK_EVERY
    except (KeyError, ValueError, TypeError):
        fresh = False
    if fresh and not force:
        release = Release(**cache["release"]) if cache.get("release") else None
    else:
        release = await fetch_latest(transport)
        try:
            _cache_path().parent.mkdir(parents=True, exist_ok=True)
            _cache_path().write_text(json.dumps({"checked_at": now.isoformat(),
                                                 "release": asdict(release) if release else None}),
                                     encoding="utf-8")
        except OSError:
            pass
    return release if release and newer(release.version) else None
