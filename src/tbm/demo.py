"""Modo demonstração: uma rede fictícia para prints, apresentações e o site.

`tbm demo` usa um histórico temporário próprio (nunca toca no seu) e preenche
alguns scans de uma casa inventada, com evolução de nota ao longo de semanas.
Nenhum endereço é real.
"""

from __future__ import annotations

import tempfile
from datetime import timedelta
from pathlib import Path

from tbm.models import Finding, Host, ScanResult, Service, Severity, utcnow
from tbm.pipeline import finalize
from tbm.squeak import HistoryStore

NET = "203.0.113."  # TEST-NET-3: documentação, nunca roteável
LAN = "192.168.10."


def _host(addr, mac, dtype, name=None, ports=(), **kw):
    return Host(address=LAN + addr, mac=mac, device_type=dtype, device_name=name,
                services=[Service(port=p) for p in ports], **kw)


HOSTS = [
    _host("1", "fc:bc:d1:00:00:01", "roteador/modem", ports=(23, 80, 443, 7547),
          discovery={"upnp_manufacturer": "ACME", "upnp_model": "HomeHub 3000"}),
    _host("20", "aa:bb:cc:00:00:20", "computador Windows", "PC-Sala", ports=(135, 139, 445)),
    _host("31", "aa:bb:cc:00:00:31", "celular Apple", "iPhone", ports=(), trusted=True),
    _host("42", "aa:bb:cc:00:00:42", "TV", "TV-Sala", ports=(8008, 8009), trusted=True),
    _host("55", "aa:bb:cc:00:00:55", "câmera/DVR", "Camera-Portao", ports=(80, 554)),
    _host("60", "aa:bb:cc:00:00:60", "casa inteligente (Matter)", "Lampada", trusted=True),
]


def _findings(level: int) -> list[Finding]:
    """`level` 0 = pior, cai a cada scan: as correções vão sumindo."""
    gw, pc, cam = LAN + "1", LAN + "20", LAN + "55"
    pool = [
        Finding(check_id="service.exposed", title="Telnet exposto", severity=Severity.HIGH, host=gw, port=23),
        Finding(check_id="cve.nvd", title="CVE-2021-36369 em Dropbear", severity=Severity.HIGH, host=gw, port=22,
                key="CVE-2021-36369", cvss=7.5, epss=0.4, kev=True),
        Finding(check_id="iot.rtsp", title="Transmissão de vídeo da câmera acessível sem senha",
                severity=Severity.HIGH, host=cam, port=554, key="open"),
        Finding(check_id="service.exposed", title="SMB exposto", severity=Severity.MEDIUM, host=pc, port=445),
        Finding(check_id="http.cleartext-login", title="Formulário de senha via HTTP", severity=Severity.MEDIUM,
                host=gw, port=80),
        Finding(check_id="network.wifi", title="Wi-Fi com WPA2 (pode subir para WPA3)", severity=Severity.INFO,
                host="wifi", key="wpa2"),
    ]
    return pool[level:] if level < len(pool) else pool[-1:]


def seed(store: HistoryStore) -> None:
    now = utcnow()
    for i, weeks in enumerate([5, 4, 3, 2, 1, 0]):
        # melhora com o tempo, mas o último scan ainda tem o que mostrar (não vira tudo verde)
        scan = ScanResult(label="casa", gateway=LAN + "1", hosts=[h.model_copy(deep=True) for h in HOSTS],
                          started_at=now - timedelta(weeks=weeks), findings=_findings(min(i, 3)))
        store.save(finalize(scan))


def demo_home() -> Path:
    home = Path(tempfile.mkdtemp(prefix="tbm-demo-"))
    seed(HistoryStore(home / "history.db"))
    return home
