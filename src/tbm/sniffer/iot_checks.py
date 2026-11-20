"""Casa conectada: câmeras, MQTT, impressoras e Home Assistant.

Estes checks detectam serviços que não exigem autenticação nenhuma (igual ao
check de FTP anônimo que já existe): é uma checagem de exposição, não de senha.

- iot.rtsp (ativo): a câmera responde a um RTSP DESCRIBE sem pedir credencial?
- iot.mqtt (ativo): o broker MQTT aceita uma conexão anônima (sem usuário)?
- iot.services (passivo): serviços de casa conectada visíveis na rede
  (impressora aceitando trabalhos na 9100, Home Assistant, NVR de câmera).

Os dois primeiros abrem uma conexão com o serviço, então aparecem nos logs do
aparelho; por isso só rodam com --active ("Testes ativos"), em equipamentos
seus. Nenhum deles tenta adivinhar senha.
"""

from __future__ import annotations

import asyncio

from tbm.models import Finding, Host, Severity
from tbm.sniffer.base import Check, CheckContext, register

RTSP_PORTS = (554, 8554)
MQTT_PORTS = (1883, 8883)


async def _probe(host: str, port: int, payload: bytes, timeout: float) -> bytes | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, TimeoutError):
        return None
    try:
        writer.write(payload)
        await writer.drain()
        return await asyncio.wait_for(reader.read(512), timeout)
    except (OSError, TimeoutError):
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


# ───────────────────────────── RTSP (câmeras) ─────────────────────────────


@register
class RTSPCheck(Check):
    id = "iot.rtsp"
    name = "Câmera com vídeo sem senha (RTSP)"
    active_only = True

    async def run(self, ctx: CheckContext) -> list[Finding]:
        findings = []
        for host, svc in ctx.services(lambda s: s.port in RTSP_PORTS or s.name == "rtsp"):
            url = f"rtsp://{host.address}:{svc.port}/"
            req = (f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n").encode()
            data = await _probe(host.address, svc.port, req, max(ctx.options.http_timeout / 2, 3.0))
            if not data:
                continue
            head = data.decode("latin-1", "replace")
            status = head.split("\r\n", 1)[0]
            if "200" in status and "application/sdp" in head.lower():
                findings.append(Finding(
                    check_id=self.id, host=host.address, port=svc.port, key="open",
                    title="Transmissão de vídeo da câmera acessível sem senha",
                    severity=Severity.HIGH,
                    description=("A câmera entregou a descrição do vídeo (RTSP) sem pedir credencial. Quem está na "
                                 "rede, e quem alcançar essa porta pela internet, consegue assistir ao vivo."),
                    evidence=head.strip().splitlines()[0][:120],
                    remediation=("Ative usuário e senha no RTSP na configuração da câmera (ou no app do fabricante). "
                                 "Nunca redirecione a porta RTSP para a internet; para ver de fora, use a nuvem do "
                                 "fabricante ou uma VPN."),
                    references=["https://www.rfc-editor.org/rfc/rfc2326"]))
            elif "401" in status:
                continue  # pede autenticação: ok
        return findings


# ───────────────────────────── MQTT (casa inteligente) ─────────────────────────────

# CONNECT mínimo do MQTT 3.1.1, client-id "tbm", sem usuário/senha.
_MQTT_CONNECT = bytes.fromhex("101000044d51545404020000000374626d")


@register
class MQTTCheck(Check):
    id = "iot.mqtt"
    name = "Broker MQTT sem autenticação"
    active_only = True

    async def run(self, ctx: CheckContext) -> list[Finding]:
        findings = []
        for host, svc in ctx.services(lambda s: s.port in MQTT_PORTS or s.name in ("mqtt", "mqtt-tls")):
            if svc.port in (8883,) or svc.tls:
                continue  # TLS: não testamos sem lidar com o handshake
            data = await _probe(host.address, svc.port, _MQTT_CONNECT, max(ctx.options.http_timeout / 2, 3.0))
            # CONNACK = 0x20 0x02 0x00 rc; rc 0x00 = aceito sem credencial
            if data and len(data) >= 4 and data[0] == 0x20 and data[3] == 0x00:
                findings.append(Finding(
                    check_id=self.id, host=host.address, port=svc.port, key="anon",
                    title="Broker MQTT aceita conexão sem usuário nem senha",
                    severity=Severity.HIGH,
                    description=("O MQTT costuma ser o sistema nervoso da casa inteligente: sensores, lâmpadas e "
                                 "fechaduras publicam e recebem comandos por ele. Sem autenticação, qualquer um na "
                                 "rede lê o estado da casa e envia comandos (abrir, ligar, desligar)."),
                    evidence="CONNACK código 0 (conexão anônima aceita)",
                    remediation=("Exija usuário e senha no broker (no Mosquitto, allow_anonymous false e um "
                                 "password_file). Nunca exponha a porta 1883 à internet; se precisar de acesso "
                                 "remoto, use TLS (8883) e uma VPN."),
                    references=["https://mosquitto.org/documentation/authentication-methods/"]))
        return findings


# ───────────────────────────── inventário de IoT (passivo) ─────────────────────────────

SERVICES = {
    9100: ("impressora aceitando trabalhos crus (porta 9100)", Severity.LOW,
           "Qualquer um da rede manda documentos direto para a impressora, sem senha.",
           "Desative o RAW/JetDirect ou limite por IP nas configurações da impressora."),
    8123: ("Home Assistant", Severity.INFO,
           "Painel de automação da casa. Confirme que exige login e não está redirecionado para a internet.",
           "Ative login forte e acesso remoto só por Nabu Casa ou VPN."),
    1400: ("Sonos/alto-falante", Severity.INFO, "Alto-falante de rede exposto.", "Mantenha o firmware em dia."),
    37777: ("NVR/câmera (Dahua)", Severity.MEDIUM,
            "Gravadores de câmera dessa família já tiveram falhas graves exploradas em massa.",
            "Atualize o firmware, troque a senha padrão e nunca exponha à internet."),
    34567: ("NVR/câmera (Xiongmai)", Severity.MEDIUM,
            "Gravadores baratos dessa família foram usados em botnets (Mirai).",
            "Atualize o firmware, troque a senha padrão e nunca exponha à internet."),
}


@register
class IoTServicesCheck(Check):
    id = "iot.services"
    name = "Serviços de casa conectada"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        findings = []
        for host, svc in ctx.services():
            spec = SERVICES.get(svc.port)
            if spec is None:
                continue
            label, severity, why, fix = spec
            findings.append(Finding(
                check_id=self.id, host=host.address, port=svc.port, key=str(svc.port),
                title=f"{label} na rede", severity=severity, description=why, remediation=fix,
                evidence=f"{host.address}:{svc.port}"))
        return findings


def likely_default_password(host: Host) -> bool:
    """Heurística passiva: roteadores/câmeras que ninguém costuma reconfigurar.

    Não testa senha nenhuma: só sinaliza, pela cara do aparelho, que vale a pena
    conferir se a senha de fábrica foi trocada.
    """
    return host.device_type in ("roteador/modem", "câmera/DVR") and bool(host.service(80) or host.service(443))
