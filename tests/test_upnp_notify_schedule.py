"""UPnP IGD (com roteador falso), Telegram/ntfy, carta ao provedor e agendamento."""

import json
from pathlib import Path

import httpx
import pytest

from tbm.models import Finding, Host, ScanResult, Service, Severity
from tbm.pipeline import finalize
from tbm.schedule import build_plan, remove_plan, task_name
from tbm.sniffer.upnp_checks import (
    PortMapping,
    find_control_url,
    list_port_mappings,
    mapping_finding,
    same_host,
    soap_fields,
)
from tbm.squeak import diff_scans
from tbm.squeak.letter import build_letter
from tbm.squeak.notify import build_delivery, send_webhook

# ───────────────────────────── UPnP ─────────────────────────────

DEVICE_XML = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device><deviceList><device><deviceList><device>
<serviceList><service>
  <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
  <controlURL>/ctl/IPConn</controlURL>
</service></serviceList></device></deviceList></device></deviceList></device></root>"""


def _mapping_xml(i: int) -> str:
    return f"""<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost><NewExternalPort>{[3389, 51413][i]}</NewExternalPort>
<NewProtocol>{['TCP', 'UDP'][i]}</NewProtocol><NewInternalPort>{[3389, 51413][i]}</NewInternalPort>
<NewInternalClient>192.168.100.{[183, 40][i]}</NewInternalClient><NewEnabled>1</NewEnabled>
<NewPortMappingDescription>{['RDP', 'Transmission'][i]}</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>"""


def test_control_url_and_ssrf_guard():
    stype, url = find_control_url(DEVICE_XML, "http://192.168.100.1:5000/rootDesc.xml")
    assert "WANIPConnection" in stype and url == "http://192.168.100.1:5000/ctl/IPConn"
    assert same_host(url, "192.168.100.1")
    assert not same_host("http://169.254.169.254/latest", "192.168.100.1")  # SSRF
    assert not same_host("file:///etc/passwd", "192.168.100.1")
    assert find_control_url("<não é xml", "http://x/") is None


async def test_list_port_mappings_until_error():
    def router(request: httpx.Request) -> httpx.Response:
        body = request.content.decode()
        assert "GetGenericPortMappingEntry" in request.headers["SOAPAction"]
        idx = int(body.split("<NewPortMappingIndex>")[1].split("<")[0])
        if idx < 2:
            return httpx.Response(200, text=_mapping_xml(idx))
        return httpx.Response(500, text="<UPnPError><errorCode>713</errorCode></UPnPError>")

    async with httpx.AsyncClient(transport=httpx.MockTransport(router)) as http:
        maps = await list_port_mappings(http, "http://192.168.100.1/ctl", "urn:x:WANIPConnection:1")
    assert [(m.external_port, m.protocol, m.internal_client) for m in maps] == [
        (3389, "TCP", "192.168.100.183"), (51413, "UDP", "192.168.100.40")]
    host = Host(address="192.168.100.1")
    rdp, torrent = (mapping_finding("upnp.igd", host, m) for m in maps)
    assert rdp.severity is Severity.HIGH and "RDP" in rdp.evidence  # RDP aberto para a internet
    assert torrent.severity is Severity.MEDIUM


def test_mapping_restricted_or_disabled_is_less_severe():
    base = dict(external_port=22, protocol="TCP", internal_client="10.0.0.2", internal_port=22,
                description="", lease=0)
    h = Host(address="10.0.0.1")
    restricted = PortMapping(enabled=True, remote_host="203.0.113.9", **base)
    assert mapping_finding("u", h, restricted).severity is Severity.MEDIUM
    assert mapping_finding("u", h, PortMapping(enabled=False, remote_host="", **base)).severity is Severity.LOW


def test_soap_fields_ignores_namespaces():
    assert soap_fields(_mapping_xml(0))["NewInternalClient"] == "192.168.100.183"


# ───────────────────────────── alertas ─────────────────────────────


def _result_and_diff():
    f = Finding(check_id="c", title="Telnet exposto", severity=Severity.HIGH, host="10.0.0.1", port=23)
    r = finalize(ScanResult(label="casa", findings=[f]))
    return r, diff_scans(None, r)


def test_telegram_delivery():
    r, d = _result_and_diff()
    out = build_delivery("tg://123456:ABC-def/987654", r, d, d.new_findings)
    assert out.url == "https://api.telegram.org/bot123456:ABC-def/sendMessage"
    assert out.json["chat_id"] == "987654" and "Telnet" in out.json["text"]
    with pytest.raises(ValueError):
        build_delivery("tg://sem-chat", r, d, d.new_findings)


def test_ntfy_delivery_short_and_long_forms():
    r, d = _result_and_diff()
    a = build_delivery("ntfy://minha-casa-tbm", r, d, d.new_findings)
    b = build_delivery("https://ntfy.sh/minha-casa-tbm", r, d, d.new_findings)
    assert a.url == b.url == "https://ntfy.sh/minha-casa-tbm"
    assert a.headers["Priority"] == "high" and b"Telnet" in a.content
    selfhosted = build_delivery("ntfy://tbm", r, d, [])
    assert selfhosted.headers["Priority"] == "low"


async def test_send_webhook_uses_delivery():
    seen = {}

    def handler(request):
        seen["url"], seen["body"] = str(request.url), request.content
        return httpx.Response(200)

    r, d = _result_and_diff()
    assert await send_webhook("ntfy://t", r, d, transport=httpx.MockTransport(handler))
    assert seen["url"] == "https://ntfy.sh/t" and b"Telnet" in seen["body"]


def test_accepted_findings_do_not_alert():
    r, d = _result_and_diff()
    for f in d.new_findings:
        f.accepted = True
    payload = build_delivery("https://example.invalid/h", r, d, [])
    assert json.loads(json.dumps(payload.json))["new_findings"] == []


# ───────────────────────────── carta ─────────────────────────────


def test_letter_for_isp():
    ont = Host(address="192.168.100.175", mac="cc:ba:bd:99:74:01", device_type="roteador/modem",
               services=[Service(port=23)])
    findings = [
        Finding(check_id="service.exposed", title="Telnet exposto", severity=Severity.HIGH,
                host=ont.address, port=23, evidence="Porta 23/tcp aberta"),
        Finding(check_id="cve.nvd", key="CVE-2021-36369", title="CVE-2021-36369 em Dropbear SSH 2020.80",
                severity=Severity.HIGH, host=ont.address, port=22, cvss=7.5, epss=0.02),
        Finding(check_id="http.headers", title="Headers ausentes", severity=Severity.LOW, host=ont.address),
    ]
    text = build_letter(ScanResult(hosts=[ont], findings=findings), ont, name="Fulano")
    assert "Desativar o serviço Telnet" in text and "CVE-2021-36369" in text
    assert "Headers ausentes" not in text  # abaixo da severidade mínima
    assert text.rstrip().splitlines()[-3] == "Fulano"


# ───────────────────────────── agendamento ─────────────────────────────


def test_schedule_windows_plan():
    plan = build_plan("win32", ["192.168.100.0/24"], "casa", 6 * 3600, ["--udp"])
    [cmd] = plan.commands
    assert cmd[:4] == ["schtasks", "/Create", "/TN", task_name("casa")]
    assert cmd[cmd.index("/SC") + 1] == "HOURLY" and cmd[cmd.index("/MO") + 1] == "6"
    assert "--label casa" in cmd[cmd.index("/TR") + 1] and "--udp" in cmd[cmd.index("/TR") + 1]
    assert remove_plan("win32", "casa").commands[0][:2] == ["schtasks", "/Delete"]


def test_schedule_linux_and_cron_plans(monkeypatch):
    monkeypatch.setattr("tbm.schedule.shutil.which", lambda name: "/usr/bin/" + name)
    plan = build_plan("linux", ["10.0.0.0/24"], "casa", 86400, ["--notify", "ntfy://x"])
    timer = next(c for p, c in plan.files.items() if Path(p).suffix == ".timer")
    assert "OnUnitActiveSec=86400s" in timer
    assert any("enable" in c for c in plan.commands)
    assert plan.warnings  # URL de notificação gravada na unit
    cron = build_plan("darwin", ["10.0.0.0/24"], "casa", 1800, [])
    assert cron.manual and "*/30 * * * *" in cron.manual and not cron.commands
