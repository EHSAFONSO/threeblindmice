"""Fase 2: destinos de alerta como registro."""

from __future__ import annotations

import asyncio

from tbm import config
from tbm.models import Finding, ScanResult, Severity
from tbm.squeak import notifiers
from tbm.squeak.diff import ScanDiff
from tbm.squeak.notifiers import NOTIFIERS, Delivery, Notifier, notifier_for, register_notifier
from tbm.squeak.notify import send_test, send_webhook


def test_every_builtin_destination_is_recognized():
    cases = {
        "tg://123:abc/42": "telegram", "ntfy://topico": "ntfy", "https://ntfy.sh/t": "ntfy",
        "pushover://a@b": "pushover", "hass://ha/wh": "hass", "https://discord.com/api/webhooks/1/x": "discord",
        "https://hooks.slack.com/services/x": "slack", "smtp://u:p@s/a@b.com": "email",
        "https://exemplo.org/hook": "webhook",
    }
    for url, kind in cases.items():
        assert notifier_for(url)[0].kind == kind, url
        assert config.describe(url)["kind"] == kind


def test_describe_never_leaks_secrets():
    for url in ("tg://123456:SEGREDO/987654321", "pushover://SEGREDO@USR", "smtp://u:SEGREDO@s/a@b.com",
                "https://discord.com/api/webhooks/1/SEGREDO", "hass://ha/SEGREDO"):
        assert "SEGREDO" not in config.describe(url)["label"]


def test_email_goes_through_smtp_not_http(monkeypatch):
    """Antes do registro, send_webhook/send_test montavam um POST HTTP para a URL smtp://."""
    sent: list[tuple[str, str]] = []
    monkeypatch.setattr(notifiers, "send_email", lambda target, subject, body: sent.append((subject, body)))
    scan = ScanResult(label="casa", score=50, grade="D")
    f = Finding(check_id="x", title="Telnet aberto", severity=Severity.HIGH, host="192.168.0.9")
    diff = ScanDiff(previous_id=None, new_findings=[f])
    assert asyncio.run(send_webhook("smtp://u:p@s/a@b.com", scan, diff)) is True
    assert asyncio.run(send_test("smtp://u:p@s/a@b.com")) == 250
    assert len(sent) == 2 and "Telnet aberto" in sent[0][1]


def test_third_party_notifier_can_register():
    @register_notifier
    class Pombo(Notifier):
        kind = "pombo"

        def matches(self, p):
            return p.scheme == "pombo"

        def describe(self, p):
            return "Pombo-correio"

        def delivery(self, target, text, *, title, priority, extra):
            return Delivery("https://pombo.example/send", json={"msg": text})

    try:
        assert config.describe("pombo://ninho") == {"kind": "pombo", "label": "Pombo-correio"}
        assert notifier_for("https://exemplo.org")[0].kind == "webhook"  # o genérico continua por último
    finally:
        NOTIFIERS[:] = [n for n in NOTIFIERS if n.kind != "pombo"]
