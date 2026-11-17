"""Fuzzing dos parsers que leem dados de aparelhos que não controlamos.

Um dispositivo malicioso (ou só bugado) pode responder qualquer coisa. O
contrato é: cada parser devolve um resultado ou levanta *apenas* o erro
documentado, nunca IndexError/struct.error/UnicodeError nem loop infinito.
O hypothesis gera milhares de entradas aleatórias e reduz qualquer falha ao
menor exemplo que a reproduz.
"""

import struct

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tbm.scout import wire
from tbm.scout.arp import parse_arp_output
from tbm.scout.banner import identify
from tbm.scout.discovery import Announcement, absorb_mdns, absorb_ssdp, parse_default_gateway
from tbm.sniffer.backport import compare_versions, distro_package
from tbm.sniffer.smb_checks import parse_smb1_response, parse_smb2_response
from tbm.sniffer.ssh_checks import SSHProtocolError, parse_kexinit
from tbm.sniffer.upnp_checks import find_control_url, soap_fields

FUZZ = settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])

# Pacotes "quase DNS": cabeçalho válido com contagens arbitrárias + lixo.
dns_like = st.builds(
    lambda txid, flags, counts, body: struct.pack("!HHHHHH", txid, flags | 0x8000, *counts) + body,
    st.integers(0, 0xFFFF), st.integers(0, 0xFFFF),
    st.tuples(*[st.integers(0, 6)] * 4), st.binary(max_size=300),
)


@FUZZ
@given(st.one_of(st.binary(max_size=400), dns_like))
def test_dns_parser_only_raises_parse_error(data):
    try:
        resp = wire.parse_response(data)
    except wire.ParseError:
        return
    resp.ptr_targets()
    resp.a_records()


@FUZZ
@given(st.binary(max_size=400))
def test_snmp_value_never_raises(data):
    assert wire.snmp_response_value(data) is None or isinstance(wire.snmp_response_value(data), str)


@FUZZ
@given(st.binary(max_size=400))
def test_mdns_and_ssdp_absorb_never_raise(data):
    found: dict[str, Announcement] = {}
    absorb_mdns(found, data, "10.0.0.1")
    absorb_ssdp(found, data, "10.0.0.1")
    for ann in found.values():
        ann.best_name  # noqa: B018 (exercita a propriedade)


@FUZZ
@given(st.integers(1, 65535), st.binary(max_size=600), st.booleans())
def test_identify_never_raises(port, data, tls):
    identify(port, data, tls)


@FUZZ
@given(st.binary(max_size=300))
def test_kexinit_only_raises_protocol_error(data):
    try:
        parse_kexinit(bytes([20]) + data)
    except SSHProtocolError:
        pass


@FUZZ
@given(st.binary(max_size=200))
def test_smb_parsers_never_raise(data):
    parse_smb1_response(data)
    parse_smb2_response(data)
    parse_smb1_response(b"\xffSMB" + data)
    parse_smb2_response(b"\xfeSMB" + data)


@FUZZ
@given(st.text(max_size=500))
def test_text_parsers_never_raise(text):
    parse_arp_output(text)
    for platform in ("linux", "win32", "bsd"):
        parse_default_gateway(text, platform)
    distro_package(text)
    find_control_url(text, "http://10.0.0.1/")
    soap_fields(text)


version_chars = st.text(alphabet="0123456789.:-~+abcpz", max_size=20)


@FUZZ
@given(version_chars, version_chars, version_chars)
def test_dpkg_compare_is_a_total_order(a, b, c):
    """Antissimetria e transitividade: se quebrar, o filtro de backport mente."""
    ab, ba = compare_versions(a, b), compare_versions(b, a)
    assert (ab > 0) == (ba < 0) and (ab == 0) == (ba == 0)
    if compare_versions(a, b) <= 0 and compare_versions(b, c) <= 0:
        assert compare_versions(a, c) <= 0
