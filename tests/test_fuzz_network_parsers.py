"""Fuzzing dos parsers que entraram depois da v0.7 (Fase 5): NBNS, LLMNR, DHCP, UPnP, netsh, firmware.

Tudo aqui interpreta bytes ou texto vindos de aparelhos alheios (ou do sistema): só pode
devolver o "não entendi" documentado (None, {}, [] ou set()), nunca levantar exceção.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from tbm.scout.model import firmware_from_text, parse_description
from tbm.scout.names import parse_llmnr_ptr, parse_nbstat
from tbm.scout.wifi import parse_netsh_networks, server_ids

XID = b"\x11\x22\x33\x44"
FUZZ = settings(max_examples=400, deadline=None)


def dhcp_reply(options: bytes) -> bytes:
    header = bytearray(236)
    header[0] = 2
    header[4:8] = XID
    return bytes(header) + bytes.fromhex("63825363") + options


@FUZZ
@given(st.binary(max_size=600))
def test_nbstat_never_raises(data):
    assert parse_nbstat(data) is None or isinstance(parse_nbstat(data), str)


@FUZZ
@given(st.binary(max_size=600))
def test_llmnr_never_raises(data):
    out = parse_llmnr_ptr(data)
    assert out is None or isinstance(out, str)


@FUZZ
@given(st.binary(max_size=80))
def test_dhcp_options_never_raise(options):
    """Opções truncadas, comprimentos mentirosos, server id curto: nada derruba o check."""
    out = server_ids([dhcp_reply(options)], XID)
    assert isinstance(out, set) and len(out) <= 1


@FUZZ
@given(st.lists(st.binary(max_size=300), max_size=5))
def test_dhcp_garbage_never_raises(packets):
    assert isinstance(server_ids(packets, XID), set)


def test_dhcp_truncated_server_id_falls_back_to_siaddr():
    assert server_ids([dhcp_reply(bytes([54, 4, 192, 168]))], XID) == {"0.0.0.0"}
    assert server_ids([dhcp_reply(bytes([54]))], XID) == {"0.0.0.0"}


@FUZZ
@given(st.text(max_size=400))
def test_upnp_description_never_raises(text):
    assert isinstance(parse_description(text), dict)


@FUZZ
@given(st.recursive(st.text(alphabet="abc<>/=\"' &;", max_size=20),
                    lambda s: st.builds("".join, st.lists(s, max_size=4)), max_leaves=10))
def test_upnp_xml_like_input_never_raises(text):
    assert isinstance(parse_description("<root><device>" + text + "</device></root>"), dict)


def test_upnp_entity_bomb_is_harmless():
    bomb = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaaaaaaaa">' +
            "".join(f'<!ENTITY {c} "&{p};&{p};&{p};&{p};&{p};&{p};&{p};&{p};&{p};&{p};">'
                    for p, c in zip("abcdefgh", "bcdefghi", strict=True)) +
            ']><root><device><friendlyName>&i;</friendlyName></device></root>')
    assert parse_description(bomb) == {}  # o expat recusa a expansão em vez de explodir a memória


@FUZZ
@given(st.text(max_size=2000))
def test_netsh_never_raises(text):
    assert isinstance(parse_netsh_networks(text), list)


@FUZZ
@given(st.text(max_size=500))
def test_firmware_regex_never_raises(text):
    out = firmware_from_text(text)
    assert out is None or (isinstance(out, str) and len(out) <= 42)
