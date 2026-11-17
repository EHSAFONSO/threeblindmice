import pytest

from tbm.scout.banner import identify
from tbm.scout.ports import parse_ports


@pytest.mark.parametrize(
    ("port", "data", "name", "product", "version"),
    [
        (22, b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n", "ssh", "OpenSSH", "8.2p1"),
        (2222, b"SSH-2.0-dropbear_2020.81\r\n", "ssh", "Dropbear SSH", "2020.81"),
        (21, b"220 (vsFTPd 3.0.3)\r\n", "ftp", "vsftpd", "3.0.3"),
        (25, b"220 mail.lan ESMTP Postfix (Debian)\r\n", "smtp", "Postfix", None),
        (8080, b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n\r\n", "http", "nginx", "1.18.0"),
        (80, b"HTTP/1.1 404 Not Found\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n", "http", "Apache httpd", "2.4.41"),
        (6379, b"$3000\r\n# Server\r\nredis_version:6.0.16\r\n", "redis", "Redis", "6.0.16"),
        (5900, b"RFB 003.008\n", "vnc", "VNC", "003.008"),
    ],
)
def test_identify(port, data, name, product, version):
    ident = identify(port, data, tls=False)
    assert (ident.name, ident.product, ident.version) == (name, product, version)


def test_identify_mysql_greeting():
    greeting = b"\x4a\x00\x00\x00\x0a8.0.36-0ubuntu0.22.04.1\x00" + b"\x00" * 40
    ident = identify(3306, greeting, tls=False)
    assert ident.product == "MySQL"
    assert ident.version == "8.0.36"


def test_redis_auth_detection():
    assert identify(6379, b"redis_version:7.2.0", False).extra["auth"] == "none"
    assert identify(6379, b"-NOAUTH Authentication required.\r\n", False).extra["auth"] == "required"


def test_https_on_unknown_port():
    ident = identify(4321, b"HTTP/1.1 200 OK\r\n\r\n", tls=True)
    assert ident.name == "https"


def test_banner_keeps_only_text():
    from tbm.scout.banner import _clean_banner, _protocol_banner

    dropbear = b"SSH-2.0-dropbear_2020.80\r\n\x00\x00\x01\xbc\x07\x14\xa7\xe6\x10curve25519-sha256"
    assert _clean_banner(_protocol_banner("ssh", dropbear)) == "SSH-2.0-dropbear_2020.80"
    assert _clean_banner(b"220 ok\xbc\xe6") == "220 ok.."  # Latin-1 "imprimível" vira ponto


def test_telnet_iac():
    assert identify(2323, b"\xff\xfd\x18\xff\xfd\x20", False).name == "telnet"


def test_parse_ports():
    assert parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]
    assert 443 in parse_ports("common")
    assert len(parse_ports("all")) == 65535
    with pytest.raises(ValueError):
        parse_ports("0")
