"""Listas de portas e parsing de especificações de portas."""

from __future__ import annotations

COMMON_PORTS: tuple[int, ...] = tuple(
    sorted(
        {
            21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445,
            465, 515, 548, 554, 587, 631, 636, 873, 993, 995, 1025, 1080, 1433, 1521,
            1723, 1883, 2049, 2082, 2083, 2222, 2375, 2376, 3000, 3128, 3306, 3389,
            4443, 5000, 5001, 5060, 5357, 5432, 5555, 5601, 5672, 5900, 5984, 5985,
            5986, 6379, 6443, 7001, 7547, 8000, 8008, 8009, 8080, 8081, 8088, 8123,
            8291, 8443, 8883, 8888, 9000, 9001, 9090, 9091, 9100, 9200, 9443, 10000,
            11211, 15672, 27017, 32400, 37777, 49152, 50000, 62078,
        }
    )
)

SERVICE_NAMES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 81: "http",
    88: "kerberos", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 515: "printer",
    548: "afp", 554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 1883: "mqtt", 2049: "nfs", 2222: "ssh", 2375: "docker",
    2376: "docker-tls", 3000: "http", 3128: "http-proxy", 3306: "mysql", 3389: "rdp",
    4443: "https", 5000: "http", 5001: "https", 5060: "sip", 5357: "wsdapi",
    5432: "postgresql", 5555: "adb", 5601: "kibana", 5672: "amqp", 5900: "vnc",
    5984: "couchdb", 5985: "winrm", 5986: "winrm-tls", 6379: "redis", 6443: "kubernetes",
    7547: "tr069", 8000: "http", 8008: "http", 8009: "ajp/googlecast", 8080: "http", 8081: "http",
    8088: "http", 8123: "http", 8291: "mikrotik-winbox", 8443: "https", 8883: "mqtt-tls",
    8888: "http", 9000: "http", 9090: "http", 9091: "http", 9100: "jetdirect",
    9200: "elasticsearch", 9443: "https", 10000: "http", 11211: "memcached",
    15672: "http", 27017: "mongodb", 32400: "http", 62078: "iphone-sync",
}

# Portas onde o handshake TLS vem primeiro.
TLS_PORTS = frozenset({443, 465, 636, 993, 995, 2376, 4443, 5001, 5986, 6443, 8443, 8883, 9443})

# Portas onde mandamos um GET logo de cara em vez de esperar o servidor falar.
HTTP_PORTS = frozenset(
    {80, 81, 443, 591, 2375, 2376, 3000, 4443, 5000, 5001, 5601, 5984, 6443, 8000, 8008,
     8080, 8081, 8088, 8123, 8443, 8888, 9000, 9090, 9091, 9200, 9443, 10000, 15672, 32400}
)

PORT_PRESETS = {"common": COMMON_PORTS, "web": tuple(sorted(HTTP_PORTS))}


def parse_ports(spec: str) -> list[int]:
    """Aceita 'common', 'web', 'all', '22,80,443', '1-1024' ou combinações."""
    spec = spec.strip().lower()
    if spec == "all":
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in filter(None, (p.strip() for p in spec.split(","))):
        if part in PORT_PRESETS:
            ports.update(PORT_PRESETS[part])
        elif "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            if not 1 <= lo <= hi <= 65535:
                raise ValueError(f"faixa de portas inválida: {part}")
            ports.update(range(lo, hi + 1))
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError(f"porta inválida: {part}")
            ports.add(port)
    if not ports:
        raise ValueError("nenhuma porta especificada")
    return sorted(ports)
