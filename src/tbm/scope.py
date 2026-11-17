"""Controle de escopo: o tbm só toca no que você autorizou.

Regra padrão: apenas redes privadas. Para alvos públicos, é obrigatório um
scope.yaml com `authorized: true` listando explicitamente os alvos.
Toda expansão de alvo (CIDR, faixa, hostname) passa por aqui antes de
qualquer pacote sair da máquina.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

import yaml

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

PRIVATE_NETWORKS: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",  # CGNAT (Tailscale etc.)
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

MAX_TARGETS = 65_536
_RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")


class ScopeError(ValueError):
    """Alvo inválido ou fora do escopo autorizado."""


@dataclass(frozen=True)
class Target:
    address: str
    hostname: str | None = None


def _resolve(name: str) -> list[IPAddress]:
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ScopeError(f"não foi possível resolver '{name}': {exc}") from exc
    # dict.fromkeys preserva a ordem e remove duplicatas
    addrs = dict.fromkeys(ipaddress.ip_address(str(info[4][0]).split("%")[0]) for info in infos)
    return list(addrs)


def _parse_network_entry(entry: str) -> list[IPNetwork]:
    try:
        return [ipaddress.ip_network(entry, strict=False)]
    except ValueError:
        return [ipaddress.ip_network(ip) for ip in _resolve(entry)]


def expand_target(spec: str) -> Iterator[Target]:
    """Expande '10.0.0.0/24', '192.168.1.10-20', '10.0.0.5' ou 'host.lan' em alvos."""
    spec = spec.strip()
    if m := _RANGE_RE.match(spec):
        prefix, start, end = m.group(1), int(m.group(2)), int(m.group(3))
        if not 0 <= start <= end <= 255:
            raise ScopeError(f"faixa inválida: {spec}")
        for i in range(start, end + 1):
            try:
                yield Target(str(ipaddress.ip_address(f"{prefix}{i}")))
            except ValueError as exc:
                raise ScopeError(f"faixa inválida: {spec}") from exc
        return

    try:
        net = ipaddress.ip_network(spec, strict=False)
    except ValueError:
        for ip in _resolve(spec):
            yield Target(str(ip), hostname=spec)
        return

    if net.num_addresses > MAX_TARGETS:
        raise ScopeError(f"{spec} tem {net.num_addresses} endereços; o limite é {MAX_TARGETS}")
    if net.num_addresses == 1:
        yield Target(str(net.network_address))
        return
    for ip in net.hosts():
        yield Target(str(ip))


@dataclass(frozen=True)
class Scope:
    allowed: tuple[IPNetwork, ...]
    excluded: tuple[IPNetwork, ...] = ()
    source: str = "padrão: somente redes privadas"

    @classmethod
    def default(cls) -> Scope:
        return cls(PRIVATE_NETWORKS)

    @classmethod
    def from_file(cls, path: str | Path) -> Scope:
        path = Path(path)
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ScopeError(f"não foi possível ler {path}: {exc}") from exc
        if data.get("authorized") is not True:
            raise ScopeError(
                f"{path}: declare 'authorized: true' para confirmar que você tem "
                "autorização para testar os alvos listados"
            )
        allowed = tuple(n for e in data.get("allow") or [] for n in _parse_network_entry(str(e)))
        if not allowed:
            raise ScopeError(f"{path}: a lista 'allow' está vazia")
        excluded = tuple(n for e in data.get("exclude") or [] for n in _parse_network_entry(str(e)))
        owner = data.get("owner") or "?"
        return cls(allowed, excluded, source=f"{path} (responsável: {owner})")

    @staticmethod
    def _in(addr: IPAddress, nets: Iterable[IPNetwork]) -> bool:
        return any(addr in n for n in nets)

    def is_excluded(self, ip: str) -> bool:
        return self._in(ipaddress.ip_address(ip), self.excluded)

    def contains(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return not self._in(addr, self.excluded) and self._in(addr, self.allowed)

    def resolve(self, specs: Iterable[str]) -> list[Target]:
        """Expande e valida todos os alvos. Falha antes de escanear qualquer coisa."""
        targets: dict[str, Target] = {}
        for spec in specs:
            for t in expand_target(spec):
                if self.is_excluded(t.address):
                    continue
                if not self._in(ipaddress.ip_address(t.address), self.allowed):
                    raise ScopeError(
                        f"{t.address} (de '{spec}') está fora do escopo autorizado "
                        f"[{self.source}]. Use --scope com um scope.yaml para alvos públicos."
                    )
                targets.setdefault(t.address, t)
                if len(targets) > MAX_TARGETS:
                    raise ScopeError(f"mais de {MAX_TARGETS} alvos; divida o scan")
        if not targets:
            raise ScopeError("nenhum alvo restante depois de aplicar as exclusões")
        return list(targets.values())
