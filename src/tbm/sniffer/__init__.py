"""Sniffer: análise. Transforma o que o Scout viu em achados de segurança."""

from tbm.sniffer.base import REGISTRY, Check, CheckContext, SnifferOptions, register
from tbm.sniffer.engine import Sniffer

__all__ = ["REGISTRY", "Check", "CheckContext", "Sniffer", "SnifferOptions", "register"]
