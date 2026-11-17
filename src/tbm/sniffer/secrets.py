"""Detector de segredos vazados em código ou configuração (diretório local).

Combina regras de alta precisão (formatos conhecidos de tokens) com uma regra
genérica de atribuição filtrada por entropia de Shannon, para não acusar
`password = "changeme"`.
"""

from __future__ import annotations

import asyncio
import math
import re
from collections import Counter
from contextlib import suppress
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from tbm.models import Finding, Severity
from tbm.sniffer.base import Check, CheckContext, register

CHECK_ID = "secrets.local"
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox",
             ".mypy_cache", ".pytest_cache", ".ruff_cache", ".idea", ".tbm", "target"}
MAX_FILE_SIZE = 2 * 1024 * 1024


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    group: int = 0
    min_entropy: float = 0.0


RULES: tuple[Rule, ...] = (
    Rule("aws-access-key", "AWS Access Key ID", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
         Severity.HIGH, 1),
    Rule("github-token", "Token do GitHub",
         re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
         Severity.HIGH, 1),
    Rule("slack-token", "Token do Slack", re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"),
         Severity.HIGH, 1),
    Rule("google-api-key", "Google API key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
         Severity.MEDIUM, 1),
    Rule("stripe-live", "Chave live do Stripe", re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{20,})\b"),
         Severity.CRITICAL, 1),
    Rule("openai-key", "API key estilo OpenAI/Anthropic",
         re.compile(r"\b(sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{32,})\b"), Severity.HIGH, 1),
    Rule("private-key", "Chave privada",
         re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY"),
         Severity.CRITICAL),
    Rule("jwt", "JSON Web Token",
         re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
         Severity.MEDIUM, 1),
    Rule("connection-string", "Connection string com senha",
         re.compile(r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:([^@\s/]{4,})@)"),
         Severity.HIGH, 1),
    Rule("generic-secret", "Segredo atribuído no código",
         re.compile(r"""(?i)\b[\w.-]*(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|credential)[\w.-]*"""
                    r"""\s*[:=]\s*['"]([^'"\s]{8,})['"]"""),
         Severity.MEDIUM, 1, min_entropy=3.2),
)

PLACEHOLDERS = re.compile(
    r"(?i)(changeme|example|placeholder|your[_-]?|xxxx|dummy|sample|<.*>|\$\{|\{\{|os\.environ|"
    r"process\.env|getenv|redacted|\*\*\*)"
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * min(len(value) - 6, 24)}{value[-2:]}"


def _is_text(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return b"\x00" not in fh.read(2048)
    except OSError:
        return False


def iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_file() and path.stat().st_size <= MAX_FILE_SIZE and _is_text(path):
            yield path


PRAGMA = "tbm:allow"  # comentário na linha = falso positivo conhecido
IGNORE_FILE = ".tbmignore"


def load_ignore(base: Path) -> list[str]:
    path = base / IGNORE_FILE
    if not path.is_file():
        return []
    lines = (ln.strip() for ln in path.read_text(encoding="utf-8").splitlines())
    return [ln.rstrip("/") for ln in lines if ln and not ln.startswith("#")]


def is_ignored(rel: str, patterns: list[str]) -> bool:
    """Sintaxe estilo .gitignore simplificada: 'tests/', 'tests/**', '*.lock', 'docs/x.md'."""
    name = rel.rsplit("/", 1)[-1]
    for p in patterns:
        base = p.removesuffix("/**")
        if fnmatch(rel, p) or fnmatch(name, p) or rel == base or rel.startswith(base + "/"):
            return True
    return False


def scan_text(text: str, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 5000 or PRAGMA in line:  # minificado/dados, ou liberado explicitamente
            continue
        matched = False
        for rule in RULES:
            if matched:  # uma regra por linha basta (a mais específica vem primeiro)
                break
            for m in rule.pattern.finditer(line):
                secret = m.group(rule.group) if rule.group else m.group(0)
                if rule.id == "connection-string":
                    secret = m.group(2)
                if rule.min_entropy and (
                    shannon_entropy(secret) < rule.min_entropy or PLACEHOLDERS.search(secret)
                ):
                    continue
                shown = line.strip().replace(secret, mask(secret))[:200]
                findings.append(Finding(
                    check_id=CHECK_ID,
                    key=f"{rel}:{lineno}:{rule.id}",
                    severity=rule.severity,
                    title=f"{rule.title} em {rel}",
                    host="local",
                    file=rel,
                    line=lineno,
                    description="Credenciais em código acabam em repositórios, backups e "
                                "imagens de container.",
                    evidence=f"{rel}:{lineno}  {shown}",
                    remediation="Revogue e rotacione a credencial, depois mova para variáveis de "
                                "ambiente ou um cofre (Vault, 1Password, AWS Secrets Manager). "
                                "Se foi commitada, limpe o histórico (git filter-repo).",
                ))
                matched = True
                break
    return findings


def _relative(path: Path, root: Path, base: Path) -> str:
    with suppress(ValueError):
        return path.relative_to(base).as_posix()
    return path.name if root.is_file() else path.relative_to(root).as_posix()


def scan_paths(paths: list[Path], base: Path | None = None) -> list[Finding]:
    """Varre arquivos e diretórios. Caminhos e o .tbmignore são relativos a `base`.

    Com `base` = raiz do repositório, os caminhos batem com os do git, e é isso
    que permite ao GitHub (via SARIF) anotar a linha exata no PR.
    """
    base = (base or Path.cwd()).resolve()
    patterns = load_ignore(base)
    findings: list[Finding] = []
    seen: set[Path] = set()
    for root in (p.resolve() for p in paths):
        for path in iter_files(root):
            if path in seen:
                continue
            seen.add(path)
            rel = _relative(path, root, base)
            if is_ignored(rel, patterns):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            findings += scan_text(text, rel)
    return findings


def scan_path(root: Path) -> list[Finding]:
    root = root.resolve()
    return scan_paths([root], base=root if root.is_dir() else root.parent)


@register
class SecretsCheck(Check):
    id = CHECK_ID
    name = "Segredos em arquivos locais"

    def enabled(self, options) -> bool:
        return options.secrets_path is not None and super().enabled(options)

    async def run(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.options.secrets_path is not None
        return await asyncio.to_thread(scan_path, ctx.options.secrets_path)
