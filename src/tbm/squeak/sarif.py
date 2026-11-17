"""Exportação em SARIF 2.1.0, o formato que o GitHub Code Scanning entende.

Achados com arquivo e linha (segredos) viram anotações no PR. Achados de rede
não têm arquivo, então vão como "logical location" (host:porta). O GitHub
aceita o upload, mas só exibe na aba Security os achados com local físico.
"""

from __future__ import annotations

from typing import Any

from tbm import __version__
from tbm.models import Finding, ScanResult, Severity

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# "security-severity" é o campo que o GitHub usa para classificar (0–10, estilo CVSS).
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def rule_id(f: Finding) -> str:
    if f.check_id == "secrets.local" and f.key:
        return f"{f.check_id}/{f.key.rsplit(':', 1)[-1]}"
    return f.check_id


def _result(f: Finding) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": rule_id(f),
        "level": LEVEL[f.severity],
        "message": {"text": f"{f.title}. {f.evidence}".strip()},
        "partialFingerprints": {"tbmFingerprint/v1": f.fingerprint},
        "properties": {"severity": f.severity.value},
    }
    if f.file:
        location: dict[str, Any] = {"artifactLocation": {"uri": f.file}}
        if f.line:
            location["region"] = {"startLine": f.line}
        result["locations"] = [{"physicalLocation": location}]
    else:
        result["locations"] = [{"logicalLocations": [{"name": f.location, "kind": "resource"}]}]
    if f.cvss is not None:
        result["properties"]["cvss"] = f.cvss
    if f.epss is not None:
        result["properties"]["epss"] = f.epss
    return result


def to_sarif(result: ScanResult) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    for f in result.findings:
        rid = rule_id(f)
        current = rules.get(rid)
        # A regra herda a maior severidade entre os achados dela.
        if current and float(current["properties"]["security-severity"]) >= float(
            SECURITY_SEVERITY[f.severity]
        ):
            continue
        rules[rid] = {
            "id": rid,
            "name": rid.replace(".", "_").replace("/", "_"),
            "shortDescription": {"text": f.title.split(" em ")[0]},
            "fullDescription": {"text": f.description or f.title},
            "help": {"text": f.remediation or "-"},
            "helpUri": f.references[0] if f.references else "https://github.com/",
            "properties": {"security-severity": SECURITY_SEVERITY[f.severity], "tags": ["security"]},
        }
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "threeblindmice",
                "version": __version__,
                "informationUri": "https://github.com/",
                "rules": sorted(rules.values(), key=lambda r: r["id"]),
            }},
            "results": [_result(f) for f in result.findings],
        }],
    }
