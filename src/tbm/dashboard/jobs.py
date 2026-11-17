"""Scans disparados pela interface gráfica, com progresso consultável.

Cada scan roda numa thread própria com o seu event loop:
- o servidor web continua respondendo (inclusive às consultas de progresso);
- no Windows, garantimos o ProactorEventLoop, o único que suporta os
  subprocessos do ping e da tabela ARP, seja qual for o loop do servidor.

Um scan por vez: dois scans simultâneos na mesma rede só se atrapalham.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
import threading
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, field_validator

from tbm.models import ScanResult, Severity, utcnow
from tbm.paths import cache_dir, tbm_home
from tbm.pipeline import ScanJob, execute
from tbm.scope import Scope, ScopeError
from tbm.scout import ScoutOptions, parse_ports
from tbm.sniffer import SnifferOptions
from tbm.squeak import HistoryStore, ScanDiff, send_webhook, write_report


class ScanParams(BaseModel):
    """O que o formulário de novo scan envia."""

    targets: str
    label: str = "casa"
    ports: str = "common"
    udp: bool = True
    active: bool = False
    gentle: bool = False
    cve: bool = True

    @field_validator("label")
    @classmethod
    def _label(cls, v: str) -> str:
        v = v.strip()
        if not re.fullmatch(r"[\w.-]{1,40}", v):
            raise ValueError("use só letras, números, ponto, hífen ou sublinhado (até 40)")
        return v

    @field_validator("ports")
    @classmethod
    def _ports(cls, v: str) -> str:
        parse_ports(v)  # levanta ValueError com mensagem clara
        return v

    @property
    def target_list(self) -> list[str]:
        items = [t for t in re.split(r"[\s,;]+", self.targets) if t]
        if not items:
            raise ValueError("informe pelo menos um alvo")
        return items


@dataclass
class Job:
    id: str
    params: ScanParams
    status: str = "queued"  # queued | running | done | error
    phases: dict[str, list[int]] = field(default_factory=dict)  # fase → [feito, total]
    log: list[str] = field(default_factory=list)
    started: datetime = field(default_factory=utcnow)
    finished: datetime | None = None
    summary: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "status": self.status, "label": self.params.label,
            "phases": [{"name": k, "done": d, "total": t} for k, (d, t) in self.phases.items()],
            "log": self.log[-20:], "summary": self.summary, "error": self.error,
            "elapsed": round(((self.finished or utcnow()) - self.started).total_seconds(), 1),
        }


class JobProgress:
    """ProgressHook que só anota números: a página consulta e desenha as barras."""

    def __init__(self, job: Job) -> None:
        self.job = job

    def start(self, phase: str, total: int) -> None:
        done, prev = self.job.phases.get(phase, [0, 0])
        self.job.phases[phase] = [done, prev + total]

    def advance(self, phase: str, amount: int = 1) -> None:
        if phase in self.job.phases:
            self.job.phases[phase][0] += amount

    def log(self, message: str) -> None:
        if "\n" not in message:  # tracebacks ficam fora da interface
            self.job.log.append(message)


Executor = Callable[[ScanJob, HistoryStore, Any], Awaitable[tuple[ScanResult, ScanDiff]]]


def build_scan_job(p: ScanParams) -> ScanJob:
    scope = Scope.default()
    targets = p.target_list
    scope.resolve(targets)  # falha cedo (ScopeError) antes de criar a thread
    ports = parse_ports(p.ports)
    common: dict[str, Any] = dict(udp=p.udp, timeout=1.0)
    scout = ScoutOptions.gentle(ports, **common) if p.gentle else ScoutOptions(ports=ports, **common)
    sniffer = SnifferOptions(
        active=p.active, cve=p.cve, nvd_api_key=os.environ.get("NVD_API_KEY"),
        cache_dir=cache_dir("intel"), scope=scope,
    )
    return ScanJob(specs=targets, scope=scope, label=p.label, scout_options=scout, sniffer_options=sniffer)


class BusyError(RuntimeError):
    pass


class JobRunner:
    def __init__(self, store: HistoryStore, executor: Executor = execute) -> None:
        self.store = store
        self.executor = executor
        self.jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._current: str | None = None

    @property
    def current(self) -> Job | None:
        return self.jobs.get(self._current) if self._current else None

    def submit(self, params: ScanParams) -> Job:
        spec = build_scan_job(params)  # ScopeError/ValueError sobem para a rota
        with self._lock:
            if self._current and self.jobs[self._current].status in ("queued", "running"):
                raise BusyError("já existe um scan em andamento")
            job = Job(id=uuid.uuid4().hex[:10], params=params)
            self.jobs[job.id] = job
            self._current = job.id
        threading.Thread(target=self._run, args=(job, spec), daemon=True, name=f"tbm-scan-{job.id}").start()
        return job

    def _run(self, job: Job, spec: ScanJob) -> None:
        # `if` em vez de ternário: o mypy só entende checagem de plataforma em
        # instrução `if`. No Linux, asyncio.ProactorEventLoop nem existe.
        loop: asyncio.AbstractEventLoop
        if sys.platform == "win32":
            loop = asyncio.ProactorEventLoop()
        else:
            loop = asyncio.new_event_loop()
        job.status = "running"
        try:
            result, diff = loop.run_until_complete(self.executor(spec, self.store, JobProgress(job)))
            report = tbm_home() / "reports" / f"tbm-{result.label}-{result.started_at:%Y%m%d-%H%M%S}.html"
            write_report(result, report, diff)
            alerted = None
            if webhook := os.environ.get("TBM_WEBHOOK"):
                try:
                    alerted = loop.run_until_complete(send_webhook(webhook, result, diff, Severity.MEDIUM))
                except Exception as exc:  # noqa: BLE001 (o alerta não invalida o scan)
                    job.log.append(f"falha ao enviar alerta: {exc.__class__.__name__}")
            job.summary = summarize(result, diff, report, alerted)
            job.status = "done"
        except ScopeError as exc:
            job.status, job.error = "error", str(exc)
        except Exception as exc:  # noqa: BLE001
            job.status, job.error = "error", f"{exc.__class__.__name__}: {exc}"
        finally:
            job.finished = utcnow()
            loop.close()


def summarize(result: ScanResult, diff: ScanDiff, report: Path, alerted: bool | None) -> dict[str, Any]:
    counts = {s.value: n for s, n in result.severity_counts().items()}
    return {
        "scan_id": result.scan_id, "label": result.label, "score": result.score, "grade": result.grade,
        "hosts": len(result.hosts), "findings": len(result.findings), "counts": counts,
        "accepted": sum(1 for f in result.findings if f.accepted),
        "new_findings": len(diff.new_findings), "resolved": len(diff.resolved_findings),
        "new_devices": [h.display for h in diff.alert_hosts],
        "previous": diff.previous_id, "score_delta": diff.score_delta,
        "report": str(report), "alerted": alerted,
    }
