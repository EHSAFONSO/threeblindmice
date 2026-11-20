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

from tbm.config import notify_target
from tbm.dashboard.icons import device_icon
from tbm.models import ScanResult, Severity, utcnow
from tbm.paths import cache_dir, tbm_home
from tbm.pipeline import ScanJob, execute
from tbm.scope import Scope, ScopeError
from tbm.scout import ScoutOptions, parse_ports
from tbm.sniffer import SnifferOptions
from tbm.squeak import HistoryStore, ScanDiff, diff_scans, send_webhook, write_report


class ScanParams(BaseModel):
    """O que o formulário de novo scan envia."""

    targets: str
    label: str = "casa"
    ports: str = "common"
    udp: bool = True
    active: bool = False
    gentle: bool = False
    cve: bool = True
    external: bool = False

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
    status: str = "queued"  # queued | running | done | error | cancelled
    phases: dict[str, list[int]] = field(default_factory=dict)  # fase → [feito, total]
    log: list[str] = field(default_factory=list)
    devices: dict[str, dict[str, Any]] = field(default_factory=dict)  # aparecem ao vivo na tela
    started: datetime = field(default_factory=utcnow)
    finished: datetime | None = None
    summary: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "status": self.status, "label": self.params.label,
            "phases": [{"name": k, "done": d, "total": t} for k, (d, t) in self.phases.items()],
            "log": self.log[-20:], "summary": self.summary, "error": self.error,
            "devices": [{**d, "icon": device_icon(d.get("type"))} for d in self.devices.values()],
            "elapsed": round(((self.finished or utcnow()) - self.started).total_seconds(), 1),
            "eta": self.eta(),
        }

    def eta(self) -> int | None:
        """Segundos que faltam, pelo ritmo até aqui (None enquanto não dá para estimar).

        Aproximado: as fases somam itens de custos diferentes e o total cresce quando
        aparecem serviços para identificar. Serve para "uns 3 minutos", não para cronômetro.
        """
        if self.status != "running":
            return None
        done = sum(d for d, _ in self.phases.values())
        total = sum(t for _, t in self.phases.values())
        elapsed = (utcnow() - self.started).total_seconds()
        if total <= 0 or done < max(1, total * 0.05) or elapsed < 3:
            return None
        return max(0, round(elapsed * (total - done) / done))


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

    def found(self, address: str, **info: Any) -> None:
        current = self.job.devices.setdefault(address, {"address": address})
        current.update({k: v for k, v in info.items() if v is not None})


Executor = Callable[[ScanJob, HistoryStore, Any], Awaitable[tuple[ScanResult, ScanDiff]]]


def build_scan_job(p: ScanParams) -> ScanJob:
    scope = Scope.default()
    targets = p.target_list
    scope.resolve(targets)  # falha cedo (ScopeError) antes de criar a thread
    ports = parse_ports(p.ports)
    common: dict[str, Any] = dict(udp=p.udp, timeout=1.0)
    scout = ScoutOptions.gentle(ports, **common) if p.gentle else ScoutOptions(ports=ports, **common)
    sniffer = SnifferOptions(
        active=p.active, cve=p.cve, external=p.external, nvd_api_key=os.environ.get("NVD_API_KEY"),
        cache_dir=cache_dir("intel"), scope=scope,
    )
    return ScanJob(specs=targets, scope=scope, label=p.label, scout_options=scout, sniffer_options=sniffer)


class BusyError(RuntimeError):
    pass


def merge_host(latest: ScanResult, partial: ScanResult, address: str) -> ScanResult:
    """O último scan da rede, com o aparelho `address` trocado pelo resultado da verificação.

    Os outros aparelhos e os achados da rede como um todo (Wi-Fi, IPv6, DNS) ficam
    como estavam: a verificação só olhou um aparelho, então só ele muda.
    """
    import ipaddress
    import uuid as _uuid

    from tbm.pipeline import finalize

    merged = latest.model_copy(deep=True)
    merged.scan_id = _uuid.uuid4().hex[:12]
    merged.started_at = utcnow()
    hosts = [h for h in merged.hosts if h.address != address]
    if (fresh := partial.host(address)) is not None:
        hosts.append(fresh)

    def order(h):
        try:
            return (0, int(ipaddress.ip_address(h.address)))
        except ValueError:
            return (1, 0)

    merged.hosts = sorted(hosts, key=order)
    network = ("network.",)
    kept = [f for f in merged.findings if f.host != address or f.check_id.startswith(network)]
    merged.findings = kept + [f for f in partial.findings if f.host == address and not f.check_id.startswith(network)]
    merged.errors = partial.errors
    return finalize(merged)


class JobRunner:
    def __init__(self, store: HistoryStore, executor: Executor = execute,
                 on_done: Callable[[Job], None] | None = None) -> None:
        self.store = store
        self.executor = executor
        self.on_done = on_done  # ex.: notificação na bandeja do app de desktop
        self.jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._current: str | None = None
        self._tasks: dict[str, tuple[asyncio.AbstractEventLoop, asyncio.Task[tuple[ScanResult, ScanDiff]]]] = {}

    def cancel(self, job_id: str) -> bool:
        """Pede o cancelamento do scan em andamento (de qualquer thread). False se não há o que cancelar."""
        job = self.jobs.get(job_id)
        entry = self._tasks.get(job_id)
        if job is None or entry is None or job.status not in ("queued", "running"):
            return False
        loop, task = entry
        job.log.append("cancelando…")
        loop.call_soon_threadsafe(task.cancel)
        return True

    def _execute(self, loop: asyncio.AbstractEventLoop, job: Job, spec: ScanJob) -> tuple[ScanResult, ScanDiff]:
        async def main() -> tuple[ScanResult, ScanDiff]:
            return await self.executor(spec, self.store, JobProgress(job))

        task: asyncio.Task[tuple[ScanResult, ScanDiff]] = loop.create_task(main())
        self._tasks[job.id] = (loop, task)
        try:
            return loop.run_until_complete(task)
        finally:
            self._tasks.pop(job.id, None)

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

    def submit_verify(self, label: str, address: str, fingerprints: list[str]) -> Job:
        """Re-escaneia só um aparelho e confere se os achados de uma ação sumiram."""
        params = ScanParams(targets=address, label=label)
        spec = build_scan_job(params)
        spec.save = False
        with self._lock:
            if self._current and self.jobs[self._current].status in ("queued", "running"):
                raise BusyError("já existe um scan em andamento")
            job = Job(id=uuid.uuid4().hex[:10], params=params)
            self.jobs[job.id] = job
            self._current = job.id
        threading.Thread(target=self._run_verify, args=(job, spec, label, address, fingerprints), daemon=True,
                         name=f"tbm-verify-{job.id}").start()
        return job

    def _run_verify(self, job: Job, spec: ScanJob, label: str, address: str, fingerprints: list[str]) -> None:
        loop: asyncio.AbstractEventLoop
        if sys.platform == "win32":
            loop = asyncio.ProactorEventLoop()
        else:
            loop = asyncio.new_event_loop()
        job.status = "running"
        try:
            before = self.store.latest(label)
            partial, _ = self._execute(loop, job, spec)
            if before is None:
                raise RuntimeError("não há scan anterior para comparar")
            merged = merge_host(before, partial, address)
            self.store.save(merged)
            still = {f.fingerprint for f in merged.findings if not f.accepted}
            wanted = [f for f in before.findings if f.fingerprint in set(fingerprints)]
            verify = {
                "resolved": [f.title for f in wanted if f.fingerprint not in still],
                "remaining": [f.title for f in wanted if f.fingerprint in still],
                "before": {"score": before.score, "grade": before.grade},
                "after": {"score": merged.score, "grade": merged.grade},
            }
            self.store.add_event("verify", {"resolved": len(verify["resolved"]), "remaining": len(verify["remaining"]),
                                            "grade": merged.grade, "score": merged.score},
                                 label=label, link=f"/findings/{label}")
            job.summary = {**summarize(merged, diff_scans(before, merged), None, None), "verify": verify}
            job.status = "done"
        except asyncio.CancelledError:
            job.status, job.error = "cancelled", "scan cancelado"
        except Exception as exc:  # noqa: BLE001
            job.status, job.error = "error", f"{exc.__class__.__name__}: {exc}"
        finally:
            job.finished = utcnow()
            loop.close()

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
            result, diff = self._execute(loop, job, spec)
            report = tbm_home() / "reports" / f"tbm-{result.label}-{result.started_at:%Y%m%d-%H%M%S}.html"
            write_report(result, report, diff)
            alerted = None
            if webhook := notify_target()[0]:
                try:
                    alerted = loop.run_until_complete(send_webhook(webhook, result, diff, Severity.MEDIUM))
                except Exception as exc:  # noqa: BLE001 (o alerta não invalida o scan)
                    job.log.append(f"falha ao enviar alerta: {exc.__class__.__name__}")
                    from tbm.log import get_logger

                    # sem exc_info: a mensagem do httpx traz a URL, e a do Telegram tem o token
                    get_logger(__name__).warning("falha ao enviar alerta: %s", exc.__class__.__name__)
                try:
                    from tbm.squeak import summary

                    if loop.run_until_complete(summary.maybe_send(self.store, result.label, webhook)):
                        job.log.append("resumo semanal enviado")
                except Exception as exc:  # noqa: BLE001
                    job.log.append(f"falha ao enviar o resumo semanal: {exc.__class__.__name__}")
            job.summary = summarize(result, diff, report, alerted)
            job.status = "done"
        except ScopeError as exc:
            job.status, job.error = "error", str(exc)
        except asyncio.CancelledError:
            job.status, job.error = "cancelled", "scan cancelado"
        except Exception as exc:  # noqa: BLE001
            job.status, job.error = "error", f"{exc.__class__.__name__}: {exc}"
        finally:
            job.finished = utcnow()
            loop.close()
            if self.on_done is not None:
                try:
                    self.on_done(job)
                except Exception:  # noqa: BLE001,S110 (a notificação nunca derruba o scan)
                    pass


def summarize(result: ScanResult, diff: ScanDiff, report: Path | None, alerted: bool | None) -> dict[str, Any]:
    counts = {s.value: n for s, n in result.severity_counts().items()}
    return {
        "scan_id": result.scan_id, "label": result.label, "score": result.score, "grade": result.grade,
        "hosts": len(result.hosts), "findings": len(result.findings), "counts": counts,
        "accepted": sum(1 for f in result.findings if f.accepted),
        "new_findings": len(diff.new_findings), "resolved": len(diff.resolved_findings),
        "new_devices": [h.display for h in diff.alert_hosts],
        "previous": diff.previous_id, "score_delta": diff.score_delta,
        "report": str(report) if report else None, "alerted": alerted,
    }
