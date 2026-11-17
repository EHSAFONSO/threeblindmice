"""Agendamento do scan pelo próprio sistema operacional.

O `tbm watch` morre quando o terminal fecha. Para um vigia de verdade,
registramos um scan periódico no agendador do SO:
- Windows: Agendador de Tarefas (schtasks), rodando com pythonw, sem janela
- Linux: timer do systemd do usuário (sem root)
- macOS e outros: linha de crontab para você colar

Cada execução é um `tbm scan` normal, sem --notify: o destino dos alertas
vem da configuração (TBM_WEBHOOK ou config.json), então nenhum segredo fica
gravado na definição da tarefa.
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from tbm.paths import no_window, tbm_home


@dataclass
class SchedulePlan:
    platform: str
    description: str
    files: dict[Path, str] = field(default_factory=dict)  # arquivos a criar
    commands: list[list[str]] = field(default_factory=list)  # comandos a executar
    manual: str | None = None  # instrução para o usuário quando não dá para automatizar
    warnings: list[str] = field(default_factory=list)
    cleanup: list[Path] = field(default_factory=list)  # arquivos a apagar (na remoção)


def task_name(label: str) -> str:
    return f"threeblindmice-{label}"


def tbm_executable() -> str:
    found = shutil.which("tbm")
    if found:
        return found
    return str(Path(sys.executable).with_name("tbm.exe" if sys.platform == "win32" else "tbm"))


def scan_args(targets: list[str], label: str, extra: list[str]) -> list[str]:
    """Argumentos do `tbm scan` (sem o executável)."""
    report = tbm_home() / "reports" / f"tbm-{label}-latest.html"
    return ["scan", *targets, "--label", label, "--report", str(report), *extra]


def scan_argv(targets: list[str], label: str, extra: list[str]) -> list[str]:
    return [tbm_executable(), *scan_args(targets, label, extra)]


def windows_spec(label: str) -> Path:
    return tbm_home() / "schedules" / f"{task_name(label)}.json"


def windows_wrapper(label: str) -> Path:
    """Formato antigo (v0.3.1): mantido só para limpar na remoção."""
    return tbm_home() / "schedules" / f"{task_name(label)}.cmd"


def log_path(label: str) -> Path:
    return tbm_home() / "logs" / f"{label}.log"


def pythonw() -> Path | None:
    """pythonw.exe: o mesmo Python, sem console. É o que evita a janela preta."""
    candidate = Path(sys.executable).with_name("pythonw.exe")
    return candidate if candidate.exists() else None


def _windows_schedule(seconds: int) -> list[str]:
    if seconds % 86400 == 0:
        return ["/SC", "DAILY", "/MO", str(seconds // 86400)]
    if seconds % 3600 == 0:
        return ["/SC", "HOURLY", "/MO", str(seconds // 3600)]
    return ["/SC", "MINUTE", "/MO", str(max(1, seconds // 60))]


def build_plan(platform: str, targets: list[str], label: str, seconds: int,
               extra: list[str]) -> SchedulePlan:
    warnings = []
    if "--notify" in extra:
        warnings.append("O --notify fica gravado no agendamento. Prefira configurar o destino uma vez "
                        "(tbm telegram-setup ou tbm gui → Alertas) e agendar sem --notify.")

    if platform == "win32":
        # A tarefa roda `pythonw -m tbm._scheduled <rótulo>`: sem janela, e com /TR
        # curto (o limite do schtasks é 261 caracteres). Os argumentos do scan
        # ficam num JSON em TBM_HOME, e a saída de cada execução vai para um log.
        spec = windows_spec(label)
        runner = pythonw() or Path(sys.executable)
        tr = subprocess.list2cmdline([str(runner), "-m", "tbm._scheduled", label])
        content = json.dumps({"label": label, "argv": scan_args(targets, label, extra),
                              "created": datetime.now().isoformat(timespec="seconds")}, indent=2)
        if runner.name.lower() != "pythonw.exe":
            warnings.append("pythonw.exe não encontrado: a tarefa vai abrir uma janela durante o scan.")
        return SchedulePlan(
            platform="Windows (Agendador de Tarefas)",
            description=f"tarefa '{task_name(label)}' a cada {_human(seconds)}, sem janela",
            files={spec: content},
            commands=[["schtasks", "/Create", "/TN", task_name(label), "/TR", tr,
                       *_windows_schedule(seconds), "/F"]],
            warnings=warnings,
            # Reinstalar migra tarefas do formato antigo (.cmd, que abria janela).
            cleanup=[windows_wrapper(label)],
        )

    argv = scan_argv(targets, label, extra)
    if platform.startswith("linux") and shutil.which("systemctl"):
        unit_dir = Path.home() / ".config" / "systemd" / "user"
        name = task_name(label)
        service = (
            "[Unit]\nDescription=threeblindmice scan " + label + "\n\n"
            "[Service]\nType=oneshot\nExecStart=" + shlex.join(argv) + "\n"
        )
        timer = (
            "[Unit]\nDescription=threeblindmice scan periódico " + label + "\n\n"
            f"[Timer]\nOnBootSec=5min\nOnUnitActiveSec={seconds}s\nPersistent=true\n\n"
            "[Install]\nWantedBy=timers.target\n"
        )
        return SchedulePlan(
            platform="Linux (systemd --user)",
            description=f"timer '{name}.timer' a cada {_human(seconds)}",
            files={unit_dir / f"{name}.service": service, unit_dir / f"{name}.timer": timer},
            commands=[["systemctl", "--user", "daemon-reload"],
                      ["systemctl", "--user", "enable", "--now", f"{name}.timer"]],
            warnings=warnings,
        )

    minutes = max(1, seconds // 60)
    cron = f"*/{minutes} * * * *" if minutes < 60 else f"0 */{max(1, minutes // 60)} * * *"
    return SchedulePlan(
        platform="cron",
        description=f"linha de crontab a cada {_human(seconds)}",
        manual=f"Rode `crontab -e` e adicione:\n{cron} {shlex.join(argv)}",
        warnings=warnings,
    )


def remove_plan(platform: str, label: str) -> SchedulePlan:
    name = task_name(label)
    if platform == "win32":
        return SchedulePlan("Windows (Agendador de Tarefas)", f"remover '{name}'",
                            commands=[["schtasks", "/Delete", "/TN", name, "/F"]],
                            cleanup=[windows_spec(label), windows_wrapper(label)])
    if platform.startswith("linux") and shutil.which("systemctl"):
        unit_dir = Path.home() / ".config" / "systemd" / "user"
        return SchedulePlan("Linux (systemd --user)", f"remover '{name}.timer'",
                            commands=[["systemctl", "--user", "disable", "--now", f"{name}.timer"]],
                            cleanup=[unit_dir / f"{name}.service", unit_dir / f"{name}.timer"])
    return SchedulePlan("cron", "remover", manual="Rode `crontab -e` e apague a linha do threeblindmice.")


def execute(plan: SchedulePlan) -> list[str]:
    """Executa o plano. Devolve as saídas dos comandos."""
    for path, content in plan.files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    outputs = []
    for cmd in plan.commands:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, **no_window())
        if proc.returncode != 0:
            raise RuntimeError(f"{cmd[0]} falhou: {(proc.stderr or proc.stdout).strip()}")
        outputs.append(proc.stdout.strip())
    for path in plan.cleanup:
        path.unlink(missing_ok=True)
    return outputs


def _human(seconds: int) -> str:
    if seconds % 86400 == 0:
        n = seconds // 86400
        return "1 dia" if n == 1 else f"{n} dias"
    if seconds % 3600 == 0:
        n = seconds // 3600
        return "1 hora" if n == 1 else f"{n} horas"
    return f"{seconds // 60} min"


# ───────────────────────────── status ─────────────────────────────

_PS_STATUS = (
    "$t = Get-ScheduledTask -TaskName '{name}' -ErrorAction SilentlyContinue; "
    "if ($t) {{ $i = $t | Get-ScheduledTaskInfo; "
    "[pscustomobject]@{{State=[string]$t.State; Last=$i.LastRunTime.ToString('o'); "
    "Next=$i.NextRunTime.ToString('o'); Result=$i.LastTaskResult}} | ConvertTo-Json -Compress }}"
)


def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return dt if dt.year > 2000 else None  # "nunca rodou" vem como 30/11/1999


def status(platform: str, label: str) -> dict[str, Any]:
    """Situação do agendamento: instalado, próxima e última execução, último resultado."""
    name = task_name(label)
    info: dict[str, Any] = {"installed": False, "supported": True, "next": None, "last": None,
                            "result": None, "state": None}
    if not re.fullmatch(r"[\w.-]+", label):
        return info
    if platform == "win32":
        try:
            proc = subprocess.run(["powershell", "-NoProfile", "-Command", _PS_STATUS.format(name=name)],
                                  capture_output=True, text=True, timeout=20, check=False,
                                  **no_window())
        except (OSError, subprocess.TimeoutExpired):
            return info
        out = proc.stdout.strip()
        if not out:
            return info
        try:
            data = json.loads(out)
        except ValueError:
            return info
        info.update(installed=True, state=data.get("State"), next=_parse_iso(data.get("Next")),
                    last=_parse_iso(data.get("Last")), result=data.get("Result"))
        return info
    if platform.startswith("linux") and shutil.which("systemctl"):
        proc = subprocess.run(["systemctl", "--user", "is-enabled", f"{name}.timer"],
                              capture_output=True, text=True, check=False)
        info["installed"] = proc.stdout.strip() == "enabled"
        return info
    info["supported"] = False
    return info


def read_log(label: str, lines: int = 40) -> str:
    path = log_path(label)
    if not path.exists():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return "\n".join(text.splitlines()[-lines:])
