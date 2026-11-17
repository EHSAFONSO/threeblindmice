"""Agendamento do scan pelo próprio sistema operacional.

O `tbm watch` morre quando o terminal fecha. Para um vigia de verdade,
registramos um scan periódico no agendador do SO:
- Windows: Agendador de Tarefas (schtasks)
- Linux: timer do systemd do usuário (sem root)
- macOS e outros: linha de crontab para você colar

Cada execução é um `tbm scan` normal, com --notify: só alerta se algo mudar.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from tbm.paths import tbm_home


@dataclass
class SchedulePlan:
    platform: str
    description: str
    files: dict[Path, str] = field(default_factory=dict)  # arquivos a criar
    commands: list[list[str]] = field(default_factory=list)  # comandos a executar
    manual: str | None = None  # instrução para o usuário quando não dá para automatizar
    warnings: list[str] = field(default_factory=list)


def task_name(label: str) -> str:
    return f"threeblindmice-{label}"


def tbm_executable() -> str:
    found = shutil.which("tbm")
    if found:
        return found
    return str(Path(sys.executable).with_name("tbm.exe" if sys.platform == "win32" else "tbm"))


def scan_argv(targets: list[str], label: str, extra: list[str]) -> list[str]:
    report = tbm_home() / "reports" / f"tbm-{label}-latest.html"
    return [tbm_executable(), "scan", *targets, "--label", label, "--report", str(report), *extra]


def _windows_schedule(seconds: int) -> list[str]:
    if seconds % 86400 == 0:
        return ["/SC", "DAILY", "/MO", str(seconds // 86400)]
    if seconds % 3600 == 0:
        return ["/SC", "HOURLY", "/MO", str(seconds // 3600)]
    return ["/SC", "MINUTE", "/MO", str(max(1, seconds // 60))]


def build_plan(platform: str, targets: list[str], label: str, seconds: int,
               extra: list[str]) -> SchedulePlan:
    argv = scan_argv(targets, label, extra)
    warnings = []
    if any(a.startswith("--notify") for a in extra) or "--notify" in extra:
        warnings.append("A URL do --notify fica gravada na definição da tarefa. Trate-a como segredo.")

    if platform == "win32":
        command = subprocess.list2cmdline(argv)
        if len(command) > 261:
            warnings.append("O comando passa de 261 caracteres, limite do schtasks /TR.")
        return SchedulePlan(
            platform="Windows (Agendador de Tarefas)",
            description=f"tarefa '{task_name(label)}' a cada {seconds}s",
            commands=[["schtasks", "/Create", "/TN", task_name(label), "/TR", command,
                       *_windows_schedule(seconds), "/F"]],
            warnings=warnings,
        )

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
            description=f"timer '{name}.timer' a cada {seconds}s",
            files={unit_dir / f"{name}.service": service, unit_dir / f"{name}.timer": timer},
            commands=[["systemctl", "--user", "daemon-reload"],
                      ["systemctl", "--user", "enable", "--now", f"{name}.timer"]],
            warnings=warnings,
        )

    minutes = max(1, seconds // 60)
    cron = f"*/{minutes} * * * *" if minutes < 60 else f"0 */{max(1, minutes // 60)} * * *"
    return SchedulePlan(
        platform="cron",
        description=f"linha de crontab a cada {seconds}s",
        manual=f"Rode `crontab -e` e adicione:\n{cron} {shlex.join(argv)}",
        warnings=warnings,
    )


def remove_plan(platform: str, label: str) -> SchedulePlan:
    name = task_name(label)
    if platform == "win32":
        return SchedulePlan("Windows (Agendador de Tarefas)", f"remover '{name}'",
                            commands=[["schtasks", "/Delete", "/TN", name, "/F"]])
    if platform.startswith("linux") and shutil.which("systemctl"):
        unit_dir = Path.home() / ".config" / "systemd" / "user"
        return SchedulePlan("Linux (systemd --user)", f"remover '{name}.timer'",
                            commands=[["systemctl", "--user", "disable", "--now", f"{name}.timer"]],
                            manual=f"Depois, apague {unit_dir / name}.service e .timer")
    return SchedulePlan("cron", "remover", manual="Rode `crontab -e` e apague a linha do threeblindmice.")


def execute(plan: SchedulePlan) -> list[str]:
    """Executa o plano. Devolve as saídas dos comandos."""
    for path, content in plan.files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    outputs = []
    for cmd in plan.commands:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"{cmd[0]} falhou: {(proc.stderr or proc.stdout).strip()}")
        outputs.append(proc.stdout.strip())
    return outputs
