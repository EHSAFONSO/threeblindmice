"""Ponto de entrada das execuções agendadas no Windows: `pythonw -m tbm._scheduled <rótulo>`.

Roda sem janela (pythonw não tem console). Como no pythonw `sys.stdout` é
None, redirecionamos a saída para TBM_HOME/logs/<rótulo>.log antes de
importar a CLI. Esse log é o que a página "Vigia" da interface mostra.
"""

from __future__ import annotations

import json
import sys
import traceback
from datetime import datetime

from tbm.schedule import log_path, windows_spec

MAX_LOG = 1_000_000  # ~1 MB; depois disso o log anterior vira .1


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        return 2
    label = args[0]
    log = log_path(label)
    log.parent.mkdir(parents=True, exist_ok=True)
    if log.exists() and log.stat().st_size > MAX_LOG:
        log.replace(log.with_suffix(".log.1"))

    with log.open("a", encoding="utf-8") as fh:
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = fh
        try:
            print(f"\n=== {datetime.now():%Y-%m-%d %H:%M:%S} · início do scan agendado '{label}' ===", flush=True)
            spec = json.loads(windows_spec(label).read_text(encoding="utf-8"))
            from tbm.cli import app

            result = app(args=spec["argv"], standalone_mode=False)
            code = result if isinstance(result, int) else 0
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
        except Exception:  # noqa: BLE001 (tudo vai para o log)
            traceback.print_exc()
            code = 1
        finally:
            print(f"=== fim · código {code if 'code' in locals() else '?'} ===", flush=True)
            sys.stdout, sys.stderr = old_out, old_err
    return code


if __name__ == "__main__":
    raise SystemExit(main())
