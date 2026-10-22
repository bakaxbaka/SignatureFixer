"""sfx_engine._stub — W0 conformance stub. Proves the pipe end-to-end.

Behaviour: reads the spec, emits progress, a finding, then done. Emits NO key
event (it recovers nothing). The ladder must accept it with zero host edits.
"""
from __future__ import annotations

import time

from .protocol import JobSpec, emit


def run(spec: JobSpec) -> int:
    t0 = time.monotonic()
    n = len(spec.group.get("records", []))
    emit({"type": "progress", "pct": 0.0, "msg": f"stub start ({n} records)"})
    emit({"type": "finding", "classification": "NO_SIGNAL", "rule": "stub", "source_record_ids": []})
    emit({"type": "progress", "pct": 1.0, "msg": "stub complete"})
    emit({"type": "done", "elapsed_ms": int((time.monotonic() - t0) * 1000), "status": "ok"})
    return 0
