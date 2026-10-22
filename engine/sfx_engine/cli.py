"""sfx_engine.cli — python-tier entry point: python -m sfx_engine.cli < spec.json

Registry pattern mirrors W4: adding an attack = one module with run(spec)->int
plus one line in ATTACKS. Unknown attack_id => error event + exit 1.
"""
from __future__ import annotations

import sys

from .protocol import ProtocolError, parse_spec
from . import _stub

ATTACKS = {
    "_stub": _stub.run,
}


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    try:
        spec = parse_spec(sys.stdin.read())
    except ProtocolError as e:
        # loud failure on bad protocol/version, per W0 gate
        sys.stderr.write(f"protocol error: {e}\n")
        # cannot emit a typed event without knowing the stream is sane? we can:
        from .protocol import emit
        try:
            emit({"type": "error", "code": "BAD_SPEC", "msg": str(e)})
            emit({"type": "done", "elapsed_ms": 0, "status": "error"})
        except Exception:
            pass
        return 2
    fn = ATTACKS.get(spec.attack_id)
    if fn is None:
        from .protocol import emit
        emit({"type": "error", "code": "UNKNOWN_ATTACK", "msg": f"no python attack {spec.attack_id!r}"})
        emit({"type": "done", "elapsed_ms": 0, "status": "error"})
        return 1
    try:
        return fn(spec)
    except MemoryError:
        from .protocol import emit
        emit({"type": "error", "code": "OOM", "msg": "worker exceeded memory allowance"})
        emit({"type": "done", "elapsed_ms": 0, "status": "error"})
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
