"""sfx_engine.protocol — protocol v1 schemas and validation (docs/protocol.md).

Frozen at v1. Unknown event types are ignored by the host, never fatal.
A {"type":"key"} event may only be emitted after the evidence gate passes;
the worker-side helper below refuses to build one without d_times_G=True.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Any, Iterator

PROTOCOL_MAJOR = 1

EVENT_TYPES = {"progress", "candidate", "finding", "key", "error", "done"}


class ProtocolError(Exception):
    """Raised for hard spec violations (bad version, missing fields)."""


@dataclass(frozen=True)
class JobSpec:
    raw: dict

    @property
    def protocol(self) -> int:
        return int(self.raw["protocol"])

    @property
    def run_id(self) -> str:
        return self.raw["run_id"]

    @property
    def attack_id(self) -> str:
        return self.raw["attack_id"]

    @property
    def runtime(self) -> str:
        return self.raw["runtime"]

    @property
    def params(self) -> dict:
        return self.raw.get("params", {})

    @property
    def limits(self) -> dict:
        return self.raw.get("limits", {})

    @property
    def group(self) -> dict:
        return self.raw["group"]


def parse_spec(text: str) -> JobSpec:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise ProtocolError(f"spec is not valid JSON: {e}") from e
    if not isinstance(obj, dict):
        raise ProtocolError("spec must be a JSON object")
    major = obj.get("protocol")
    if major != PROTOCOL_MAJOR:
        # fail LOUDLY before running anything — never silently proceed
        raise ProtocolError(f"unsupported protocol version {major!r}, host speaks {PROTOCOL_MAJOR}")
    for field in ("run_id", "attack_id", "runtime", "group"):
        if field not in obj:
            raise ProtocolError(f"spec missing required field {field!r}")
    if obj["runtime"] not in ("inproc", "python", "native"):
        raise ProtocolError(f"unknown runtime {obj['runtime']!r}")
    if not isinstance(obj["group"], dict) or "records" not in obj["group"]:
        raise ProtocolError("group must be an object with records")
    return JobSpec(raw=obj)


def emit(event: dict) -> None:
    """Write one JSONL event to stdout. Logs go to stderr, never here."""
    et = event.get("type")
    if et == "key" and not event.get("d_times_G"):
        # §9 rule enforced worker-side too: no key event without the gate flag
        raise ProtocolError('{"type":"key"} requires d_times_G=true (gate passed first)')
    if et is None:
        raise ProtocolError("event missing discriminator 'type'")
    sys.stdout.write(json.dumps(event, separators=(",", ":"), sort_keys=False) + "\n")
    sys.stdout.flush()


def read_events(lines: Iterator[str]) -> list[dict]:
    """Host-side reference parser: unknown types ignored, never fatal."""
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue  # malformed line is skipped, not fatal
        if ev.get("type") in EVENT_TYPES:
            out.append(ev)
    return out
