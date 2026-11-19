"""Local tamper-evident (not tamper-proof) JSONL audit log for the MVP."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def _hash(record: dict[str, Any]) -> str:
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def verify_log(path: str | Path) -> bool:
    """Verify that existing entries form an internally consistent hash chain."""
    previous = "0" * 64
    try:
        with Path(path).open(encoding="utf-8") as stream:
            for i, line in enumerate(stream, 1):
                entry = json.loads(line)
                if not isinstance(entry, dict) or set(entry) != {"record", "sha256"}:
                    return False
                record = entry["record"]
                if not isinstance(record, dict) or record.get("sequence") != i:
                    return False
                if record.get("previous_sha256") != previous or entry["sha256"] != _hash(record):
                    return False
                previous = entry["sha256"]
    except (OSError, ValueError, TypeError):
        return False
    return True


def append_decision(path: str | Path, proposal: dict, decision: dict) -> str:
    """Append a decision with only non-secret proposal identifiers; single-writer use.

    The file can still be rewritten by an OS user with write permission; for
    stronger integrity, export hashes to independently protected storage.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not verify_log(path):
        raise ValueError("Existing audit chain failed verification")
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    previous = json.loads(lines[-1])["sha256"] if lines else "0" * 64
    record = {
        "sequence": len(lines) + 1,
        "previous_sha256": previous,
        "proposal": {k: proposal.get(k) for k in ("cloud", "environment", "action", "resource_id")},
        "decision": decision,
    }
    digest = _hash(record)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"record": record, "sha256": digest}, sort_keys=True) + "\n")
    return digest
