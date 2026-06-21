"""Verify Node-produced artifacts with the released Python Canon reference."""

from __future__ import annotations

import json
import hashlib
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANON = Path(os.environ.get("OLP_CANON_PATH", ROOT.parent / "olp-wire-canon"))
if not (CANON / "reference.py").exists():
    raise SystemExit(
        "Canon reference not found. Set OLP_CANON_PATH to an olp-wire-canon v0.1-draft checkout."
    )
sys.path.insert(0, str(CANON))

from reference import (  # noqa: E402
    canonical_json,
    validate_disclosure,
    validate_profile,
    verify_chain,
    verify_receipt,
)


def load(name: str) -> dict:
    return json.loads((ROOT / "artifacts" / name).read_text(encoding="utf-8"))


trace = load("node-trace-receipt.json")
coherence = load("node-coherence-input-receipt.json")
amendment = load("node-amendment-receipt.json")
loss = load("node-capture-loss-amendment.json")
disclosure = load("node-coherence-input-disclosure.json")
trace_records = load("node-trace-span-records.json")


def merkle_root(records: list[dict]) -> str:
    if not records:
        return hashlib.sha256(b"").hexdigest()
    level = [hashlib.sha256(b"\x00" + canonical_json(record)).digest() for record in records]
    while len(level) > 1:
        next_level = []
        for index in range(0, len(level), 2):
            if index + 1 == len(level):
                next_level.append(level[index])
            else:
                next_level.append(
                    hashlib.sha256(b"\x01" + level[index] + level[index + 1]).digest()
                )
        level = next_level
    return level[0].hex()

for receipt in (trace, coherence, amendment, loss):
    validate_profile(receipt)
    if not verify_receipt(receipt):
        raise SystemExit(f"Python rejected Node receipt: {receipt['kind']}")

if not verify_chain([coherence, amendment, loss]):
    raise SystemExit("Python rejected Node amendment chain")
validate_disclosure(disclosure, coherence)
if merkle_root(trace_records) != trace["trace_root"]:
    raise SystemExit("Python could not reproduce Node trace_root from disclosed span records")

print("Python verified 4 Node receipt kinds, recomputed trace_root, amendment chain, and bound disclosure")
