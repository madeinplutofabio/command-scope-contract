#!/usr/bin/env python3
"""Smoke-check that all CSC JSON Schemas are themselves valid."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"

SCHEMA_FILES = [
    "csc.contract.v0.1.schema.json",
    "csc.policy-decision.v0.1.schema.json",
    "csc.execution-receipt.v0.1.schema.json",
]


def main() -> int:
    errors = 0
    for name in SCHEMA_FILES:
        path = SCHEMA_DIR / name
        if not path.exists():
            print(f"MISSING: {path}")
            errors += 1
            continue
        schema = json.loads(path.read_text(encoding="utf-8"))
        try:
            Draft202012Validator.check_schema(schema)
            print(f"OK: {name}")
        except Exception as exc:
            print(f"INVALID: {name} — {exc}")
            errors += 1
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
