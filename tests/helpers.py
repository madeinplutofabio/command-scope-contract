"""Reusable test helpers for schema validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"

_SCHEMA_CACHE: dict[str, dict[str, Any]] = {}


def load_schema(schema_name: str) -> dict[str, Any]:
    """Load a JSON Schema by filename from the schemas/ directory."""
    if schema_name not in _SCHEMA_CACHE:
        path = SCHEMA_DIR / schema_name
        _SCHEMA_CACHE[schema_name] = json.loads(path.read_text(encoding="utf-8"))
    return _SCHEMA_CACHE[schema_name]


def validate_against_schema(instance: dict[str, Any], schema_name: str) -> None:
    """Validate a dict against a named schema. Raises ValidationError on failure."""
    schema = load_schema(schema_name)
    validator = Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    validator.validate(instance)
