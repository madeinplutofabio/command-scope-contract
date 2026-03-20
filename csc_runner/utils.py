from __future__ import annotations

import hashlib
import json

from csc_runner.models import CommandContract


def hash_contract(contract: CommandContract) -> str:
    payload = contract.model_dump(mode="json", exclude_none=True)
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
