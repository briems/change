from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def dump_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_for_hash(snapshot: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        "issuer": snapshot.get("issuer"),
        "redirect_hosts": sorted(set(snapshot.get("redirect_hosts", []))),
        "discovered_endpoints": sorted(set(snapshot.get("discovered_endpoints", []))),
        "key_headers": {
            k.lower(): str(v)
            for k, v in sorted((snapshot.get("key_headers", {}) or {}).items())
            if k.lower() in {"strict-transport-security", "content-security-policy", "server"}
        },
    }
    return normalized


def config_hash(snapshot: dict[str, Any]) -> str:
    normalized = normalize_for_hash(snapshot)
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
