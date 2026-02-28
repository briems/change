from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class ContextControls:
    geo_restriction_hint: str | bool = "unknown"
    waf_proxy_hint: str = "unknown"


@dataclass
class Snapshot:
    config_hash: str
    issuer: str | None
    redirect_hosts: list[str]
    discovered_endpoints: list[str]
    key_headers: dict[str, str]


@dataclass
class AttackPath:
    path_id: str
    entry_point: str
    identity_provider: str
    issuer: str | None
    tenant_hint: str | None
    redirect_chain: list[str]
    oidc_discovered: bool
    legacy_auth_signal: bool
    context_controls: ContextControls
    severity_score: int
    confidence: float
    status: str
    dns_resolved: bool
    reachable: bool
    probe_error: str | None
    created_at: str
    last_validated: str
    snapshots: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["context_controls"] = asdict(self.context_controls)
        return data


@dataclass
class DriftEvent:
    path_id: str
    event_type: str
    previous_hash: str
    current_hash: str
    previous_status: str
    new_status: str
    detected_at: str = field(default_factory=utc_now_iso)


@dataclass
class ProbeResult:
    host: str
    start_url: str
    final_url: str | None
    status_code: int | None
    dns_resolved: bool
    reachable: bool
    redirect_chain: list[dict[str, Any]]
    headers: dict[str, str]
    oidc: dict[str, Any] | None
    probe_error: str | None = None
