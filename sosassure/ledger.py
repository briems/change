from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from .models import AttackPath, ContextControls, DriftEvent, Snapshot, utc_now_iso
from .scoring import classify_idp, score_path, tenant_hint_from_issuer
from .utils import config_hash, load_json


def build_attack_paths(results: list[dict[str, Any]], prior_statuses: dict[str, str] | None = None) -> tuple[list[AttackPath], dict[str, Snapshot]]:
    paths: list[AttackPath] = []
    snapshots: dict[str, Snapshot] = {}
    prior_statuses = prior_statuses or {}

    for idx, res in enumerate(results, start=1):
        path_id = f"AP-{idx:04d}"
        chain = res.get("redirect_chain", [])
        final_host = chain[-1] if chain else res["host"]
        oidc = res.get("oidc") or {}
        issuer = oidc.get("issuer")
        scopes = oidc.get("scopes_supported", []) if isinstance(oidc, dict) else []
        legacy = any(t in final_host.lower() for t in ["adfs", "wsfed", "basic-auth"])
        headers = res.get("headers", {})

        severity, confidence = score_path(
            entry_point=res["host"],
            issuer=issuer,
            oidc_discovered=bool(oidc),
            legacy_auth_signal=legacy,
            redirect_stable=bool(chain),
            scopes=scopes,
            headers=headers,
        )
        snapshot_obj = {
            "issuer": issuer,
            "redirect_hosts": chain,
            "discovered_endpoints": [k for k in [oidc.get("authorization_endpoint"), oidc.get("token_endpoint")] if k],
            "key_headers": headers,
        }
        c_hash = config_hash(snapshot_obj)
        snapshot = Snapshot(
            config_hash=c_hash,
            issuer=issuer,
            redirect_hosts=chain,
            discovered_endpoints=snapshot_obj["discovered_endpoints"],
            key_headers=headers,
        )
        status = prior_statuses.get(path_id, "Open")

        path = AttackPath(
            path_id=path_id,
            entry_point=res["host"],
            identity_provider=classify_idp(issuer),
            issuer=issuer,
            tenant_hint=tenant_hint_from_issuer(issuer, res["host"]),
            redirect_chain=chain,
            oidc_discovered=bool(oidc),
            legacy_auth_signal=legacy,
            context_controls=ContextControls(),
            severity_score=severity,
            confidence=confidence,
            status=status,
            created_at=utc_now_iso(),
            last_validated=utc_now_iso(),
            snapshots={"current": f"evidence/{path_id}/before.json"},
        )
        paths.append(path)
        snapshots[path_id] = snapshot
    return paths, snapshots


def detect_drift(
    current_paths: list[AttackPath],
    current_snapshots: dict[str, Snapshot],
    previous_run_dir: Path | None,
) -> tuple[list[DriftEvent], list[AttackPath]]:
    if not previous_run_dir:
        return [], current_paths

    prev_ledger = previous_run_dir / "ledger" / "risk_ledger.json"
    if not prev_ledger.exists():
        return [], current_paths

    prev_data = load_json(prev_ledger)
    prev_map = {item["path_id"]: item for item in prev_data}

    events: list[DriftEvent] = []
    for path in current_paths:
        prev = prev_map.get(path.path_id)
        if not prev:
            continue
        old_hash = (prev.get("snapshot") or {}).get("config_hash", "")
        new_hash = current_snapshots[path.path_id].config_hash
        if old_hash != new_hash:
            prev_status = prev.get("status", "Open")
            path.status = "RevalidationRequired"
            event_type = "config_hash_changed"
            if prev.get("legacy_auth_signal") and not path.legacy_auth_signal:
                event_type = "risk_reduced_needs_verification"
            events.append(
                DriftEvent(
                    path_id=path.path_id,
                    event_type=event_type,
                    previous_hash=old_hash,
                    current_hash=new_hash,
                    previous_status=prev_status,
                    new_status=path.status,
                )
            )
    return events, current_paths


def risk_ledger_entries(paths: list[AttackPath], snapshots: dict[str, Snapshot]) -> list[dict[str, Any]]:
    entries = []
    for p in paths:
        d = p.to_dict()
        d["snapshot"] = asdict(snapshots[p.path_id])
        entries.append(d)
    return entries
