import json
from pathlib import Path

from sosassure.ledger import build_attack_paths, detect_drift


def test_detect_drift_hash_change(tmp_path: Path):
    prev = tmp_path / "prev" / "ledger"
    prev.mkdir(parents=True)
    prev_data = [
        {
            "path_id": "AP-0001",
            "status": "Open",
            "legacy_auth_signal": True,
            "snapshot": {"config_hash": "oldhash"},
        }
    ]
    (prev / "risk_ledger.json").write_text(json.dumps(prev_data), encoding="utf-8")

    results = [
        {
            "host": "login.example.com",
            "redirect_chain": ["https://login.example.com/"],
            "headers": {},
            "oidc": {"issuer": "https://login.microsoftonline.com/x/v2.0"},
        }
    ]
    paths, snapshots = build_attack_paths(results)
    events, updated = detect_drift(paths, snapshots, tmp_path / "prev")

    assert len(events) == 1
    assert updated[0].status == "RevalidationRequired"
