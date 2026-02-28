from pathlib import Path

from sosassure.ledger import build_attack_paths, risk_ledger_entries
from sosassure.reporting import write_executive_summary


def test_unreachable_never_direct_to_crisis(tmp_path: Path):
    results = [
        {
            "host": "login.example.com",
            "redirect_chain": ["https://login.example.com/"],
            "headers": {
                "strict-transport-security": "max-age=63072000",
                "content-security-policy": "default-src 'self'",
            },
            "dns_resolved": False,
            "reachable": False,
            "probe_error": "<urlopen error [Errno -5] No address associated with hostname>",
            "oidc": {
                "issuer": "https://login.microsoftonline.com/highrisk/v2.0",
                "scopes_supported": ["offline_access", "Directory.ReadWrite.All"],
            },
        }
    ]

    paths, snapshots = build_attack_paths(results)
    ledger = risk_ledger_entries(paths, snapshots)

    assert ledger[0]["severity_score"] <= 5
    assert ledger[0]["confidence"] <= 0.2
    assert ledger[0]["status"] == "Unreachable"

    summary = tmp_path / "executive_summary.md"
    write_executive_summary(summary, "example.com", ledger, None)
    text = summary.read_text(encoding="utf-8")

    assert "Direct-to-Crisis candidates: 0" in text
    assert "unreachable; cannot validate identity posture" in text


def test_executive_summary_has_data_quality_counts(tmp_path: Path):
    ledger = [
        {
            "path_id": "AP-0001",
            "entry_point": "login.example.com",
            "identity_provider": "AzureAD",
            "severity_score": 82,
            "confidence": 0.8,
            "reachable": True,
        },
        {
            "path_id": "AP-0002",
            "entry_point": "portal.example.com",
            "identity_provider": "Unknown",
            "severity_score": 5,
            "confidence": 0.2,
            "reachable": False,
        },
    ]

    summary = tmp_path / "executive_summary.md"
    write_executive_summary(summary, "example.com", ledger, None)
    text = summary.read_text(encoding="utf-8")

    assert "## Data Quality" in text
    assert "total_hosts_input: 2" in text
    assert "reachable_hosts: 1" in text
    assert "unreachable_hosts: 1" in text
