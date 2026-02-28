from __future__ import annotations

from pathlib import Path


def write_executive_summary(path: Path, domain: str, ledger: list[dict], previous_ledger: list[dict] | None) -> None:
    direct = [x for x in ledger if x["severity_score"] >= 80 and x["confidence"] >= 0.75]
    prev_avg = round(sum(x["severity_score"] for x in previous_ledger) / len(previous_ledger), 2) if previous_ledger else None
    curr_avg = round(sum(x["severity_score"] for x in ledger) / len(ledger), 2) if ledger else 0
    top3 = sorted(ledger, key=lambda x: (x["severity_score"], x["confidence"]), reverse=True)[:3]

    lines = [
        f"# Executive Summary - {domain}",
        "",
        "## Snapshot",
        f"- Total attack paths: {len(ledger)}",
        f"- Direct-to-Crisis candidates: {len(direct)}",
        f"- Current average severity: {curr_avg}",
    ]
    if prev_avg is not None:
        lines.append(f"- Previous average severity: {prev_avg}")

    lines.append("\n## Top 3 Paths")
    for i, p in enumerate(top3, start=1):
        lines.append(
            f"{i}. **{p['path_id']}** via `{p['entry_point']}` (IdP: {p['identity_provider']}) - "
            f"Severity {p['severity_score']}, confidence {p['confidence']}. "
            "Potential impact: externally reachable identity flow could expose authentication posture drift if misconfigured."
        )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_technical_annex(path: Path, ledger: list[dict], drift_events: list[dict]) -> None:
    lines = ["# Technical Annex", "", "## Paths", ""]
    for p in ledger:
        lines.extend(
            [
                f"### {p['path_id']}",
                f"- Entry point: {p['entry_point']}",
                f"- Issuer: {p.get('issuer')}",
                f"- Redirect chain: {', '.join(p.get('redirect_chain', []))}",
                f"- Config hash: {p.get('snapshot', {}).get('config_hash', 'n/a')}",
                f"- Evidence: `evidence/{p['path_id']}/before.json`, `probe_request.txt`, `probe_response.txt`",
                "",
            ]
        )

    lines.extend(["## Drift Events", ""])
    if not drift_events:
        lines.append("- No drift events detected.")
    else:
        for e in drift_events:
            lines.append(
                f"- {e['path_id']}: {e['event_type']} ({e['previous_hash']} -> {e['current_hash']})"
            )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
