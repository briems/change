from __future__ import annotations

from pathlib import Path


def write_executive_summary(path: Path, domain: str, ledger: list[dict], previous_ledger: list[dict] | None) -> None:
    reachable = [x for x in ledger if x.get("reachable", False)]
    unreachable = [x for x in ledger if not x.get("reachable", False)]
    direct = [x for x in reachable if x["severity_score"] >= 80 and x["confidence"] >= 0.75]
    prev_avg = round(sum(x["severity_score"] for x in previous_ledger) / len(previous_ledger), 2) if previous_ledger else None
    curr_avg = round(sum(x["severity_score"] for x in ledger) / len(ledger), 2) if ledger else 0

    preferred = sorted(reachable, key=lambda x: (x["severity_score"], x["confidence"]), reverse=True)
    if len(preferred) < 3:
        fill = sorted(unreachable, key=lambda x: (x["severity_score"], x["confidence"]), reverse=True)
        preferred = preferred + fill
    top3 = preferred[:3]

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

    lines.extend(
        [
            "",
            "## Data Quality",
            f"- total_hosts_input: {len(ledger)}",
            f"- reachable_hosts: {len(reachable)}",
            f"- unreachable_hosts: {len(unreachable)}",
            "- Some findings are informational only due to DNS/HTTP reachability failures.",
            "",
            "## Top 3 Paths",
        ]
    )

    for i, p in enumerate(top3, start=1):
        if p.get("reachable", False):
            impact = "Potential impact: externally reachable identity flow could expose authentication posture drift if misconfigured."
            label = ""
        else:
            impact = "Potential impact: unreachable; cannot validate identity posture."
            label = " [Unreachable]"
        lines.append(
            f"{i}. **{p['path_id']}**{label} via `{p['entry_point']}` (IdP: {p['identity_provider']}) - "
            f"Severity {p['severity_score']}, confidence {p['confidence']}. {impact}"
        )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_technical_annex(path: Path, ledger: list[dict], drift_events: list[dict]) -> None:
    lines = ["# Technical Annex", "", "## Paths", ""]
    for p in ledger:
        lines.extend(
            [
                f"### {p['path_id']}",
                f"- Entry point: {p['entry_point']}",
                f"- Reachable: {p.get('reachable', False)}",
                f"- DNS resolved: {p.get('dns_resolved', False)}",
                f"- Probe error: {p.get('probe_error')}",
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
