from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .discovery import oidc_records, probe_hosts, resolved_records, to_redirect_records
from .ledger import build_attack_paths, detect_drift, risk_ledger_entries
from .models import ProbeResult
from .providers import AmassProvider, FileProvider
from .reporting import write_executive_summary, write_technical_annex
from .utils import dump_json, ensure_dir, load_json


class Engine:
    def __init__(
        self,
        domain: str,
        out_dir: str,
        timeout: int,
        subs_file: str | None,
        max_requests: int,
        delay_ms: int,
        debug: bool = False,
    ) -> None:
        self.domain = domain.lower().strip()
        self.out_root = Path(out_dir)
        self.timeout = timeout
        self.subs_file = subs_file
        self.max_requests = max_requests
        self.delay_ms = delay_ms
        self.debug = debug

    def run(self) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_dir = self.out_root / self.domain / ts
        self._init_dirs(run_dir)

        hosts = self._discover_subdomains()
        if self.domain not in hosts:
            hosts.append(self.domain)
        hosts = sorted(set(hosts))
        (run_dir / "discovery" / "subdomains.txt").write_text("\n".join(hosts) + "\n", encoding="utf-8")

        probe_results = probe_hosts(hosts, self.timeout, self.max_requests, self.delay_ms)
        probe_dicts = [self._probe_to_dict(p) for p in probe_results]

        dump_json(run_dir / "discovery" / "resolved.json", resolved_records(hosts))
        dump_json(run_dir / "discovery" / "http_probes.json", probe_dicts)
        dump_json(run_dir / "discovery" / "redirects.json", to_redirect_records(probe_results))
        dump_json(run_dir / "discovery" / "oidc.json", oidc_records(probe_results))

        prior_dir = self._latest_previous_run(self.out_root / self.domain, run_dir)
        previous_ledger = None
        if prior_dir and (prior_dir / "ledger" / "risk_ledger.json").exists():
            previous_ledger = load_json(prior_dir / "ledger" / "risk_ledger.json")

        paths, snapshots = build_attack_paths(probe_dicts)
        drift_events, updated_paths = detect_drift(paths, snapshots, prior_dir)

        self._write_evidence(run_dir, probe_dicts, snapshots, prior_dir)

        attack_paths_json = [p.to_dict() for p in updated_paths]
        risk_ledger = risk_ledger_entries(updated_paths, snapshots)
        dump_json(run_dir / "ledger" / "attack_paths.json", attack_paths_json)
        dump_json(run_dir / "ledger" / "risk_ledger.json", risk_ledger)
        dump_json(run_dir / "ledger" / "drift_events.json", [asdict(e) for e in drift_events])

        write_executive_summary(run_dir / "report" / "executive_summary.md", self.domain, risk_ledger, previous_ledger)
        write_technical_annex(run_dir / "report" / "technical_annex.md", risk_ledger, [asdict(e) for e in drift_events])

        dump_json(
            run_dir / "config.json",
            {
                "domain": self.domain,
                "timeout": self.timeout,
                "max_requests": self.max_requests,
                "delay_ms": self.delay_ms,
                "subs_file": self.subs_file,
            },
        )
        return run_dir

    def _discover_subdomains(self) -> list[str]:
        if self.subs_file:
            hosts = FileProvider(self.subs_file).discover(self.domain)
            if hosts:
                return hosts
        return AmassProvider().discover(self.domain)

    def _init_dirs(self, run_dir: Path) -> None:
        for rel in ["discovery", "ledger", "evidence", "report"]:
            ensure_dir(run_dir / rel)

    @staticmethod
    def _probe_to_dict(res: ProbeResult) -> dict[str, Any]:
        chain_urls = [hop["url"] for hop in res.redirect_chain]
        if res.final_url:
            chain_urls.append(res.final_url)
        return {
            "host": res.host,
            "start_url": res.start_url,
            "final_url": res.final_url,
            "status_code": res.status_code,
            "dns_resolved": res.dns_resolved,
            "reachable": res.reachable,
            "probe_error": res.probe_error,
            "redirect_chain": chain_urls,
            "headers": res.headers,
            "oidc": res.oidc,
        }

    def _write_evidence(self, run_dir: Path, probes: list[dict[str, Any]], snapshots: dict[str, Any], prior_dir: Path | None) -> None:
        for idx, p in enumerate(probes, start=1):
            path_id = f"AP-{idx:04d}"
            e_dir = run_dir / "evidence" / path_id
            ensure_dir(e_dir)
            before = {"probe": p, "snapshot": asdict(snapshots[path_id])}
            dump_json(e_dir / "before.json", before)
            if prior_dir:
                prev = prior_dir / "evidence" / path_id / "before.json"
                if prev.exists():
                    (e_dir / "after.json").write_text(prev.read_text(encoding="utf-8"), encoding="utf-8")
            (e_dir / "probe_request.txt").write_text(f"GET {p['start_url']}\n", encoding="utf-8")
            (e_dir / "probe_response.txt").write_text(
                f"status={p['status_code']} reachable={p['reachable']} dns_resolved={p['dns_resolved']} "
                f"final_url={p['final_url']} probe_error={p['probe_error']}\nheaders={p['headers']}\n",
                encoding="utf-8",
            )

    @staticmethod
    def _latest_previous_run(domain_dir: Path, current: Path) -> Path | None:
        if not domain_dir.exists():
            return None
        runs = sorted([p for p in domain_dir.iterdir() if p.is_dir() and p != current])
        return runs[-1] if runs else None
