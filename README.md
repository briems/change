# Identity-Centric Assurance Engine v0.1 (SOSAssure)

SOSAssure is an OSINT and defensive validation CLI that maps identity-centric external attack paths for a target domain and tracks drift over time.

## Safety & Legal Scope

- **Allowed**: public endpoint discovery, HTTP GET probes, redirect observation, OIDC metadata reads.
- **Not allowed**: exploitation, credential stuffing, brute force, auth bypass, or unauthorized access attempts.
- Built-in controls: timeout, request cap (`--max-requests`), and pacing delay (`--delay-ms`).

## Features (MVP)

- Subdomain discovery via `amass` (if available) or `--subs-file`
- HTTPS probing with redirect chain capture
- OIDC discovery at `/.well-known/openid-configuration`
- Deterministic attack path scoring and confidence
- Stable config hashing for drift detection
- Evidence artifacts (before/after snapshots + probe request/response)
- Markdown reporting (`executive_summary.md`, `technical_annex.md`)

## Install

```bash
make install
# or
pip install -r requirements.txt
```

## How to run

```bash
python -m sosassure run example.com --timeout 30 --profile ent1 --out scans --max-requests 100 --delay-ms 200
```

With subdomain file:

```bash
python -m sosassure run example.com --subs-file examples/subdomains_example.txt
```

## Output structure

```
scans/<domain>/<timestamp>/
  config.json
  discovery/
    subdomains.txt
    resolved.json
    http_probes.json
    redirects.json
    oidc.json
  ledger/
    attack_paths.json
    risk_ledger.json
    drift_events.json
  evidence/
    AP-0001/
      before.json
      after.json
      probe_request.txt
      probe_response.txt
  report/
    executive_summary.md
    technical_annex.md
```

## Limitations

- DNS resolution is a placeholder in MVP (`resolved: unknown`).
- No CT log integration in MVP (left as future provider stub opportunity).
- OIDC parsing is best-effort and may miss custom non-standard metadata.
