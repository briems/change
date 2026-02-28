from __future__ import annotations

import json
import socket
import ssl
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .models import ProbeResult

OIDC_PATH = "/.well-known/openid-configuration"


class RecordingRedirectHandler(HTTPRedirectHandler):
    def __init__(self) -> None:
        super().__init__()
        self.chain: list[dict[str, Any]] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        self.chain.append({"url": req.full_url, "status_code": code, "location": newurl})
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def probe_hosts(hosts: list[str], timeout: int, max_requests: int, delay_ms: int) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    req_count = 0
    context = ssl.create_default_context()

    for host in hosts:
        if req_count >= max_requests:
            break
        start = f"https://{host}/"
        redirect_handler = RecordingRedirectHandler()
        opener = build_opener(HTTPSHandler(context=context), redirect_handler)
        dns_resolved = _dns_resolved(host)

        try:
            req = Request(start, method="GET", headers={"User-Agent": "sosassure/0.1"})
            with opener.open(req, timeout=timeout) as response:
                body_headers = response.headers
                headers = {
                    "strict-transport-security": body_headers.get("Strict-Transport-Security", ""),
                    "content-security-policy": body_headers.get("Content-Security-Policy", ""),
                    "server": body_headers.get("Server", ""),
                }
                final_url = response.geturl()
                status = getattr(response, "status", None)
            req_count += 1
            oidc = discover_oidc(host, timeout, context)
            req_count += 1
            result = ProbeResult(
                host=host,
                start_url=start,
                final_url=final_url,
                status_code=status,
                dns_resolved=dns_resolved,
                reachable=status is not None,
                redirect_chain=redirect_handler.chain,
                headers=headers,
                oidc=oidc,
            )
        except HTTPError as exc:
            result = ProbeResult(
                host=host,
                start_url=start,
                final_url=getattr(exc, "url", None),
                status_code=getattr(exc, "code", None),
                dns_resolved=dns_resolved,
                reachable=getattr(exc, "code", None) is not None,
                redirect_chain=redirect_handler.chain,
                headers={},
                oidc=None,
                probe_error=str(exc),
            )
        except (URLError, TimeoutError, ssl.SSLError) as exc:
            result = ProbeResult(
                host=host,
                start_url=start,
                final_url=None,
                status_code=getattr(exc, "code", None),
                dns_resolved=dns_resolved,
                reachable=False,
                redirect_chain=redirect_handler.chain,
                headers={},
                oidc=None,
                probe_error=str(exc),
            )
        results.append(result)
        if delay_ms > 0:
            time.sleep(delay_ms / 1000)
    return results


def _dns_resolved(host: str) -> bool:
    try:
        socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        return True
    except socket.gaierror:
        return False


def discover_oidc(host: str, timeout: int, context: ssl.SSLContext) -> dict[str, Any] | None:
    url = f"https://{host}{OIDC_PATH}"
    try:
        req = Request(url, method="GET", headers={"User-Agent": "sosassure/0.1"})
        opener = build_opener(HTTPSHandler(context=context))
        with opener.open(req, timeout=timeout) as r:
            if getattr(r, "status", None) != 200:
                return None
            data = json.loads(r.read().decode("utf-8"))
            return {
                "issuer": data.get("issuer"),
                "authorization_endpoint": data.get("authorization_endpoint"),
                "token_endpoint": data.get("token_endpoint"),
                "scopes_supported": data.get("scopes_supported", []),
                "raw_status": 200,
            }
    except Exception:
        return None


def to_redirect_records(results: list[ProbeResult]) -> list[dict[str, Any]]:
    records = []
    for res in results:
        chain = [hop["url"] for hop in res.redirect_chain]
        if res.final_url:
            chain.append(res.final_url)
        records.append({"host": res.host, "redirect_chain": chain})
    return records


def resolved_records(hosts: list[str]) -> list[dict[str, str]]:
    return [{"host": h, "resolved": "unknown"} for h in hosts]


def oidc_records(results: list[ProbeResult]) -> list[dict[str, Any]]:
    records = []
    for res in results:
        if res.oidc:
            records.append({"host": res.host, **res.oidc})
    return records


def hosts_from_redirect_chain(chain: list[str]) -> list[str]:
    hosts = []
    for url in chain:
        host = urlparse(url).hostname
        if host:
            hosts.append(host)
    return hosts
