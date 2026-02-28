from __future__ import annotations

from urllib.parse import urlparse

KEYWORDS = {"admin", "sso", "login", "portal", "prod", "ehr", "pay", "vault", "gateway"}


def classify_idp(issuer: str | None) -> str:
    if not issuer:
        return "Unknown"
    full = issuer.lower()
    host = (urlparse(issuer).hostname or issuer).lower()
    if "microsoftonline" in host or "login.live" in host:
        return "AzureAD"
    if "okta" in host:
        return "Okta"
    if "auth0" in host:
        return "Auth0"
    if "keycloak" in host or "keycloak" in full:
        return "Keycloak"
    if "onelogin" in host:
        return "OneLogin"
    if "ping" in host:
        return "Ping"
    return "Unknown"


def tenant_hint_from_issuer(issuer: str | None, entry_point: str) -> str | None:
    if not issuer:
        return None
    parsed = urlparse(issuer)
    bits = [x for x in parsed.path.split("/") if x]
    if bits:
        return bits[0]
    host = parsed.hostname or ""
    if host and host != entry_point:
        return host.split(".")[0]
    return None


def score_path(
    entry_point: str,
    issuer: str | None,
    oidc_discovered: bool,
    legacy_auth_signal: bool,
    redirect_stable: bool,
    scopes: list[str],
    headers: dict[str, str],
    reachable: bool,
) -> tuple[int, float]:
    score = 0
    confidence = 0.4

    if not reachable:
        return 5, 0.2

    if issuer and classify_idp(issuer) != "Unknown":
        score += 30
        confidence += 0.2
    elif oidc_discovered:
        score += 18
        confidence += 0.1

    broad = {"offline_access", "Directory.ReadWrite.All", "*"}
    if any(s in broad for s in scopes):
        score += 20
        confidence += 0.15

    if any(k in entry_point.lower() for k in KEYWORDS):
        score += 15
        confidence += 0.1

    if redirect_stable:
        score += 20
        confidence += 0.1

    if legacy_auth_signal:
        score += 15
        confidence += 0.1

    low_headers = not headers.get("strict-transport-security") or not headers.get("content-security-policy")
    dev_smell = any(x in (issuer or "").lower() for x in ["dev", "sandbox", "staging", "test"])
    if low_headers:
        confidence -= 0.1
    if dev_smell:
        confidence -= 0.2

    score = max(0, min(100, score))
    confidence = round(max(0.0, min(1.0, confidence)), 2)
    return score, confidence
