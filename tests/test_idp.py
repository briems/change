from sosassure.scoring import classify_idp


def test_classify_known_idps():
    assert classify_idp("https://login.microsoftonline.com/tenant/v2.0") == "AzureAD"
    assert classify_idp("https://acme.okta.com/oauth2/default") == "Okta"
    assert classify_idp("https://tenant.us.auth0.com/") == "Auth0"
    assert classify_idp("https://sso.internal/keycloak/realms/master") == "Keycloak"


def test_classify_unknown():
    assert classify_idp(None) == "Unknown"
    assert classify_idp("https://id.example.com") == "Unknown"
