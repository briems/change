from sosassure.utils import config_hash


def test_config_hash_stable_with_order_variations():
    a = {
        "issuer": "https://idp.example.com/tenant",
        "redirect_hosts": ["b.example.com", "a.example.com"],
        "discovered_endpoints": ["/token", "/auth"],
        "key_headers": {"Server": "nginx", "Content-Security-Policy": "default-src 'self'"},
    }
    b = {
        "issuer": "https://idp.example.com/tenant",
        "redirect_hosts": ["a.example.com", "b.example.com"],
        "discovered_endpoints": ["/auth", "/token"],
        "key_headers": {"content-security-policy": "default-src 'self'", "server": "nginx"},
    }
    assert config_hash(a) == config_hash(b)
