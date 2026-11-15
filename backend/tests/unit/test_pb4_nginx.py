"""Static assertions supplement, but do not replace, real proxy/browser tests."""

from pathlib import Path


def test_proxy_overwrites_forwarded_identity_and_applies_security_headers() -> None:
    site = Path("infra/nginx/soc-site.conf").read_text(encoding="utf-8")
    assert "proxy_pass http://backend:8000;" in site
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in site
    assert "proxy_set_header X-Real-IP $remote_addr;" in site
    assert "proxy_set_header X-Forwarded-Proto $scheme;" in site
    assert 'proxy_set_header Forwarded "";' in site
    assert "$proxy_add_x_forwarded_for" not in site
    assert "try_files $uri $uri/ /index.html;" in site
    for directive in (
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ):
        assert directive in site
    assert "script-src 'self'" in site
    assert "connect-src 'self'" in site
    assert "frame-ancestors 'none'" in site
    assert "'unsafe-inline'" not in site and "'unsafe-eval'" not in site


def test_tls_is_inactive_by_default_and_hsts_is_conditional() -> None:
    configuration = Path("infra/nginx/nginx.conf").read_text(encoding="utf-8")
    template = Path("infra/nginx/tls.conf.example").read_text(encoding="utf-8")
    assert "listen 8080 default_server;" in configuration
    assert "client_max_body_size 1m;" in configuration
    assert (
        'default "";' in configuration
        and 'on "max-age=31536000; includeSubDomains";' in configuration
    )
    assert "include /etc/nginx/tls-enabled/*.conf;" in configuration
    assert "listen 8443 ssl;" in template
    assert "ssl_certificate /run/secrets/tls_certificate;" in template
    assert "ssl_certificate_key /run/secrets/tls_private_key;" in template
