import pytest
from conftest import create_entry, csrf

PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "<form action=https://evil.example><input name=password></form>",
]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_stored_payload_is_escaped(user_client, payload):
    entry_id = create_entry(user_client, title=payload, notes=payload)
    for path in ("/vault", f"/vault/{entry_id}"):
        html = user_client.get(path).text
        assert payload not in html
        assert "&lt;" in html


@pytest.mark.parametrize("url", ["javascript:alert(1)", "data:text/html,<script>alert(1)</script>", "vbscript:x"])
def test_dangerous_url_schemes_rejected(user_client, url):
    data = {"title": "Link", "url": url, "csrf_token": csrf(user_client)}
    response = user_client.post("/vault/new", data=data)
    assert response.status_code == 400
    assert "URL must start with http:// or https://." in response.text


def test_content_security_policy(client):
    policy = client.get("/login").headers["content-security-policy"]
    assert "script-src 'self'" in policy
    assert "form-action 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "unsafe-inline" not in policy
