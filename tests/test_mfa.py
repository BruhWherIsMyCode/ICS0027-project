import re

import pyotp
import pytest
from conftest import PASSWORD, csrf, login, new_client

from app import sessions


@pytest.fixture
def mfa_secret(user_client):
    page = user_client.get("/settings/mfa").text
    secret = re.search(r"<code>([A-Z2-7]+)</code>", page).group(1)
    data = {"password": PASSWORD, "code": pyotp.TOTP(secret).now(), "csrf_token": csrf(user_client, "/settings/mfa")}
    user_client.post("/settings/mfa", data=data)
    return secret


def submit_code(client, code):
    return client.post("/login/mfa", data={"code": code, "csrf_token": csrf(client, "/login/mfa")})


def test_password_alone_does_not_open_vault(username, mfa_secret):
    client = new_client()
    assert login(client, username).url.path == "/login/mfa"
    assert client.get("/vault").url.path == "/login"


def test_code_opens_vault_with_new_session_id(username, mfa_secret):
    client = new_client()
    login(client, username)
    pending = client.cookies.get(sessions.COOKIE_NAME)
    response = submit_code(client, pyotp.TOTP(mfa_secret).now())
    assert response.url.path == "/vault"
    assert client.cookies.get(sessions.COOKIE_NAME) != pending


def test_code_guessing_hits_lockout(username, mfa_secret):
    client = new_client()
    login(client, username)
    for _ in range(5):
        submit_code(client, "000000")
    assert "Too many failed attempts" in submit_code(client, pyotp.TOTP(mfa_secret).now()).text
