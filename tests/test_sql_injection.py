import pytest
from conftest import PASSWORD, create_entry, login
from sqlalchemy import func, select

from app.db import Entry, SessionLocal, User

PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "'; DROP TABLE users;--",
    "\" OR \"\"=\"",
    "' UNION SELECT password_hash FROM users--",
]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_login_username_injection(client, payload):
    response = login(client, payload, PASSWORD)
    assert response.status_code == 400
    assert response.url.path == "/login"


@pytest.mark.parametrize("payload", PAYLOADS + ["%", "_"])
def test_search_injection_returns_only_matches(user_client, payload):
    create_entry(user_client, title="Netflix", url="https://netflix.com")
    response = user_client.get("/vault", params={"q": payload})
    assert response.status_code == 200
    assert "Netflix" not in response.text


@pytest.mark.parametrize("payload", PAYLOADS)
def test_payload_stored_as_plain_text(user_client, payload):
    entry_id = create_entry(user_client, title=payload)
    with SessionLocal() as db:
        entry = db.get(Entry, entry_id)
        users = db.scalar(select(func.count()).select_from(User))
    assert entry.title == payload
    assert users > 0
