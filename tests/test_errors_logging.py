import json

from conftest import PASSWORD, create_entry, login, read_log, register

from app.db import Entry, SessionLocal


def test_unknown_page_is_generic(client):
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    assert "Page not found." in response.text
    assert "detail" not in response.text
    assert response.headers["x-frame-options"] == "DENY"


def test_tampered_entry_fails_closed(user_client):
    entry_id = create_entry(user_client, password="must-not-leak")
    with SessionLocal() as db:
        entry = db.get(Entry, entry_id)
        entry.ciphertext = bytes([entry.ciphertext[0] ^ 1]) + entry.ciphertext[1:]
        db.commit()
    response = user_client.get(f"/vault/{entry_id}")
    assert response.status_code == 500
    assert "Something went wrong." in response.text
    assert "Traceback" not in response.text
    assert "must-not-leak" not in response.text


def test_log_lines_are_json_with_required_fields(client, username):
    register(client, username)
    login(client, username, "wrong password!!")
    lines = [json.loads(line) for line in read_log().splitlines()]
    failures = [line for line in lines if line["event"] == "login" and line["outcome"] == "failure" and line["username"] == username]
    assert failures
    for field in ("time", "event", "outcome", "user_id", "request_id", "ip", "path"):
        assert field in failures[-1]


def test_log_never_contains_secrets(user_client, username):
    create_entry(user_client, password="entry-secret-123", notes="secret note text")
    login(user_client, username, "wrong-password-in-log")
    log = read_log()
    assert PASSWORD not in log
    assert "entry-secret-123" not in log
    assert "secret note text" not in log
    assert "wrong-password-in-log" not in log
