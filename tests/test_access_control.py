import pytest
from conftest import create_entry, csrf, login, new_client, new_username, register

from app.db import Entry, SessionLocal


@pytest.fixture
def victim_entry(user_client):
    return create_entry(user_client, title="Victim bank", password="victim-password-1")


@pytest.fixture
def attacker():
    client = new_client()
    name = new_username()
    register(client, name)
    login(client, name)
    return client


def test_read_other_users_entry(attacker, victim_entry):
    response = attacker.get(f"/vault/{victim_entry}")
    assert response.status_code == 404
    assert "victim-password-1" not in response.text
    assert "Victim bank" not in attacker.get("/vault").text


def test_edit_other_users_entry(attacker, victim_entry):
    data = {"title": "Hacked", "csrf_token": csrf(attacker)}
    response = attacker.post(f"/vault/{victim_entry}/edit", data=data)
    assert response.status_code == 404
    with SessionLocal() as db:
        assert db.get(Entry, victim_entry).title == "Victim bank"


def test_delete_other_users_entry(attacker, victim_entry):
    response = attacker.post(f"/vault/{victim_entry}/delete", data={"csrf_token": csrf(attacker)})
    assert response.status_code == 404
    with SessionLocal() as db:
        assert db.get(Entry, victim_entry) is not None


def test_pages_need_login(victim_entry):
    client = new_client()
    for path in ("/vault", f"/vault/{victim_entry}", "/settings/password", "/settings/mfa"):
        assert client.get(path).url.path == "/login"
