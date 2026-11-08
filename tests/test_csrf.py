import pytest
from conftest import create_entry, csrf, new_client

from app.db import Entry, SessionLocal


@pytest.mark.parametrize("token", ["", "forged-token"])
def test_create_entry_rejects_forged_token(user_client, token):
    response = user_client.post("/vault/new", data={"title": "Forged", "csrf_token": token})
    assert response.status_code == 400
    assert "Forged" not in user_client.get("/vault").text


def test_delete_rejects_forged_token(user_client):
    entry_id = create_entry(user_client)
    response = user_client.post(f"/vault/{entry_id}/delete", data={"csrf_token": "forged"})
    assert response.status_code == 400
    with SessionLocal() as db:
        assert db.get(Entry, entry_id) is not None


def test_token_from_other_session_rejected(user_client):
    other_token = csrf(new_client())
    response = user_client.post("/vault/new", data={"title": "Cross", "csrf_token": other_token})
    assert response.status_code == 400
