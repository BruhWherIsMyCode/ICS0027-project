import pytest
from conftest import create_entry
from cryptography.exceptions import InvalidTag

from app import crypto
from app.db import Entry, SessionLocal


def test_login_hash_is_argon2id():
    password_hash = crypto.hash_password("correct horse battery")
    assert password_hash.startswith("$argon2id$")
    assert crypto.verify_password(password_hash, "correct horse battery")
    assert not crypto.verify_password(password_hash, "wrong password")


def test_ciphertext_moved_to_other_row_fails():
    key = crypto.derive_key("correct horse battery", crypto.new_salt())
    nonce, ciphertext = crypto.encrypt(key, {"password": "hunter2"}, "id-1")
    with pytest.raises(InvalidTag):
        crypto.decrypt(key, nonce, ciphertext, "id-2")


def test_database_holds_no_plaintext(user_client):
    entry_id = create_entry(user_client, username="alice@example.com", password="find-me-in-db")
    with SessionLocal() as db:
        entry = db.get(Entry, entry_id)
    assert b"find-me-in-db" not in entry.ciphertext
    assert b"alice@example.com" not in entry.ciphertext
