import os
import re
import tempfile
import uuid

TEST_DIR = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(TEST_DIR, "test.db")
os.environ["LOG_FILE"] = os.path.join(TEST_DIR, "test.log")

import pytest
from fastapi.testclient import TestClient

from app.main import app

PASSWORD = "correct horse battery"


def new_client():
    return TestClient(app, base_url="https://testserver")


def csrf(client, path="/login"):
    html = client.get(path).text
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def register(client, username, password=PASSWORD):
    data = {"username": username, "password": password, "confirm": password, "csrf_token": csrf(client)}
    return client.post("/register", data=data)


def login(client, username, password=PASSWORD):
    data = {"username": username, "password": password, "csrf_token": csrf(client)}
    return client.post("/login", data=data)


def create_entry(client, **fields):
    data = {"title": "GitHub", "url": "https://github.com", "username": "alice", "password": "S3cret-pass"}
    data.update(fields)
    data["csrf_token"] = csrf(client)
    response = client.post("/vault/new", data=data)
    return response.url.path.rsplit("/", 1)[1]


def read_log():
    with open(os.environ["LOG_FILE"], encoding="utf-8") as file:
        return file.read()


def new_username():
    return "user" + uuid.uuid4().hex[:8]


@pytest.fixture
def client():
    return new_client()


@pytest.fixture
def username():
    return new_username()


@pytest.fixture
def user_client(client, username):
    register(client, username)
    login(client, username)
    return client
