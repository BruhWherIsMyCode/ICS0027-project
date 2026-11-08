from conftest import PASSWORD, csrf, login, register

from app import config, sessions


def test_cookie_flags(client, username):
    register(client, username)
    response = login(client, username)
    cookie = response.history[0].headers["set-cookie"]
    assert cookie.startswith("__Host-session=")
    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert "Max-Age" not in cookie


def test_session_fixation(client, username):
    register(client, username)
    planted = client.cookies.get(sessions.COOKIE_NAME)
    login(client, username)
    assert client.cookies.get(sessions.COOKIE_NAME) != planted
    assert sessions.get_session(planted) is None


def test_same_error_for_unknown_user_and_wrong_password(client, username):
    register(client, username)
    wrong = login(client, username, "wrong password!!")
    unknown = login(client, "nobody" + username)
    assert wrong.status_code == unknown.status_code == 400
    assert "Invalid username or password." in wrong.text
    assert "Invalid username or password." in unknown.text


def test_lockout_after_five_failures(client, username):
    register(client, username)
    for _ in range(5):
        login(client, username, "wrong password!!")
    assert "Too many failed attempts" in login(client, username).text


def test_idle_timeout(user_client):
    sid = user_client.cookies.get(sessions.COOKIE_NAME)
    sessions.sessions[sid].last_seen -= config.SESSION_IDLE_SECONDS + 1
    assert user_client.get("/vault").url.path == "/login"


def test_logout_removes_session(user_client):
    sid = user_client.cookies.get(sessions.COOKIE_NAME)
    user_client.post("/logout", data={"csrf_token": csrf(user_client, "/vault")})
    assert sessions.get_session(sid) is None
    assert user_client.get("/vault").url.path == "/login"


def test_password_change_logs_out_other_sessions(user_client, username):
    other = user_client.__class__(user_client.app, base_url="https://testserver")
    login(other, username)
    other_sid = other.cookies.get(sessions.COOKIE_NAME)
    data = {"current_password": PASSWORD, "new_password": "new master password", "confirm": "new master password", "csrf_token": csrf(user_client, "/settings/password")}
    user_client.post("/settings/password", data=data)
    assert sessions.get_session(other_sid) is None
    assert other.get("/vault").url.path == "/login"
