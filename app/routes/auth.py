import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app import crypto, mfa, sessions
from app.db import User, get_db
from app.logs import log_event
from app.templating import templates

router = APIRouter()

USERNAME_PATTERN = re.compile(r"[a-z0-9_.-]{3,32}")
MIN_PASSWORD_LENGTH = 12
DUMMY_HASH = crypto.hash_password("dummy password")


def login_error(request: Request, username: str, error: str):
    log_event(request, "login", "failure", username=username, reason=error)
    context = {"error": error, "username": username}
    return templates.TemplateResponse(request, "login.html", context, status_code=400)


def mfa_error(request: Request, error: str):
    log_event(request, "login_mfa", "failure", reason=error)
    context = {"error": error}
    return templates.TemplateResponse(request, "login_mfa.html", context, status_code=400)


@router.get("/register")
def register_form(request: Request):
    return templates.TemplateResponse(request, "register.html")


@router.post("/register")
def register(
    request: Request,
    username: str = Form(max_length=32),
    password: str = Form(max_length=1024),
    confirm: str = Form(max_length=1024),
    csrf_token: str = Form(),
    db: DbSession = Depends(get_db),
):
    username = username.strip().lower()
    error = None
    if not sessions.csrf_valid(request, csrf_token):
        error = "The form expired. Please try again."
    elif not USERNAME_PATTERN.fullmatch(username):
        error = "Username must be 3-32 characters. Letters, digits, dot, dash or underscore."
    elif len(password) < MIN_PASSWORD_LENGTH:
        error = f"Master password must be at least {MIN_PASSWORD_LENGTH} characters."
    elif password != confirm:
        error = "Passwords do not match."
    elif db.scalar(select(User).where(User.username == username)):
        error = "This username is taken."

    if error:
        log_event(request, "register", "failure", username=username, reason=error)
        context = {"error": error, "username": username}
        return templates.TemplateResponse(request, "register.html", context, status_code=400)

    user = User(
        username=username,
        password_hash=crypto.hash_password(password),
        key_salt=crypto.new_salt(),
    )
    db.add(user)
    db.commit()
    log_event(request, "register", "success", username=username)
    return RedirectResponse("/login?registered=1", status_code=303)


@router.get("/login")
def login_form(request: Request):
    return templates.TemplateResponse(request, "login.html")


@router.post("/login")
def login(
    request: Request,
    username: str = Form(max_length=32),
    password: str = Form(max_length=1024),
    csrf_token: str = Form(),
    db: DbSession = Depends(get_db),
):
    username = username.strip().lower()
    if not sessions.csrf_valid(request, csrf_token):
        return login_error(request, username, "The form expired. Please try again.")
    if sessions.is_locked(username):
        return login_error(request, username, "Too many failed attempts. Try again in 15 minutes.")

    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        crypto.verify_password(DUMMY_HASH, password)
    if user is None or not crypto.verify_password(user.password_hash, password):
        sessions.record_failed_login(username)
        return login_error(request, username, "Invalid username or password.")

    key = crypto.derive_key(password, user.key_salt)
    sessions.delete_session(request.cookies.get(sessions.COOKIE_NAME))
    if user.mfa_enabled:
        sid = sessions.create_session(user.id, user.username, key, mfa_pending=True)
        log_event(request, "login", "mfa_required", username=username)
        target = "/login/mfa"
    else:
        sessions.clear_failed_logins(username)
        sid = sessions.create_session(user.id, user.username, key)
        log_event(request, "login", "success", username=username)
        target = "/"

    response = RedirectResponse(target, status_code=303)
    sessions.set_cookie(response, sid)
    return response


@router.get("/login/mfa")
def mfa_form(request: Request):
    if not request.state.session.mfa_pending:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "login_mfa.html")


@router.post("/login/mfa")
def mfa_login(
    request: Request,
    code: str = Form(max_length=10),
    csrf_token: str = Form(),
    db: DbSession = Depends(get_db),
):
    session = request.state.session
    if not session.mfa_pending:
        return RedirectResponse("/login", status_code=303)
    if not sessions.csrf_valid(request, csrf_token):
        return mfa_error(request, "The form expired. Please try again.")
    if sessions.is_locked(session.username):
        return mfa_error(request, "Too many failed attempts. Try again in 15 minutes.")

    user = db.get(User, session.user_id)
    secret = mfa.decrypt_secret(session.key, user)
    if not mfa.verify(secret, code):
        sessions.record_failed_login(session.username)
        return mfa_error(request, "Invalid code.")

    sessions.clear_failed_logins(session.username)
    sessions.delete_session(request.cookies.get(sessions.COOKIE_NAME))
    sid = sessions.create_session(user.id, user.username, session.key)
    log_event(request, "login_mfa", "success", username=user.username)

    response = RedirectResponse("/", status_code=303)
    sessions.set_cookie(response, sid)
    return response


@router.post("/logout")
def logout(request: Request, csrf_token: str = Form()):
    if not sessions.csrf_valid(request, csrf_token):
        log_event(request, "logout", "failure", reason="csrf")
        return RedirectResponse("/", status_code=303)

    log_event(request, "logout", "success")
    sessions.delete_session(request.cookies.get(sessions.COOKIE_NAME))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(sessions.COOKIE_NAME, secure=True, httponly=True, samesite="strict")
    return response
