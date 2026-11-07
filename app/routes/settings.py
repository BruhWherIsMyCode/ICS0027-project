from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app import crypto, mfa, sessions
from app.db import Entry, User, get_db
from app.logs import log_event
from app.routes.auth import MIN_PASSWORD_LENGTH
from app.sessions import Session, require_user
from app.templating import templates

router = APIRouter()


def password_error(request: Request, error: str):
    log_event(request, "password_change", "failure", reason=error)
    context = {"error": error}
    return templates.TemplateResponse(request, "password.html", context, status_code=400)


@router.get("/settings/password")
def password_form(request: Request, session: Session = Depends(require_user)):
    return templates.TemplateResponse(request, "password.html")


@router.post("/settings/password")
def change_password(
    request: Request,
    current_password: str = Form(max_length=1024),
    new_password: str = Form(max_length=1024),
    confirm: str = Form(max_length=1024),
    csrf_token: str = Form(),
    session: Session = Depends(require_user),
    db: DbSession = Depends(get_db),
):
    if not sessions.csrf_valid(request, csrf_token):
        return password_error(request, "The form expired. Please try again.")
    if sessions.is_locked(session.username):
        return password_error(request, "Too many failed attempts. Try again in 15 minutes.")

    user = db.get(User, session.user_id)
    if not crypto.verify_password(user.password_hash, current_password):
        sessions.record_failed_login(session.username)
        return password_error(request, "The current master password is wrong.")
    if len(new_password) < MIN_PASSWORD_LENGTH:
        return password_error(request, f"Master password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if new_password != confirm:
        return password_error(request, "Passwords do not match.")

    new_salt = crypto.new_salt()
    new_key = crypto.derive_key(new_password, new_salt)
    entries = db.scalars(select(Entry).where(Entry.owner_id == user.id)).all()
    for entry in entries:
        secret = crypto.decrypt(session.key, entry.nonce, entry.ciphertext, entry.id)
        entry.nonce, entry.ciphertext = crypto.encrypt(new_key, secret, entry.id)
    if user.mfa_enabled:
        totp_secret = mfa.decrypt_secret(session.key, user)
        mfa.encrypt_secret(new_key, user, totp_secret)
    user.password_hash = crypto.hash_password(new_password)
    user.key_salt = new_salt
    db.commit()

    sessions.delete_user_sessions(user.id)
    sid = sessions.create_session(user.id, user.username, new_key)
    log_event(request, "password_change", "success", entries=len(entries))

    response = RedirectResponse("/settings/password?changed=1", status_code=303)
    sessions.set_cookie(response, sid)
    return response


def mfa_page(request: Request, session: Session, user: User, error: str | None = None):
    context = {"enabled": user.mfa_enabled, "error": error}
    if not user.mfa_enabled:
        if session.totp_setup is None:
            session.totp_setup = mfa.new_secret()
        context["secret"] = session.totp_setup
        context["qr"] = mfa.qr_code(session.totp_setup, user.username)
    status_code = 400 if error else 200
    return templates.TemplateResponse(request, "mfa.html", context, status_code=status_code)


def mfa_settings_error(request: Request, session: Session, user: User, error: str):
    log_event(request, "mfa_change", "failure", reason=error)
    return mfa_page(request, session, user, error)


@router.get("/settings/mfa")
def mfa_settings(
    request: Request,
    session: Session = Depends(require_user),
    db: DbSession = Depends(get_db),
):
    user = db.get(User, session.user_id)
    return mfa_page(request, session, user)


@router.post("/settings/mfa")
def change_mfa(
    request: Request,
    password: str = Form(max_length=1024),
    code: str = Form(max_length=10),
    csrf_token: str = Form(),
    session: Session = Depends(require_user),
    db: DbSession = Depends(get_db),
):
    user = db.get(User, session.user_id)
    if not sessions.csrf_valid(request, csrf_token):
        return mfa_settings_error(request, session, user, "The form expired. Please try again.")
    if sessions.is_locked(session.username):
        return mfa_settings_error(request, session, user, "Too many failed attempts. Try again in 15 minutes.")
    if not crypto.verify_password(user.password_hash, password):
        sessions.record_failed_login(session.username)
        return mfa_settings_error(request, session, user, "The master password is wrong.")

    if user.mfa_enabled:
        secret = mfa.decrypt_secret(session.key, user)
    else:
        secret = session.totp_setup
    if secret is None or not mfa.verify(secret, code):
        sessions.record_failed_login(session.username)
        return mfa_settings_error(request, session, user, "Invalid code.")

    if user.mfa_enabled:
        user.mfa_enabled = False
        user.totp_nonce = None
        user.totp_ciphertext = None
        event = "mfa_disable"
    else:
        mfa.encrypt_secret(session.key, user, secret)
        user.mfa_enabled = True
        session.totp_setup = None
        event = "mfa_enable"
    db.commit()
    log_event(request, event, "success")
    return RedirectResponse("/settings/mfa", status_code=303)
