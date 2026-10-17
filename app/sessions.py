import secrets
import time
from dataclasses import dataclass, field

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app import config

COOKIE_NAME = "__Host-session"


@dataclass
class Session:
    csrf_token: str
    user_id: int | None = None
    username: str | None = None
    key: bytes | None = None
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


sessions: dict[str, Session] = {}


def is_expired(session: Session, now: float) -> bool:
    if now - session.last_seen > config.SESSION_IDLE_SECONDS:
        return True
    return now - session.created_at > config.SESSION_ABSOLUTE_SECONDS


def remove_expired():
    now = time.time()
    for sid, session in list(sessions.items()):
        if is_expired(session, now):
            sessions.pop(sid, None)


def create_session(user_id=None, username=None, key=None) -> str:
    remove_expired()
    sid = secrets.token_urlsafe(32)
    sessions[sid] = Session(secrets.token_urlsafe(32), user_id, username, key)
    return sid


def get_session(sid: str) -> Session | None:
    session = sessions.get(sid)
    if session is None:
        return None
    now = time.time()
    if is_expired(session, now):
        sessions.pop(sid, None)
        return None
    session.last_seen = now
    return session


def delete_session(sid: str):
    sessions.pop(sid, None)


def set_cookie(response, sid: str):
    response.set_cookie(COOKIE_NAME, sid, secure=True, httponly=True, samesite="strict")


def csrf_valid(request: Request, token: str) -> bool:
    expected = request.state.session.csrf_token
    return secrets.compare_digest(expected.encode(), token.encode())


class SessionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        sid = request.cookies.get(COOKIE_NAME)
        session = get_session(sid) if sid else None
        new_sid = None
        if session is None:
            new_sid = create_session()
            session = sessions[new_sid]
        request.state.session = session

        response = await call_next(request)

        if new_sid:
            set_cookie(response, new_sid)
        return response
