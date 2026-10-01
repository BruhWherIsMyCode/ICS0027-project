import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app import crypto, sessions
from app.db import Entry, get_db
from app.sessions import Session, require_user
from app.templating import templates

router = APIRouter()


class EntryForm(BaseModel):
    model_config = {"extra": "forbid"}

    title: str = Field(max_length=200)
    url: str = Field("", max_length=2048)
    username: str = Field("", max_length=200)
    password: str = Field("", max_length=1024)
    notes: str = Field("", max_length=5000)
    csrf_token: str


def validate(request: Request, form: EntryForm) -> str | None:
    if not sessions.csrf_valid(request, form.csrf_token):
        return "The form expired. Please try again."
    if not form.title.strip():
        return "Title is required."
    if form.url and not form.url.startswith(("http://", "https://")):
        return "URL must start with http:// or https://."
    return None


def secret_fields(form: EntryForm) -> dict:
    return {"username": form.username, "password": form.password, "notes": form.notes}


def get_entry(db: DbSession, entry_id: str, user_id: int) -> Entry:
    query = select(Entry).where(Entry.id == entry_id, Entry.owner_id == user_id)
    entry = db.scalar(query)
    if entry is None:
        raise HTTPException(status_code=404)
    return entry


@router.get("/vault")
def vault(
    request: Request,
    q: str = "",
    session: Session = Depends(require_user),
    db: DbSession = Depends(get_db),
):
    query = select(Entry).where(Entry.owner_id == session.user_id)
    if q:
        matches = Entry.title.icontains(q, autoescape=True) | Entry.url.icontains(q, autoescape=True)
        query = query.where(matches)
    entries = db.scalars(query.order_by(Entry.title)).all()
    return templates.TemplateResponse(request, "vault.html", {"entries": entries, "q": q})


@router.get("/vault/new")
def new_entry_form(request: Request, session: Session = Depends(require_user)):
    context = {"heading": "New entry", "action": "/vault/new", "values": {}}
    return templates.TemplateResponse(request, "entry_form.html", context)


@router.post("/vault/new")
def create_entry(
    request: Request,
    form: Annotated[EntryForm, Form()],
    session: Session = Depends(require_user),
    db: DbSession = Depends(get_db),
):
    error = validate(request, form)
    if error:
        context = {
            "heading": "New entry",
            "action": "/vault/new",
            "values": form.model_dump(),
            "error": error,
        }
        return templates.TemplateResponse(request, "entry_form.html", context, status_code=400)

    entry_id = str(uuid.uuid4())
    nonce, ciphertext = crypto.encrypt(session.key, secret_fields(form), entry_id)
    entry = Entry(
        id=entry_id,
        owner_id=session.user_id,
        title=form.title.strip(),
        url=form.url.strip(),
        nonce=nonce,
        ciphertext=ciphertext,
    )
    db.add(entry)
    db.commit()
    return RedirectResponse(f"/vault/{entry_id}", status_code=303)


@router.get("/vault/{entry_id}")
def view_entry(
    request: Request,
    entry_id: str,
    session: Session = Depends(require_user),
    db: DbSession = Depends(get_db),
):
    entry = get_entry(db, entry_id, session.user_id)
    secret = crypto.decrypt(session.key, entry.nonce, entry.ciphertext, entry.id)
    context = {"entry": entry, "secret": secret}
    return templates.TemplateResponse(request, "entry.html", context)


@router.get("/vault/{entry_id}/edit")
def edit_entry_form(
    request: Request,
    entry_id: str,
    session: Session = Depends(require_user),
    db: DbSession = Depends(get_db),
):
    entry = get_entry(db, entry_id, session.user_id)
    secret = crypto.decrypt(session.key, entry.nonce, entry.ciphertext, entry.id)
    values = {"title": entry.title, "url": entry.url, **secret}
    context = {"heading": "Edit entry", "action": f"/vault/{entry.id}/edit", "values": values}
    return templates.TemplateResponse(request, "entry_form.html", context)


@router.post("/vault/{entry_id}/edit")
def update_entry(
    request: Request,
    entry_id: str,
    form: Annotated[EntryForm, Form()],
    session: Session = Depends(require_user),
    db: DbSession = Depends(get_db),
):
    entry = get_entry(db, entry_id, session.user_id)
    error = validate(request, form)
    if error:
        context = {
            "heading": "Edit entry",
            "action": f"/vault/{entry.id}/edit",
            "values": form.model_dump(),
            "error": error,
        }
        return templates.TemplateResponse(request, "entry_form.html", context, status_code=400)

    entry.title = form.title.strip()
    entry.url = form.url.strip()
    entry.nonce, entry.ciphertext = crypto.encrypt(session.key, secret_fields(form), entry.id)
    db.commit()
    return RedirectResponse(f"/vault/{entry.id}", status_code=303)


@router.post("/vault/{entry_id}/delete")
def delete_entry(
    request: Request,
    entry_id: str,
    csrf_token: str = Form(),
    session: Session = Depends(require_user),
    db: DbSession = Depends(get_db),
):
    entry = get_entry(db, entry_id, session.user_id)
    if not sessions.csrf_valid(request, csrf_token):
        raise HTTPException(status_code=400)

    db.delete(entry)
    db.commit()
    return RedirectResponse("/vault", status_code=303)
