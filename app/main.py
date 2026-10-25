from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.db import Base, engine
from app.routes import auth, vault
from app.sessions import SessionMiddleware

Base.metadata.create_all(engine)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.include_router(auth.router)
app.include_router(vault.router)


@app.get("/")
def index(request: Request):
    if request.state.session.user_id:
        return RedirectResponse("/vault", status_code=303)
    return RedirectResponse("/login", status_code=303)
