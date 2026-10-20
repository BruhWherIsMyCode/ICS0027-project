from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from app.db import Base, engine
from app.routes import auth
from app.sessions import SessionMiddleware
from app.templating import templates

Base.metadata.create_all(engine)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.include_router(auth.router)


@app.get("/")
def index(request: Request):
    return templates.TemplateResponse(request, "home.html")
