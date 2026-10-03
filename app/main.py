from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from app.templating import templates

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/")
def index(request: Request):
    return templates.TemplateResponse(request, "home.html")
