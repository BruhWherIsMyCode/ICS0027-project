import os
import secrets

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException

from app.db import Base, engine
from app.logs import log_event
from app.routes import auth, settings, vault
from app.sessions import SessionMiddleware
from app.templating import templates

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
    "Strict-Transport-Security": "max-age=31536000",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

ERROR_MESSAGES = {
    400: "The request was not valid.",
    404: "Page not found.",
    405: "This action is not allowed.",
    500: "Something went wrong.",
}

Base.metadata.create_all(engine)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware)
app.mount("/static", StaticFiles(directory=os.path.join("app", "static")), name="static")
app.include_router(auth.router)
app.include_router(vault.router)
app.include_router(settings.router)


def error_page(request: Request, status_code: int):
    message = ERROR_MESSAGES.get(status_code, ERROR_MESSAGES[400])
    context = {"message": message, "status_code": status_code}
    return templates.TemplateResponse(request, "error.html", context, status_code=status_code)


@app.middleware("http")
async def request_context(request: Request, call_next):
    request.state.request_id = secrets.token_hex(8)
    request.state.session = None
    try:
        response = await call_next(request)
    except Exception as error:
        log_event(request, "server_error", "failure", error=type(error).__name__)
        response = error_page(request, 500)

    for name, value in SECURITY_HEADERS.items():
        response.headers[name] = value
    response.headers["X-Request-ID"] = request.state.request_id
    return response


@app.exception_handler(HTTPException)
async def http_error(request: Request, error: HTTPException):
    if error.status_code == 303:
        return RedirectResponse(error.headers["Location"], status_code=303)
    log_event(request, "http_error", "failure", status=error.status_code)
    return error_page(request, error.status_code)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, error: RequestValidationError):
    fields = [".".join(str(part) for part in item["loc"]) for item in error.errors()]
    log_event(request, "invalid_input", "failure", fields=fields)
    return error_page(request, 400)


@app.get("/")
def index(request: Request):
    session = request.state.session
    if session.user_id and not session.mfa_pending:
        return RedirectResponse("/vault", status_code=303)
    return RedirectResponse("/login", status_code=303)
