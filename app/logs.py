import json
import logging
from datetime import datetime, timezone

from fastapi import Request

from app import config

logger = logging.getLogger("password_manager")
logger.setLevel(logging.INFO)
logger.propagate = False
logger.addHandler(logging.StreamHandler())
logger.addHandler(logging.FileHandler(config.LOG_FILE, encoding="utf-8"))


def log_event(request: Request, event: str, outcome: str, **fields):
    session = request.state.session
    record = {
        "time": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "outcome": outcome,
        "user_id": session.user_id if session else None,
        "request_id": request.state.request_id,
        "ip": request.client.host if request.client else None,
        "path": request.url.path,
        **fields,
    }
    logger.info(json.dumps(record))
