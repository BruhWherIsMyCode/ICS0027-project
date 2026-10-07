import os
import sys

import uvicorn

from app import config

if not os.path.exists(config.SSL_CERTFILE) or not os.path.exists(config.SSL_KEYFILE):
    sys.exit("TLS certificate not found. Please run - python scripts/gen_cert.py")

uvicorn.run(
    "app.main:app",
    host=config.HOST,
    port=config.PORT,
    ssl_certfile=config.SSL_CERTFILE,
    ssl_keyfile=config.SSL_KEYFILE,
)
