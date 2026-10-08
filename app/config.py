import os

from dotenv import load_dotenv

load_dotenv()

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8443"))
SSL_CERTFILE = os.getenv("SSL_CERTFILE", "certs/cert.pem")
SSL_KEYFILE = os.getenv("SSL_KEYFILE", "certs/key.pem")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///vault.db")
