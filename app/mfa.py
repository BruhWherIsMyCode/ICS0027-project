import pyotp
import segno

from app import crypto
from app.db import User

ISSUER = "Password Manager"


def new_secret() -> str:
    return pyotp.random_base32()


def qr_code(secret: str, username: str) -> str:
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)
    return segno.make(uri).svg_data_uri(scale=4)


def verify(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)


def encrypt_secret(key: bytes, user: User, secret: str):
    user.totp_nonce, user.totp_ciphertext = crypto.encrypt(key, {"secret": secret}, f"totp:{user.id}")


def decrypt_secret(key: bytes, user: User) -> str:
    data = crypto.decrypt(key, user.totp_nonce, user.totp_ciphertext, f"totp:{user.id}")
    return data["secret"]
