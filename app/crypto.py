import json
import os

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TIME_COST = 3
MEMORY_COST = 65536
PARALLELISM = 4

hasher = PasswordHasher(
    time_cost=TIME_COST,
    memory_cost=MEMORY_COST,
    parallelism=PARALLELISM,
    type=Type.ID,
)


def hash_password(password: str) -> str:
    return hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def new_salt() -> bytes:
    return os.urandom(16)


def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=TIME_COST,
        memory_cost=MEMORY_COST,
        parallelism=PARALLELISM,
        hash_len=32,
        type=Type.ID,
    )


def encrypt(key: bytes, data: dict, associated_data: str) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    plaintext = json.dumps(data).encode()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data.encode())
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: str) -> dict:
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, associated_data.encode())
    return json.loads(plaintext)
