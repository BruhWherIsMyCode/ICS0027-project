# Web-Based Secure Password Manager

A multi-user web password manager. The server encrypts stored credentials with
a key derived from the user's master password.

## Running locally

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python scripts/gen_cert.py
python run.py
```

Open https://127.0.0.1:8443/ and accept the self-signed certificate warning.
