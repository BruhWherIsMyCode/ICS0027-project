# Web-Based Secure Password Manager

A multi-user web password manager. The server encrypts stored credentials with
a key derived from the user's master password.

[Progress note](docs/checkpoint2-progress.md)

## Running locally

You need Python 3.12 or newer.

```
git clone https://github.com/BruhWherIsMyCode/ICS0027-project.git
cd ICS0027-project
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python scripts/gen_cert.py
python run.py
```

On Linux or macOS, activate with - `source .venv/bin/activate`.

Open https://127.0.0.1:8443/ and accept the self-signed certificate warning.

There are optional settings in `.env.example`.
