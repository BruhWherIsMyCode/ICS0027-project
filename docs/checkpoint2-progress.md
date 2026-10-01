# Checkpoint 2 progress note

## Done

- You can register, log in, log out, and list, search, create, view, edit and
  delete vault entries.
- The server encrypts each entry's username, password and notes with
  AES-256-GCM, using a fresh nonce on every save and the entry ID as associated
  data.
- Argon2id hashes the master password for login. A second Argon2id run with its
  own salt derives the encryption key, and the server never stores that key.
- Sessions live in server memory. The `__Host-session` cookie carries only a
  random ID (Secure, HttpOnly, SameSite=Strict). Sessions expire after 15
  minutes idle or 8 hours total, and login issues a new ID. Every form carries
  a CSRF token.
- The master password needs at least 12 characters. Unknown users and wrong
  passwords get the same error, and 5 failures in 15 minutes lock the username.
- `scripts/gen_cert.py` creates a self-signed localhost certificate, and
  `run.py` refuses to start without it.

Restarting the server logs everyone out, because sessions live in memory.
