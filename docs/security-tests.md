# Security test results

All 54 tests in the tests folder passed.

The SQL injection tests send six payloads: ' OR '1'='1, ' OR 1=1--, admin'--, '; DROP TABLE users;--, " OR ""=" and ' UNION SELECT password_hash FROM users--. As a login username, each one gets a 400 and no session. As a search term, they return only the user's own matching entries. Saved as an entry title, each one comes back exactly as typed and the users table is still there.

The cross-site scripting tests save five payloads as the title and notes of an entry: a script tag, an image and an SVG with JavaScript event handlers, a script that breaks out of an HTML attribute, and a fake login form. The vault list and the entry page show them as plain text. Links with javascript:, data: and vbscript: URLs get a 400. The Content-Security-Policy header allows scripts only from the app itself.

The access control tests log in as a second user and try to read, edit and delete the first user's entry by its ID. Each attempt returns 404 and the entry stays unchanged. Without a login, the vault, an entry and the settings pages redirect to the login page.

The CSRF tests post with an empty token, a random token and a valid token from another session. Each request gets a 400 and nothing changes.

The session tests check that the cookie is __Host-session with the Secure, HttpOnly and SameSite=Strict flags. A session ID planted before login stops working after login. A wrong password and an unknown username get the same error. Five wrong passwords lock the account. A session idle for 15 minutes, a session after logout and the user's other sessions after a master password change all lead back to the login page.

The two-factor tests show that the password alone does not open the vault, that a correct code opens it with a new session ID, and that five wrong codes lock the account.

The error and logging tests open a missing page and a tampered entry. Both show a generic error page with no stack trace and no secret data. A failed login writes one JSON line with the time, event, outcome, user ID, request ID, IP and path. The log contains none of the passwords or notes used in the tests.

The encryption tests find no entry username or password in the database bytes, show that ciphertext moved to another entry fails to decrypt, and check that the login hash is Argon2id.
