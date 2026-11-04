"""Operator recovery: set a new password for a console user and clear its sign-in lockout (forgotten admin
password, a restored copy of the database). Run on the server:

  docker compose exec api python -m pdp_server.tools.reset_password admin            # prints a new random password
  docker compose exec -T api python -m pdp_server.tools.reset_password admin --stdin  # reads the password from stdin
"""
from __future__ import annotations

import argparse
import secrets
import sys

from pdp_server import auth, db


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("username")
    ap.add_argument("--stdin", action="store_true", help="read the new password from standard input")
    a = ap.parse_args()
    pw = sys.stdin.readline().strip() if a.stdin else secrets.token_urlsafe(14)
    if len(pw) < 10:
        raise SystemExit("password too short (10 characters at least)")
    with db.conn() as c:
        u = db.q(c, "SELECT id FROM users WHERE lower(username)=lower(%s)", (a.username,), one=True)
        if not u:
            raise SystemExit(f"no user {a.username!r}")
        db.q(c, "UPDATE users SET password_hash=%s, failed_logins=0, locked_until=NULL WHERE id=%s", (auth.hash_password(pw), u["id"]))
    print(f"password of {a.username} reset" + ("" if a.stdin else f"; new password: {pw}"))


if __name__ == "__main__":
    main()
