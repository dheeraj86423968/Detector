"""SSO end-to-end: a real browser signs in to the console through Keycloak (tests/e2e/sso/run_sso_e2e.sh).

Checks: the login page offers SSO; admin and analyst roles come from IdP groups; a user in no mapped group is
refused; an IdP account cannot take over a local account with the same username; the callback cannot be replayed;
a forged state is refused; role changes at the IdP apply at the next sign-in; logout ends the IdP session too.
"""
import json
import os
import sys
import urllib.parse
import urllib.request

from playwright.sync_api import sync_playwright

BASE = os.environ.get("PDP_CONSOLE", "https://gateway")
KC = os.environ.get("KC", "http://keycloak:8080")
fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg, flush=True)
    fails += 0 if cond else 1


def kc_admin_token():
    data = urllib.parse.urlencode({"grant_type": "password", "client_id": "admin-cli", "username": "kcadmin",
                                   "password": "kcadmin-test-only"}).encode()
    return json.loads(urllib.request.urlopen(f"{KC}/realms/master/protocol/openid-connect/token", data).read())["access_token"]


def kc(method, path, body=None):
    req = urllib.request.Request(f"{KC}/admin/realms/pdp/{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {kc_admin_token()}", "Content-Type": "application/json"})
    raw = urllib.request.urlopen(req).read()
    return json.loads(raw) if raw else None


def sso_login(browser, user, pw):
    ctx = browser.new_context(ignore_https_errors=True)
    pg = ctx.new_page()
    pg.goto(f"{BASE}/#/login")
    pg.wait_for_selector("a.sso", timeout=15000)
    pg.click("a.sso")
    pg.wait_for_selector("#username", timeout=20000)
    pg.fill("#username", user)
    pg.fill("#password", pw)
    pg.click("#kc-login")
    pg.wait_for_load_state("networkidle")
    pg.wait_for_timeout(1500)
    return ctx, pg


def me(pg):
    return pg.evaluate("fetch('/api/me').then(r => r.status === 200 ? r.json() : {status: r.status})")


with sync_playwright() as p:
    b = p.chromium.launch()

    ctx = b.new_context(ignore_https_errors=True)
    pg = ctx.new_page()
    pg.goto(f"{BASE}/#/login")
    pg.wait_for_selector("a.sso", timeout=15000)
    check(pg.inner_text("a.sso") == "Sign in with Keycloak", "login page offers the configured SSO button")
    check(pg.locator("input[type=password]").count() == 1, "password sign-in still offered (PDP_PASSWORD_LOGIN=enabled)")
    ctx.close()

    ctx, pg = sso_login(b, "alice", "alice-pass-123")
    m = me(pg)
    check(m.get("role") == "admin" and m.get("auth") == "oidc" and m.get("email") == "alice@example.com",
          f"alice (pdp-admins) signs in as admin via SSO: {m}")
    check("#/endpoints" in pg.url, "lands on the endpoints page")
    users = pg.evaluate("fetch('/api/users').then(r => r.json())")
    alice = [u for u in users.get("users", []) if u["username"] == "alice"]
    check(alice and alice[0]["auth"] == "oidc", "Users page lists alice as an SSO account")
    pw = pg.evaluate("fetch('/api/me/password', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({old_password:'x', new_password:'yyyyyyyyyyyy'})}).then(r => r.status)")
    check(pw == 400, "an SSO account has no PDP password to change")
    # logout ends the IdP session too
    pg.click("text=Log out")
    try:
        pg.wait_for_url("**/protocol/openid-connect/logout**", timeout=15000)
    except Exception:  # noqa
        pass
    check("/realms/pdp/protocol/openid-connect/logout" in pg.url, f"logout redirects to the IdP's end-session endpoint ({pg.url[:80]})")
    check(ctx.request.get(f"{BASE}/api/me").status == 401, "the console session is gone after logout")
    ctx.close()

    ctx, pg = sso_login(b, "bob", "bob-pass-123")
    m = me(pg)
    check(m.get("role") == "analyst" and m.get("auth") == "oidc", f"bob (pdp-analysts) signs in as analyst: {m}")
    check(pg.evaluate("fetch('/api/users').then(r => r.status)") == 403, "analyst cannot list users")
    check(pg.locator("nav >> text=Users").count() == 0, "analyst sees no Users menu")
    ctx.close()

    ctx, pg = sso_login(b, "carol", "carol-pass-123")
    check("sso_error" in pg.url and "not in a group" in urllib.parse.unquote(pg.url), "carol (no mapped group) is refused")
    check(me(pg).get("status") == 401, "no session for carol")
    check("not in a group" in pg.inner_text("div.err"), "the refusal is shown on the login page")
    ctx.close()

    ctx, pg = sso_login(b, "admin", "impostor-pass-123")
    check("sso_error" in pg.url and "already used" in urllib.parse.unquote(pg.url),
          "an IdP account named 'admin' cannot take over the local admin account")
    ctx.close()

    # replay: capture the callback URL, use it a second time
    ctx = b.new_context(ignore_https_errors=True)
    pg = ctx.new_page()
    cb = []
    pg.on("request", lambda r: cb.append(r.url) if "/api/oidc/callback" in r.url else None)
    pg.goto(f"{BASE}/api/oidc/login")
    pg.wait_for_selector("#username")
    pg.fill("#username", "bob"); pg.fill("#password", "bob-pass-123"); pg.click("#kc-login")
    pg.wait_for_load_state("networkidle")
    check(me(pg).get("role") == "analyst", "first use of the callback signs in")
    ctx2 = b.new_context(ignore_https_errors=True)
    pg2 = ctx2.new_page()
    pg2.goto(cb[0]); pg2.wait_for_load_state("networkidle")
    check("sso_error" in pg2.url and me(pg2).get("status") == 401, "a captured callback URL cannot be replayed in another browser")
    pg.goto(cb[0]); pg.wait_for_load_state("networkidle")
    check("sso_error" in pg.url, "nor in the same browser (state cookie consumed, code single-use)")
    ctx.close(); ctx2.close()

    # role change at the IdP applies at the next sign-in
    bob_id = kc("GET", "users?username=bob&exact=true")[0]["id"]
    groups = {g["name"]: g["id"] for g in kc("GET", "groups")}
    kc("PUT", f"users/{bob_id}/groups/{groups['pdp-admins']}")
    kc("DELETE", f"users/{bob_id}/groups/{groups['pdp-analysts']}")
    ctx, pg = sso_login(b, "bob", "bob-pass-123")
    check(me(pg).get("role") == "admin", "bob moved to pdp-admins at the IdP is admin at the next sign-in")
    kc("DELETE", f"users/{bob_id}/groups/{groups['pdp-admins']}")
    old_ctx, old_pg = ctx, pg
    ctx, pg = sso_login(b, "bob", "bob-pass-123")
    check("sso_error" in pg.url, "bob removed from all PDP groups at the IdP is refused at the next sign-in")
    check(me(old_pg).get("status") == 401, "and bob's still-open admin session is ended")
    ctx.close(); old_ctx.close()
    kc("PUT", f"users/{bob_id}/groups/{groups['pdp-analysts']}")
    b.close()

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
