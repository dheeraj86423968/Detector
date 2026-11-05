"""Allow-listed HTTPS egress proxy (HTTP CONNECT only) for the otherwise offline backend network.

The api service reaches identity providers (OIDC discovery, JWKS, token endpoint) and the DNS-over-HTTPS resolver
(SSO domain proof) through this proxy; nothing else on the backend network has a route out. Only CONNECT to allowed
host:port pairs is relayed - TLS is end to end between the api and the provider, the proxy sees only the host name.

Allowed destinations:
  static   PDP_EGRESS_ALLOW (comma-separated host[:port], default port 443; default: the host of PDP_OIDC_ISSUER),
           the Google and Microsoft sign-in hosts, and the host of PDP_DOH_URL. Set by the operator: trusted.
  per org  the issuer host of every organisation's own OIDC provider (orgs.sso, provider "oidc") and the hosts of
           its discovery document's token and key endpoints, re-read every minute. Entered by client admins: only
           public addresses are allowed, and the connection goes to the address that was checked (no DNS rebinding
           to internal services).

  PDP_EGRESS_PORT    listen port (default 3128)

Run: python -m pdp_server.egress   (compose service "egress", profile "sso")
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import socket
import time
import urllib.parse
import urllib.request

log = logging.getLogger("pdp.egress")
BUILTIN = {("accounts.google.com", 443), ("oauth2.googleapis.com", 443), ("www.googleapis.com", 443),
           ("openidconnect.googleapis.com", 443), ("login.microsoftonline.com", 443)}


def _hostport(url: str) -> tuple[str, int] | None:
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or not u.hostname:
        return None
    return u.hostname.lower(), u.port or 443


def static_allow() -> set[tuple[str, int]]:
    """Operator-set destinations (trusted, may be internal: an IdP on the company network)."""
    out = allow_list() | BUILTIN
    doh = _hostport(os.environ.get("PDP_DOH_URL", "https://cloudflare-dns.com/dns-query"))
    if doh:
        out.add(doh)
    return out


def public_addrs(host: str, port: int) -> list[str]:
    """Addresses of `host` if every one is a public unicast address, else []."""
    try:
        addrs = sorted({i[4][0] for i in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    except (socket.gaierror, UnicodeError):
        return []
    if not addrs or not all(ipaddress.ip_address(a.split("%")[0]).is_global for a in addrs):
        return []
    return addrs


def _discovery_hosts(issuer: str) -> set[tuple[str, int]]:
    hp = _hostport(issuer)
    if not hp or not public_addrs(*hp):
        return set()
    out = {hp}
    try:
        req = urllib.request.Request(issuer.rstrip("/") + "/.well-known/openid-configuration", headers={"Accept": "application/json"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))      # this service is the way out
        with opener.open(req, timeout=10) as r:
            d = json.loads(r.read(1 << 20))
        for k in ("token_endpoint", "jwks_uri"):
            h = _hostport(str(d.get(k) or ""))
            if h:
                out.add(h)
    except Exception as e:  # noqa: BLE001 - the provider may be down; its issuer host stays allowed
        log.info("discovery of %s failed: %s", issuer, e)
    return out


def org_issuers() -> list[str]:
    from . import db
    with db.conn() as c:
        rows = db.q(c, "SELECT DISTINCT sso->>'issuer' AS iss FROM orgs WHERE NOT disabled AND sso IS NOT NULL "
                       "AND sso->>'provider' = 'oidc' AND (sso->>'enabled')::boolean")
    return [r["iss"] for r in rows if r["iss"]]


class Policy:
    """Static (trusted) destinations plus the organisations' own providers (public addresses only)."""

    def __init__(self, static: set[tuple[str, int]], issuers=org_issuers, refresh_s: float = 60):
        self.static, self._issuers, self.refresh_s = static, issuers, refresh_s
        self.dynamic: set[tuple[str, int]] = set()
        self._disc: dict[str, tuple[float, set]] = {}
        self._at = 0.0

    def refresh(self) -> None:
        try:
            issuers = self._issuers()
        except Exception as e:  # noqa: BLE001 - database briefly unavailable: keep the last list
            log.warning("could not read the organisations' identity providers: %s", e)
            return
        dyn = set()
        for iss in issuers:
            hit = self._disc.get(iss)
            if not hit or time.time() - hit[0] > 3600:
                hit = (time.time(), _discovery_hosts(iss))
                self._disc[iss] = hit
            dyn |= hit[1]
        if dyn != self.dynamic:
            log.info("organisation identity providers allowed: %s", ", ".join(f"{h}:{p}" for h, p in sorted(dyn)) or "none")
        self.dynamic, self._at = dyn, time.time()

    def decide(self, host: str, port: int) -> list[str] | None:
        """None: refused. []: connect by name (static, trusted). [addrs]: connect only to these checked addresses."""
        if (host, port) in self.static:
            return []
        if time.time() - self._at > self.refresh_s:
            self.refresh()
        elif (host, port) not in self.dynamic and time.time() - self._at > 5:
            self.refresh()          # a provider saved since the last read works at once (at most one re-read per 5 s)
        if (host, port) in self.dynamic:
            return public_addrs(host, port) or None
        return None


def allow_list() -> set[tuple[str, int]]:
    raw = os.environ.get("PDP_EGRESS_ALLOW", "")
    if not raw and os.environ.get("PDP_OIDC_ISSUER"):
        u = urllib.parse.urlsplit(os.environ["PDP_OIDC_ISSUER"])
        raw = f"{u.hostname}:{u.port or (443 if u.scheme == 'https' else 80)}"
    out = set()
    for item in filter(None, (x.strip() for x in raw.split(","))):
        host, _, port = item.rpartition(":") if item.rsplit(":", 1)[-1].isdigit() else (item, "", "443")
        out.add((host.lower().strip("[]"), int(port)))
    return out


async def _pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        try:
            w.close()
        except Exception:  # noqa
            pass


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, allowed) -> None:
    """`allowed`: a Policy, or a plain set of trusted host:port pairs."""
    peer = writer.get_extra_info("peername")
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
        method, target, _ = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ", 2)
        if method.upper() != "CONNECT":
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            return
        host, _, port = target.rpartition(":")
        host, port = host.lower().strip("[]"), int(port)
        if isinstance(allowed, Policy):
            addrs = await asyncio.get_running_loop().run_in_executor(None, allowed.decide, host, port)
        else:
            addrs = [] if (host, port) in allowed else None
        if addrs is None:
            log.warning("refused CONNECT %s:%s from %s", host, port, peer)
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        up_r, up_w = await asyncio.wait_for(asyncio.open_connection(addrs[0] if addrs else host, port), 10)
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        log.info("CONNECT %s:%s from %s", host, port, peer)
        await asyncio.gather(_pipe(reader, up_w), _pipe(up_r, writer))
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, asyncio.LimitOverrunError, ValueError, OSError) as e:
        try:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except Exception:  # noqa
            pass
        log.info("connection from %s failed: %s", peer, e)
    finally:
        try:
            await writer.drain()
            writer.close()
        except Exception:  # noqa
            pass


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    policy = Policy(static_allow())
    await asyncio.get_running_loop().run_in_executor(None, policy.refresh)
    port = int(os.environ.get("PDP_EGRESS_PORT", "3128"))
    srv = await asyncio.start_server(lambda r, w: handle(r, w, policy), "0.0.0.0", port)
    log.info("egress proxy on :%d allowing %s and the organisations' own providers", port,
             ", ".join(f"{h}:{p}" for h, p in sorted(policy.static)))
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
