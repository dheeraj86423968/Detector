"""Allow-listed HTTPS egress proxy (HTTP CONNECT only) for the otherwise offline backend network.

The api service reaches the identity provider (OIDC discovery, JWKS, token endpoint) through this proxy; nothing
else on the backend network has a route out. Only CONNECT to host:port pairs in the allow-list is relayed - TLS is
end to end between the api and the IdP, the proxy sees only the host name.

  PDP_EGRESS_ALLOW   comma-separated host[:port] (default port 443); default: the host of PDP_OIDC_ISSUER
  PDP_EGRESS_PORT    listen port (default 3128)

Run: python -m pdp_server.egress   (compose service "egress", profile "sso")
"""
from __future__ import annotations

import asyncio
import logging
import os
import urllib.parse

log = logging.getLogger("pdp.egress")


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


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, allowed: set[tuple[str, int]]) -> None:
    peer = writer.get_extra_info("peername")
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
        method, target, _ = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ", 2)
        if method.upper() != "CONNECT":
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            return
        host, _, port = target.rpartition(":")
        host, port = host.lower().strip("[]"), int(port)
        if (host, port) not in allowed:
            log.warning("refused CONNECT %s:%s from %s", host, port, peer)
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        up_r, up_w = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
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
    allowed = allow_list()
    if not allowed:
        raise SystemExit("PDP_EGRESS_ALLOW (or PDP_OIDC_ISSUER) is not set - nothing to allow")
    port = int(os.environ.get("PDP_EGRESS_PORT", "3128"))
    srv = await asyncio.start_server(lambda r, w: handle(r, w, allowed), "0.0.0.0", port)
    log.info("egress proxy on :%d allowing %s", port, ", ".join(f"{h}:{p}" for h, p in sorted(allowed)))
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
