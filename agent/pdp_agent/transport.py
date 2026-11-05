"""HTTPS client with mutual TLS (stdlib only, so the agent runtime stays small)."""
from __future__ import annotations

import gzip
import http.client
import json
import socket
import ssl
import time
from urllib.parse import urlparse

RETRYABLE = (ConnectionError, socket.timeout, socket.gaierror, OSError, http.client.HTTPException)


class Transport:
    def __init__(self, base_url: str, ca_pem_path: str | None = None, cert_path: str | None = None, key_path: str | None = None, timeout: float = 60,
                 connect_timeout: float = 10, attempts: int = 6):
        u = urlparse(base_url)
        self.host, self.port, self.prefix = u.hostname, u.port or 443, u.path.rstrip("/")
        self.ctx = ssl.create_default_context(cafile=ca_pem_path) if ca_pem_path else ssl.create_default_context()
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if cert_path:
            self.ctx.load_cert_chain(cert_path, key_path)
        self.timeout = timeout                   # per read once connected (uploads, downloads)
        # connecting (TCP + TLS) fails fast: a network that silently drops packets must not hold the caller for
        # minutes. `attempts`: the default number of tries (the agent's main loop uses 1: it retries on its own)
        self.connect_timeout = connect_timeout
        self.attempts = attempts

    # set while the endpoint is isolated: the server's addresses resolved before isolation (DNS is blocked then);
    # TLS still verifies the server's name
    pinned: list[str] | None = None

    def _conn(self):
        if self.pinned:
            return _PinnedHTTPS(self.host, self.port, self.pinned, context=self.ctx, timeout=self.timeout, connect_timeout=self.connect_timeout)
        return _HTTPS(self.host, self.port, context=self.ctx, timeout=self.timeout, connect_timeout=self.connect_timeout)

    def request(self, method: str, path: str, body=None, headers: dict | None = None, raw: bool = False, attempts: int | None = None):
        """Connection-level failures (refused, no route, timeout, reset, 502/503 from the gateway) are retried with
        exponential backoff; application errors (4xx with a JSON body) are raised immediately."""
        delay = 2.0
        attempts = attempts or self.attempts
        for i in range(attempts):
            try:
                return self._request(method, path, body, headers, raw)
            except TransportError as e:
                if e.status not in (502, 503, 504) or i == attempts - 1:
                    raise
            except RETRYABLE:
                if i == attempts - 1:
                    raise
            time.sleep(delay)
            delay = min(delay * 2, 60)

    def _request(self, method: str, path: str, body=None, headers: dict | None = None, raw: bool = False):
        h = {"Accept": "application/json", **(headers or {})}
        data = None
        if body is not None:
            if isinstance(body, (bytes, bytearray)):
                data = bytes(body)
            else:
                data = json.dumps(body).encode()
                h["Content-Type"] = "application/json"
        c = self._conn()
        try:
            c.request(method, self.prefix + path, body=data, headers=h)
            r = c.getresponse()
            payload = r.read()
            if raw:
                return r.status, dict(r.getheaders()), payload
            try:
                js = json.loads(payload.decode() or "{}")
            except json.JSONDecodeError:            # an HTML error page from the gateway or a proxy (502, 503 ...)
                js = {"ok": False, "error": f"HTTP {r.status} from {self.host} (not an answer from the PDP server: the gateway or a proxy)"}
            if r.status >= 400 or not js.get("ok", False):
                raise TransportError(r.status, js.get("error", js.get("detail", "request failed")))
            return js
        finally:
            c.close()

    def download(self, path: str, dest: str, attempts: int | None = None) -> dict:
        """GET `path` streamed into the file `dest` (models are hundreds of MB: never held in memory). Returns the
        response headers. Retried like request()."""
        delay = 2.0
        attempts = attempts or self.attempts
        for i in range(attempts):
            c = self._conn()
            try:
                c.request("GET", self.prefix + path, headers={"Accept": "*/*"})
                r = c.getresponse()
                if r.status != 200:
                    body = r.read(500).decode(errors="replace")
                    raise TransportError(r.status, body or "download failed")
                with open(dest, "wb") as f:
                    while True:
                        chunk = r.read(1 << 20)
                        if not chunk:
                            break
                        f.write(chunk)
                return dict(r.getheaders())
            except TransportError as e:
                if e.status not in (502, 503, 504) or i == attempts - 1:
                    raise
            except RETRYABLE:
                if i == attempts - 1:
                    raise
            finally:
                c.close()
            time.sleep(delay)
            delay = min(delay * 2, 60)

    def post_ndjson(self, path: str, rows: list[dict], batch_id: str | None = None):
        body = gzip.compress("\n".join(json.dumps(r) for r in rows).encode())
        h = {"Content-Type": "application/x-ndjson", "Content-Encoding": "gzip"}
        if batch_id:
            h["X-Batch-Id"] = batch_id
        return self.request("POST", path, body=body, headers=h)


class _HTTPS(http.client.HTTPSConnection):
    """HTTPS with its own (short) timeout for connecting and the TLS handshake; `timeout` then applies to reads."""
    def __init__(self, host, port, connect_timeout: float = 10, **kw):
        super().__init__(host, port, **kw)
        self._connect_timeout = connect_timeout

    def connect(self):
        t, self.timeout = self.timeout, min(self.timeout, self._connect_timeout)
        try:
            super().connect()
        finally:
            self.timeout = t
        self.sock.settimeout(t)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, addrs, connect_timeout: float = 10, **kw):
        super().__init__(host, port, **kw)
        self._addrs = addrs
        self._connect_timeout = connect_timeout

    def connect(self):
        err = None
        for a in self._addrs:
            try:
                sock = socket.create_connection((a, self.port), min(self.timeout, self._connect_timeout))
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
                self.sock.settimeout(self.timeout)
                return
            except OSError as e:
                err = e
        raise err or OSError("no pinned address")


class TransportError(RuntimeError):
    def __init__(self, status: int, msg: str):
        super().__init__(f"{status}: {msg}")
        self.status = status
