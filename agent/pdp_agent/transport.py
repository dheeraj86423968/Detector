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
    def __init__(self, base_url: str, ca_pem_path: str | None = None, cert_path: str | None = None, key_path: str | None = None, timeout: float = 60):
        u = urlparse(base_url)
        self.host, self.port, self.prefix = u.hostname, u.port or 443, u.path.rstrip("/")
        self.ctx = ssl.create_default_context(cafile=ca_pem_path) if ca_pem_path else ssl.create_default_context()
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if cert_path:
            self.ctx.load_cert_chain(cert_path, key_path)
        self.timeout = timeout

    def _conn(self):
        return http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=self.timeout)

    def request(self, method: str, path: str, body=None, headers: dict | None = None, raw: bool = False, attempts: int = 6):
        """Connection-level failures (refused, no route, timeout, reset, 502/503 from the gateway) are retried with
        exponential backoff; application errors (4xx with a JSON body) are raised immediately."""
        delay = 2.0
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
            except json.JSONDecodeError:
                js = {"ok": False, "error": payload[:200].decode(errors="replace")}
            if r.status >= 400 or not js.get("ok", False):
                raise TransportError(r.status, js.get("error", js.get("detail", "request failed")))
            return js
        finally:
            c.close()

    def post_ndjson(self, path: str, rows: list[dict], batch_id: str | None = None):
        body = gzip.compress("\n".join(json.dumps(r) for r in rows).encode())
        h = {"Content-Type": "application/x-ndjson", "Content-Encoding": "gzip"}
        if batch_id:
            h["X-Batch-Id"] = batch_id
        return self.request("POST", path, body=body, headers=h)


class TransportError(RuntimeError):
    def __init__(self, status: int, msg: str):
        super().__init__(f"{status}: {msg}")
        self.status = status
