"""Key management service client: the bundle-signing key and the agent CA key live in a Vault-compatible KMS
(OpenBao or HashiCorp Vault), never on the platform's disks.

  * bundle signing  - transit secrets engine, key type ed25519, non-exportable: the platform sends the manifest and
                      gets an Ed25519 signature back (agents verify it with the public key they got at enrolment).
  * agent CA        - PKI secrets engine: the platform sends a CSR and gets a certificate signed by the CA back; the
                      CA private key stays inside the KMS.

The platform authenticates with a token whose policy (`pdp-signer`, written by tools/kms_setup.py) allows exactly
those signing calls - it cannot read, export, import, rotate or delete keys. Every call is in the KMS audit log.

Configuration (environment):
  PDP_KMS=transit             enable (default "file": keys in the pdp_pki volume, development only)
  PDP_KMS_ADDR                e.g. http://kms:8200 (bundled OpenBao) or https://vault.corp:8200
  PDP_KMS_TOKEN_FILE          file holding the token (default /run/pdp-kms/token); or PDP_KMS_TOKEN
  PDP_KMS_CACERT              CA bundle to verify an https KMS (optional)
  PDP_KMS_NAMESPACE           Vault Enterprise / OpenBao namespace (optional)
  PDP_KMS_TRANSIT_MOUNT       default "transit";   PDP_KMS_BUNDLE_KEY  default "pdp-bundle-signing"
  PDP_KMS_PKI_MOUNT           default "pki";       roles "pdp-agent" (client certs) and "pdp-server" (TLS)

Only the standard library is used, so the agent-free server image needs no new dependency.
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import threading
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

MODE = os.environ.get("PDP_KMS", "file").lower()
ADDR = os.environ.get("PDP_KMS_ADDR", "http://kms:8200").rstrip("/")
TOKEN_FILE = os.environ.get("PDP_KMS_TOKEN_FILE", "/run/pdp-kms/token")
CACERT = os.environ.get("PDP_KMS_CACERT")
NAMESPACE = os.environ.get("PDP_KMS_NAMESPACE")
TRANSIT = os.environ.get("PDP_KMS_TRANSIT_MOUNT", "transit")
BUNDLE_KEY = os.environ.get("PDP_KMS_BUNDLE_KEY", "pdp-bundle-signing")
PKI = os.environ.get("PDP_KMS_PKI_MOUNT", "pki")
AGENT_ROLE, SERVER_ROLE = "pdp-agent", "pdp-server"


class KMSError(RuntimeError):
    pass


def enabled() -> bool:
    return MODE == "transit"


class Client:
    """Minimal Vault HTTP API client (KV-free: transit, pki, sys, auth/token)."""

    def __init__(self, addr: str = ADDR, token: str | None = None, cacert: str | None = CACERT,
                 namespace: str | None = NAMESPACE, timeout: float = 10.0):
        self.addr, self._token, self.namespace, self.timeout = addr.rstrip("/"), token, namespace, timeout
        self.ctx = ssl.create_default_context(cafile=cacert) if addr.startswith("https") else None
        self._renewed_at = 0.0
        self._lock = threading.Lock()

    @property
    def token(self) -> str:
        if self._token:
            return self._token
        tok = os.environ.get("PDP_KMS_TOKEN")
        if not tok:
            try:
                tok = open(TOKEN_FILE).read().strip()
            except OSError as e:
                raise KMSError(f"no KMS token: set PDP_KMS_TOKEN or provide {TOKEN_FILE} ({e})") from None
        return tok

    def call(self, method: str, path: str, body: dict | None = None, token: bool = True, ok404: bool = False):
        req = urllib.request.Request(f"{self.addr}/v1/{path.lstrip('/')}", method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("X-Vault-Token", self.token)
        if self.namespace:
            req.add_header("X-Vault-Namespace", self.namespace)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            if ok404 and e.code == 404:
                return None
            try:
                errs = json.loads(e.read()).get("errors") or []
            except Exception:  # noqa
                errs = []
            raise KMSError(f"KMS {method} {path}: HTTP {e.code} {'; '.join(map(str, errs))[:300]}") from None
        except urllib.error.URLError as e:
            raise KMSError(f"KMS unreachable at {self.addr}: {e.reason}") from None

    # ------------------------------------------------------------------ token lifetime
    def keep_alive(self) -> None:
        """Renew a periodic token at most every 6 h (the setup issues 30-day periodic tokens)."""
        with self._lock:
            if time.time() - self._renewed_at < 6 * 3600:
                return
            info = self.call("GET", "auth/token/lookup-self")["data"]
            if info.get("renewable") and info.get("period"):
                self.call("POST", "auth/token/renew-self", {})
            self._renewed_at = time.time()

    # ------------------------------------------------------------------ transit: bundle signing
    def sign_ed25519(self, data: bytes, key: str = BUNDLE_KEY) -> tuple[bytes, str]:
        """-> (64-byte Ed25519 signature over `data`, key id "transit:<key>:v<N>")."""
        self.keep_alive()
        r = self.call("POST", f"{TRANSIT}/sign/{key}", {"input": base64.b64encode(data).decode()})
        sig = r["data"]["signature"]                       # "vault:v1:<base64>"
        _, ver, b64 = sig.split(":", 2)
        return base64.b64decode(b64), f"transit:{key}:{ver}"

    def ed25519_public_pem(self, key: str = BUNDLE_KEY) -> str:
        d = self.call("GET", f"{TRANSIT}/keys/{key}")["data"]
        latest = str(d["latest_version"])
        raw = base64.b64decode(d["keys"][latest]["public_key"])
        pub = ed25519.Ed25519PublicKey.from_public_bytes(raw)
        return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    # ------------------------------------------------------------------ pki: agent and server certificates
    def sign_client_csr(self, csr_pem: str, common_name: str, days: int) -> tuple[str, str]:
        """-> (certificate PEM, serial as lowercase hex without separators)."""
        self.keep_alive()
        r = self.call("POST", f"{PKI}/sign/{AGENT_ROLE}", {"csr": csr_pem, "common_name": common_name,
                                                           "ttl": f"{days * 24}h", "format": "pem"})["data"]
        return r["certificate"] + "\n", format(int(r["serial_number"].replace(":", ""), 16), "x")

    def sign_server_csr(self, csr_pem: str, hostnames: list[str], days: int) -> str:
        self.keep_alive()
        names = [h for h in hostnames if not h.replace(".", "").isdigit()]
        ips = [h for h in hostnames if h.replace(".", "").isdigit()]
        r = self.call("POST", f"{PKI}/sign/{SERVER_ROLE}", {
            "csr": csr_pem, "common_name": hostnames[0], "alt_names": ",".join(names), "ip_sans": ",".join(ips),
            "ttl": f"{days * 24}h", "format": "pem"})["data"]
        return r["certificate"] + "\n"

    def ca_pem(self) -> str:
        r = self.call("GET", f"{PKI}/cert/ca", token=False)
        return r["data"]["certificate"].strip() + "\n"


_client: Client | None = None


def client() -> Client:
    global _client
    if _client is None:
        _client = Client()
    return _client
