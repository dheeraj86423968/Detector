"""Set up the KMS for PDP and move the platform's private keys into it (idempotent).

  python -m pdp_server.tools.kms_setup --secrets /kms-secrets [--admin-token-file F] [--remove-local-keys]

Bundled OpenBao (compose profile "kms"): on first run the KMS is initialised with one unseal key share, written to
<secrets>/unseal/key (mounted only into the kms container, which unseals itself on start); the initial root token is
used for this setup only and revoked at the end. External Vault / OpenBao: pass an admin token with
--admin-token-file; nothing is initialised or unsealed.

Steps:
 1. enable the transit and pki engines and a file audit device (every signing request is logged)
 2. bundle-signing key `pdp-bundle-signing` (ed25519, non-exportable): imported from /pki/bundle_signing.key when it
    exists - enrolled agents keep trusting it - otherwise generated inside the KMS
 3. agent CA: imported from /pki/ca.key + ca.pem when they exist - enrolled agents keep their pinned CA fingerprint
    and certificates - otherwise a new root CA generated inside the KMS
 4. roles pdp-agent (client certificates, CN forced by the platform) and pdp-server (gateway TLS)
 5. policy pdp-signer (sign only) and a 30-day periodic token for the platform services, written to
    <secrets>/token/token (readable by the service uid 10001)
 6. verification: a signature by the KMS verifies with the local public key; a test CSR gets a certificate that
    chains to ca.pem; the service token is refused key export / import / CA reads of private material
 7. --remove-local-keys: moves /pki/ca.key and /pki/bundle_signing.key to <secrets>/backup/ (root-only; take it
    offline) once step 6 passed
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import secrets
import shutil
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding
from cryptography.x509.oid import NameOID

from pdp_server import kms

PKI_DIR = os.environ.get("PDP_PKI_DIR", "/pki")
SERVICE_UID = 10001

SIGNER_POLICY = f"""
# PDP platform services: sign bundle manifests and certificate requests; nothing else.
path "{kms.TRANSIT}/sign/{kms.BUNDLE_KEY}" {{ capabilities = ["update"] }}
path "{kms.TRANSIT}/keys/{kms.BUNDLE_KEY}" {{ capabilities = ["read"] }}
path "{kms.PKI}/sign/{kms.AGENT_ROLE}"     {{ capabilities = ["update"] }}
path "{kms.PKI}/sign/{kms.SERVER_ROLE}"    {{ capabilities = ["update"] }}
path "{kms.PKI}/cert/ca"                   {{ capabilities = ["read"] }}
"""


def log(m: str) -> None:
    print(time.strftime("%H:%M:%S"), m, flush=True)


def _write(path: str, data: str, mode: int, uid: int | None = None) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(data)
    os.chmod(path, mode)
    if uid is not None:
        os.chown(path, uid, -1)


def init_and_unseal(k: kms.Client, secrets_dir: str) -> str | None:
    """Bundled KMS: initialise on first run, unseal; -> root token if this run initialised the KMS."""
    root = None
    st = k.call("GET", "sys/init", token=False)
    key_file = os.path.join(secrets_dir, "unseal", "key")
    if not st["initialized"]:
        r = k.call("PUT", "sys/init", {"secret_shares": 1, "secret_threshold": 1}, token=False)
        _write(key_file, (r.get("keys_base64") or r["keys"])[0], 0o600)
        root = r["root_token"]
        _write(os.path.join(secrets_dir, "root-token"), root + "\n", 0o600)   # until revoked at the end of the run
        log(f"initialised the KMS; unseal key written to {key_file}")
    if k.call("GET", "sys/seal-status", token=False)["sealed"]:
        if not os.path.exists(key_file):
            raise SystemExit(f"the KMS is sealed and {key_file} does not exist")
        k.call("PUT", "sys/unseal", {"key": open(key_file).read().strip()}, token=False)
        log("unsealed the KMS")
    return root


def ensure_engines(k: kms.Client) -> None:
    mounts = k.call("GET", "sys/mounts")
    mounts = mounts.get("data", mounts)
    if f"{kms.TRANSIT}/" not in mounts:
        k.call("POST", f"sys/mounts/{kms.TRANSIT}", {"type": "transit"})
        log("enabled transit")
    if f"{kms.PKI}/" not in mounts:
        k.call("POST", f"sys/mounts/{kms.PKI}", {"type": "pki", "config": {"max_lease_ttl": "87600h"}})
        log("enabled pki")
    audits = k.call("GET", "sys/audit")
    audits = audits.get("data", audits)
    if not any(v.get("type") == "file" for v in audits.values() if isinstance(v, dict)):
        try:
            k.call("PUT", "sys/audit/file", {"type": "file", "options": {"file_path": "/openbao/logs/audit.log"}})
            log("enabled the file audit device (/openbao/logs/audit.log)")
        except kms.KMSError as e:     # an external KMS usually has its own audit configuration
            log(f"audit device not enabled ({e}); configure auditing on the KMS")


def ensure_bundle_key(k: kms.Client) -> str:
    if k.call("GET", f"{kms.TRANSIT}/keys/{kms.BUNDLE_KEY}", ok404=True):
        return "existing"
    local = os.path.join(PKI_DIR, "bundle_signing.key")
    if os.path.exists(local):
        key = serialization.load_pem_private_key(open(local, "rb").read(), password=None)
        target = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        wrap_pem = k.call("GET", f"{kms.TRANSIT}/wrapping_key")["data"]["public_key"]
        wrap = serialization.load_pem_public_key(wrap_pem.encode())
        aes = secrets.token_bytes(32)
        wrapped_aes = wrap.encrypt(aes, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        ct = base64.b64encode(wrapped_aes + aes_key_wrap_with_padding(aes, target)).decode()
        k.call("POST", f"{kms.TRANSIT}/keys/{kms.BUNDLE_KEY}/import",
               {"ciphertext": ct, "type": "ed25519", "hash_function": "SHA256", "exportable": False,
                "allow_plaintext_backup": False, "allow_rotation": True})
        return "imported"
    k.call("POST", f"{kms.TRANSIT}/keys/{kms.BUNDLE_KEY}", {"type": "ed25519", "exportable": False})
    return "generated"


def ensure_ca(k: kms.Client) -> str:
    try:
        r = k.call("GET", f"{kms.PKI}/cert/ca", token=False, ok404=True)
    except kms.KMSError as e:
        if "no default issuer" not in str(e):
            raise
        r = None
    if r and r.get("data", {}).get("certificate"):
        return "existing"
    key_p, crt_p = os.path.join(PKI_DIR, "ca.key"), os.path.join(PKI_DIR, "ca.pem")
    if os.path.exists(key_p) and os.path.exists(crt_p):
        k.call("POST", f"{kms.PKI}/config/ca", {"pem_bundle": open(key_p).read() + "\n" + open(crt_p).read()})
        return "imported"
    k.call("POST", f"{kms.PKI}/root/generate/internal", {
        "common_name": "PDP Root CA", "organization": "PDP", "key_type": "ec", "key_bits": 384,
        "ttl": "87600h", "max_path_length": 0})
    return "generated"


def ensure_roles(k: kms.Client) -> None:
    common = {"allow_any_name": True, "enforce_hostnames": False, "allow_subdomains": True, "allow_glob_domains": True,
              "use_csr_common_name": False, "use_csr_sans": False, "key_type": "any", "require_cn": True,
              "basic_constraints_valid_for_non_ca": True, "no_store": False, "allow_wildcard_certificates": False}
    k.call("POST", f"{kms.PKI}/roles/{kms.AGENT_ROLE}", {**common, "client_flag": True, "server_flag": False,
           "allow_ip_sans": False, "exclude_cn_from_sans": True, "organization": "PDP endpoints", "key_usage": ["DigitalSignature"],
           "max_ttl": f"{730 * 24}h"})
    k.call("POST", f"{kms.PKI}/roles/{kms.SERVER_ROLE}", {**common, "client_flag": False, "server_flag": True,
           "allow_ip_sans": True, "organization": "PDP", "key_usage": ["DigitalSignature", "KeyAgreement"],
           "max_ttl": f"{825 * 24}h"})


def service_token(k: kms.Client, secrets_dir: str, rotate: bool) -> str:
    path = os.path.join(secrets_dir, "token", "token")
    k.call("PUT", "sys/policies/acl/pdp-signer", {"policy": SIGNER_POLICY})
    if os.path.exists(path) and not rotate:
        tok = open(path).read().strip()
        try:
            kms.Client(k.addr, token=tok).call("GET", "auth/token/lookup-self")
            return tok
        except kms.KMSError:
            log("existing service token is no longer valid; issuing a new one")
    r = k.call("POST", "auth/token/create-orphan", {"policies": ["pdp-signer"], "period": "720h",
                                                     "display_name": "pdp-platform", "renewable": True})
    tok = r["auth"]["client_token"]
    _write(path, tok + "\n", 0o400, SERVICE_UID)
    os.chmod(os.path.dirname(path), 0o755)
    log(f"issued the platform service token ({path})")
    return tok


def verify(addr: str, token: str) -> None:
    svc = kms.Client(addr, token=token)
    data = b"pdp kms self-test " + secrets.token_bytes(16)
    sig, kid = svc.sign_ed25519(data)
    local_pub_p = os.path.join(PKI_DIR, "bundle_signing.pub")
    kms_pub = svc.ed25519_public_pem()
    if os.path.exists(local_pub_p) and open(local_pub_p).read().strip() != kms_pub.strip():
        raise SystemExit("the KMS bundle-signing key differs from /pki/bundle_signing.pub - enrolled agents would reject bundles")
    serialization.load_pem_public_key(kms_pub.encode()).verify(sig, data)
    log(f"bundle signing ok ({kid})")
    ca_pem = svc.ca_pem()
    local_ca = os.path.join(PKI_DIR, "ca.pem")
    if os.path.exists(local_ca):
        a = x509.load_pem_x509_certificate(open(local_ca, "rb").read())
        b = x509.load_pem_x509_certificate(ca_pem.encode())
        if a.public_bytes(serialization.Encoding.DER) != b.public_bytes(serialization.Encoding.DER):
            raise SystemExit("the KMS CA differs from /pki/ca.pem - enrolled agents would reject the gateway")
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attacker-chosen")])).sign(key, hashes.SHA256())
    pem, serial = svc.sign_client_csr(csr.public_bytes(serialization.Encoding.PEM).decode(), "kms-selftest", 1)
    cert = x509.load_pem_x509_certificate(pem.encode())
    cert.verify_directly_issued_by(x509.load_pem_x509_certificate(ca_pem.encode()))
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if cn != "kms-selftest":
        raise SystemExit(f"the pdp-agent role kept the CSR's common name ({cn})")
    if (cert.not_valid_after_utc - dt.datetime.now(dt.timezone.utc)).days > 2:
        raise SystemExit("the requested certificate lifetime was not applied")
    log(f"certificate signing ok (serial {serial}, CN forced)")
    for method, path, body in [("POST", f"{kms.TRANSIT}/export/signing-key/{kms.BUNDLE_KEY}", None),
                               ("GET", f"{kms.TRANSIT}/export/signing-key/{kms.BUNDLE_KEY}", None),
                               ("POST", f"{kms.TRANSIT}/keys/{kms.BUNDLE_KEY}/rotate", {}),
                               ("DELETE", f"{kms.TRANSIT}/keys/{kms.BUNDLE_KEY}", None),
                               ("POST", f"{kms.PKI}/root/generate/exported", {"common_name": "x"}),
                               ("POST", f"{kms.PKI}/issue/{kms.AGENT_ROLE}", {"common_name": "x"}),
                               ("GET", "sys/policies/acl/pdp-signer", None)]:
        try:
            svc.call(method, path, body)
        except kms.KMSError as e:
            if "HTTP 403" not in str(e) and "HTTP 405" not in str(e):
                raise SystemExit(f"unexpected answer to {method} {path}: {e}")
            continue
        raise SystemExit(f"the service token was allowed {method} {path}")
    log("service token is limited to signing (export, rotate, delete, issue, policy read refused)")


def remove_local_keys(secrets_dir: str) -> None:
    backup = os.path.join(secrets_dir, "backup", time.strftime("%Y%m%dT%H%M%S"))
    for name in ("ca.key", "bundle_signing.key"):
        p = os.path.join(PKI_DIR, name)
        if os.path.exists(p):
            os.makedirs(backup, mode=0o700, exist_ok=True)
            shutil.copy2(p, os.path.join(backup, name))
            os.chmod(os.path.join(backup, name), 0o400)
            with open(p, "r+b") as f:            # overwrite before unlinking (best effort on a CoW/volume fs)
                f.write(secrets.token_bytes(os.path.getsize(p)))
                f.flush()
                os.fsync(f.fileno())
            os.remove(p)
            log(f"moved {p} -> {backup}/{name}")
    if os.path.isdir(backup):
        log(f"take {backup} offline (it is the only copy outside the KMS) and delete it from this host")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--addr", default=kms.ADDR)
    ap.add_argument("--secrets", required=True, help="directory for the unseal key, service token and key backup")
    ap.add_argument("--admin-token-file", help="external KMS: admin token (no init/unseal, no root revocation)")
    ap.add_argument("--rotate-token", action="store_true", help="issue a new service token")
    ap.add_argument("--remove-local-keys", action="store_true")
    ap.add_argument("--keep-root-token", action="store_true", help="do not revoke a root token created by this run")
    a = ap.parse_args()
    os.makedirs(a.secrets, exist_ok=True)
    os.chmod(a.secrets, 0o711)
    k = kms.Client(a.addr, token="-")
    for _ in range(60):
        try:
            k.call("GET", "sys/health?standbyok=true&sealedcode=200&uninitcode=200", token=False)
            break
        except kms.KMSError:
            time.sleep(1)
    root = None
    tok_p = os.path.join(a.secrets, "token", "token")
    if not a.admin_token_file and not a.rotate_token and not os.path.exists(os.path.join(a.secrets, "root-token")) \
            and os.path.exists(tok_p) and k.call("GET", "sys/init", token=False)["initialized"]:
        init_and_unseal(k, a.secrets)          # unseal only
        verify(a.addr, open(tok_p).read().strip())
        if a.remove_local_keys:
            remove_local_keys(a.secrets)
        print(json.dumps({"ok": True, "kms": a.addr, "already_configured": True}))
        return
    if a.admin_token_file:
        k._token = open(a.admin_token_file).read().strip()
    else:
        root = init_and_unseal(k, a.secrets)
        if root is None:
            tok_p = os.path.join(a.secrets, "root-token")
            if not os.path.exists(tok_p):
                raise SystemExit("the KMS is already initialised: pass --admin-token-file (generate one with "
                                 "`bao operator generate-root` and the unseal key)")
            root = open(tok_p).read().strip()
        k._token = root
    ensure_engines(k)
    log(f"bundle-signing key: {ensure_bundle_key(k)}")
    log(f"agent CA: {ensure_ca(k)}")
    ensure_roles(k)
    tok = service_token(k, a.secrets, a.rotate_token)
    verify(a.addr, tok)
    if a.remove_local_keys:
        remove_local_keys(a.secrets)
    if root and not a.admin_token_file and not a.keep_root_token:
        k.call("POST", "auth/token/revoke-self", {})
        if os.path.exists(os.path.join(a.secrets, "root-token")):
            os.remove(os.path.join(a.secrets, "root-token"))
        log("revoked the root token (regenerate one with `bao operator generate-root` when needed)")
    elif root and a.keep_root_token:
        _write(os.path.join(a.secrets, "root-token"), root + "\n", 0o600)
    print(json.dumps({"ok": True, "kms": a.addr}))


if __name__ == "__main__":
    try:
        main()
    except kms.KMSError as e:
        sys.exit(f"KMS error: {e}")
