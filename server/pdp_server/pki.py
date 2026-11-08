"""PKI: internal CA for agent client certificates, TLS server certificate, Ed25519 bundle-signing key.

Two modes (pdp_server.kms):
  * PDP_KMS=transit (production): the CA key and the bundle-signing key live in a Vault-compatible KMS; this module
    asks it to sign CSRs and bundle manifests. PDP_PKI_DIR holds only public material (ca.pem, bundle_signing.pub),
    the gateway's TLS key and the session secret.
  * PDP_KMS=file (development, the default for compatibility): all keys under PDP_PKI_DIR (a Docker volume),
    created on first start.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import kms

PKI_DIR = os.environ.get("PDP_PKI_DIR", "/pki")
# Private material (file mode: the CA key and the bundle-signing key; always: the console session secret) lives in
# its own directory / volume that only the api and the workers mount - the gateway mounts PKI_DIR for its TLS key
# and must never see the keys that issue agent certificates or sign models (security review F9).
PRIVATE_DIR = os.environ.get("PDP_PKI_PRIVATE_DIR", os.path.join(PKI_DIR, "private"))
PRIVATE_FILES = ("ca.key", "bundle_signing.key", "session.secret")
log = logging.getLogger("pdp.pki")


def private_path(name: str) -> str:
    return os.path.join(PRIVATE_DIR, name)


def migrate_private() -> list[str]:
    """Move private files that older versions kept directly in PKI_DIR into PRIVATE_DIR (idempotent; the two may be
    different volumes, so copy then remove). Returns the files moved."""
    import shutil
    moved = []
    os.makedirs(PRIVATE_DIR, mode=0o700, exist_ok=True)
    for name in PRIVATE_FILES:
        old, new = os.path.join(PKI_DIR, name), private_path(name)
        if os.path.exists(old) and not os.path.exists(new):
            shutil.copy2(old, new)
            os.chmod(new, 0o600)
            os.remove(old)
            moved.append(name)
            log.warning("moved %s into %s (the gateway mounts %s and must not hold private keys)", name, PRIVATE_DIR, PKI_DIR)
    return moved


def _write(path: str, data: bytes, mode: int = 0o600) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)


def _name(cn: str, org: str = "PDP") -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def ensure_pki(server_hostnames: list[str]) -> None:
    migrate_private()
    if kms.enabled():
        return _ensure_pki_kms(server_hostnames)
    ca_key_p, ca_crt_p = private_path("ca.key"), os.path.join(PKI_DIR, "ca.pem")
    if not os.path.exists(ca_key_p):
        key = ec.generate_private_key(ec.SECP384R1())
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(_name("PDP Root CA")).issuer_name(_name("PDP Root CA"))
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                             key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
                .sign(key, hashes.SHA384()))
        _write(ca_key_p, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        _write(ca_crt_p, cert.public_bytes(serialization.Encoding.PEM), 0o644)
    if not os.path.exists(os.path.join(PKI_DIR, "server.key")) or _hostnames_changed(server_hostnames):
        issue_server_cert(server_hostnames)
    elif not os.path.exists(os.path.join(PKI_DIR, "server-chain.pem")):
        write_chain()
    sk = private_path("bundle_signing.key")
    if not os.path.exists(sk):
        key = ed25519.Ed25519PrivateKey.generate()
        _write(sk, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        _write(os.path.join(PKI_DIR, "bundle_signing.pub"), key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo), 0o644)


def _ensure_pki_kms(server_hostnames: list[str]) -> None:
    """Public material from the KMS; the server certificate is issued by the KMS CA from a locally generated key."""
    k = kms.client()
    ca_crt_p, pub_p = os.path.join(PKI_DIR, "ca.pem"), os.path.join(PKI_DIR, "bundle_signing.pub")
    ca = k.ca_pem()
    if not os.path.exists(ca_crt_p) or _cert_der(open(ca_crt_p).read()) != _cert_der(ca):
        _write(ca_crt_p, ca.encode(), 0o644)
    pub = k.ed25519_public_pem()
    if not os.path.exists(pub_p) or open(pub_p).read().strip() != pub.strip():
        _write(pub_p, pub.encode(), 0o644)
    for leftover in ("ca.key", "bundle_signing.key"):
        if os.path.exists(private_path(leftover)):
            log.warning("PDP_KMS=transit but %s is still in %s: run tools/kms_setup.py --remove-local-keys", leftover, PRIVATE_DIR)
    if not os.path.exists(os.path.join(PKI_DIR, "server.key")) or _hostnames_changed(server_hostnames) or not _issued_by_ca("server.pem"):
        issue_server_cert(server_hostnames)
    elif not os.path.exists(os.path.join(PKI_DIR, "server-chain.pem")):
        write_chain()


def _cert_der(pem: str) -> bytes:
    return x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)


def _issued_by_ca(name: str) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(open(os.path.join(PKI_DIR, name), "rb").read())
        ca = x509.load_pem_x509_certificate(open(os.path.join(PKI_DIR, "ca.pem"), "rb").read())
        cert.verify_directly_issued_by(ca)
        return True
    except Exception:  # noqa
        return False


def _hostnames_changed(hostnames: list[str]) -> bool:
    """Re-issue the server certificate when PDP_HOSTNAMES gains names the current certificate does not cover."""
    try:
        cert = x509.load_pem_x509_certificate(open(os.path.join(PKI_DIR, "server.pem"), "rb").read())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        have = {str(n.value) for n in san}
    except Exception:  # noqa
        return True
    return not set(hostnames) <= have


def _ca():
    key = serialization.load_pem_private_key(open(private_path("ca.key"), "rb").read(), password=None)
    cert = x509.load_pem_x509_certificate(open(os.path.join(PKI_DIR, "ca.pem"), "rb").read())
    return key, cert


def issue_server_cert(hostnames: list[str]) -> None:
    if kms.enabled():
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (x509.CertificateSigningRequestBuilder().subject_name(_name(hostnames[0])).sign(key, hashes.SHA256()))
        pem = kms.client().sign_server_csr(csr.public_bytes(serialization.Encoding.PEM).decode(), hostnames, 825)
        _write(os.path.join(PKI_DIR, "server.key"), key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        _write(os.path.join(PKI_DIR, "server.pem"), pem.encode(), 0o644)
        write_chain()
        return
    ca_key, ca_cert = _ca()
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    sans = [x509.DNSName(h) for h in hostnames if not h.replace(".", "").isdigit()]
    import ipaddress
    sans += [x509.IPAddress(ipaddress.ip_address(h)) for h in hostnames if h.replace(".", "").isdigit()]
    cert = (x509.CertificateBuilder().subject_name(_name(hostnames[0])).issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    _write(os.path.join(PKI_DIR, "server.key"), key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    _write(os.path.join(PKI_DIR, "server.pem"), cert.public_bytes(serialization.Encoding.PEM), 0o644)
    write_chain()


def write_chain() -> None:
    """server-chain.pem = leaf + CA: the gateway serves the full chain, so clients that pin the CA (desktop app,
    agents) find it in the handshake."""
    leaf = open(os.path.join(PKI_DIR, "server.pem"), "rb").read()
    ca = open(os.path.join(PKI_DIR, "ca.pem"), "rb").read()
    _write(os.path.join(PKI_DIR, "server-chain.pem"), leaf + ca, 0o644)


def sign_csr(csr_pem: str, endpoint_id: str, days: int = 730) -> tuple[str, str]:
    """-> (certificate PEM, serial). The CN is forced to the endpoint id; whatever the CSR says is ignored."""
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    if not csr.is_signature_valid:
        raise ValueError("invalid CSR signature")
    if kms.enabled():
        return kms.client().sign_client_csr(csr_pem, endpoint_id, days)
    ca_key, ca_cert = _ca()
    now = dt.datetime.now(dt.timezone.utc)
    serial = x509.random_serial_number()
    cert = (x509.CertificateBuilder().subject_name(_name(endpoint_id, "PDP endpoints")).issuer_name(ca_cert.subject)
            .public_key(csr.public_key()).serial_number(serial)
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode(), format(serial, "x")


def ca_pem() -> str:
    return open(os.path.join(PKI_DIR, "ca.pem")).read()


def ca_sha256() -> str:
    """Hex sha256 of the CA certificate's DER encoding (what agents and the desktop app pin)."""
    import hashlib
    cert = x509.load_pem_x509_certificate(open(os.path.join(PKI_DIR, "ca.pem"), "rb").read())
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def signing_private_pem() -> bytes:
    """File mode only; with a KMS the private key is not available to the platform (use sign_bundle)."""
    if kms.enabled():
        raise RuntimeError("the bundle-signing key is in the KMS; use pki.sign_bundle()")
    return open(private_path("bundle_signing.key"), "rb").read()


def sign_bundle(bundle_dir: str) -> str:
    """Sign a bundle's manifest.json into signature.json ({alg, sig, kid}); -> key id.

    Agents verify the Ed25519 signature with the public key from their enrolment (pdp_engine.bundle.verify_signature);
    the key id records which key signed the bundle (KMS key version, or the file key's fingerprint)."""
    import hashlib
    data = open(os.path.join(bundle_dir, "manifest.json"), "rb").read()
    if kms.enabled():
        sig, kid = kms.client().sign_ed25519(data)
    else:
        key = serialization.load_pem_private_key(signing_private_pem(), password=None)
        sig = key.sign(data)
        kid = "file:" + hashlib.sha256(signing_public_pem().encode()).hexdigest()[:16]
    # verify before publishing: a wrong key or a KMS mix-up must never reach agents
    pub = serialization.load_pem_public_key(signing_public_pem().encode())
    pub.verify(sig, data)
    with open(os.path.join(bundle_dir, "signature.json"), "w") as f:
        json.dump({"alg": "Ed25519", "sig": sig.hex(), "kid": kid}, f)
    return kid


def signing_public_pem() -> str:
    return open(os.path.join(PKI_DIR, "bundle_signing.pub")).read()


def new_id() -> str:
    return str(uuid.uuid4())
