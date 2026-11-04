"""PKI: internal CA for agent client certificates, TLS server certificate, Ed25519 bundle-signing key.

All keys live under PDP_PKI_DIR (a Docker volume), created on first start. Private keys never leave it.
"""
from __future__ import annotations

import datetime as dt
import os
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PKI_DIR = os.environ.get("PDP_PKI_DIR", "/pki")


def _write(path: str, data: bytes, mode: int = 0o600) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)


def _name(cn: str, org: str = "PDP") -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def ensure_pki(server_hostnames: list[str]) -> None:
    ca_key_p, ca_crt_p = os.path.join(PKI_DIR, "ca.key"), os.path.join(PKI_DIR, "ca.pem")
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
    sk = os.path.join(PKI_DIR, "bundle_signing.key")
    if not os.path.exists(sk):
        key = ed25519.Ed25519PrivateKey.generate()
        _write(sk, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        _write(os.path.join(PKI_DIR, "bundle_signing.pub"), key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo), 0o644)


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
    key = serialization.load_pem_private_key(open(os.path.join(PKI_DIR, "ca.key"), "rb").read(), password=None)
    cert = x509.load_pem_x509_certificate(open(os.path.join(PKI_DIR, "ca.pem"), "rb").read())
    return key, cert


def issue_server_cert(hostnames: list[str]) -> None:
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
    ca_key, ca_cert = _ca()
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    if not csr.is_signature_valid:
        raise ValueError("invalid CSR signature")
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
    return open(os.path.join(PKI_DIR, "bundle_signing.key"), "rb").read()


def signing_public_pem() -> str:
    return open(os.path.join(PKI_DIR, "bundle_signing.pub")).read()


def new_id() -> str:
    return str(uuid.uuid4())
