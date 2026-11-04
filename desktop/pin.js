// Certificate pin checks for the desktop wrapper. Pure functions (no Electron), so they can be tested with plain Node.
// Electron hands the verify proc each certificate as PEM text (`Certificate.data`), issuers via `issuerCert`.
//
// Accepted pin formats (settings "CA fingerprint"):
//   - hex sha256 of a certificate's DER, any case, ':' separators allowed (the `openssl x509 -fingerprint -sha256`
//     format, with or without its "sha256 Fingerprint=" prefix). This is what the console shows as ca_sha256.
//   - sha256/<base64> of a certificate's SubjectPublicKeyInfo DER (HPKP-style SPKI pin).
// The pin may name the server (leaf) certificate itself or the CA that issued it. A CA cert is public, so its mere
// presence in the chain proves nothing: when the pin names a CA, the leaf must chain to it by signature and be valid
// for the hostname. The gateway sends only its leaf, so the CA can be supplied separately (`caPem`, e.g. fetched from
// /dl/ca.pem); it is used only if it matches the pin itself.
const crypto = require("crypto");
const net = require("net");

function normalisePin(pin) {
  const p = String(pin || "").trim();
  if (!p) return null;
  if (/^sha256\//i.test(p)) return { kind: "spki", value: "sha256/" + p.slice(7) };
  const hex = p.replace(/^sha-?256\s*fingerprint\s*=\s*/i, "").replace(/[:\s]/g, "").toLowerCase();
  if (/^[0-9a-f]{64}$/.test(hex)) return { kind: "der", value: hex };
  return { kind: "invalid", value: p };
}

function pemToDer(pem) {
  const m = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(String(pem));
  if (!m) throw new Error("not a PEM certificate");
  return Buffer.from(m[1].replace(/\s+/g, ""), "base64");
}

const toX509 = (c) => (c instanceof crypto.X509Certificate ? c : new crypto.X509Certificate(Buffer.isBuffer(c) ? c : pemToDer(c)));

// { der: hex sha256 of the certificate DER, spki: "sha256/<base64>" of its SPKI DER }
function certFingerprints(cert) {
  const x = toX509(cert);
  return {
    der: crypto.createHash("sha256").update(x.raw).digest("hex"),
    spki: "sha256/" + crypto.createHash("sha256").update(x.publicKey.export({ type: "spki", format: "der" })).digest("base64"),
  };
}

function certMatchesPin(cert, pin) {
  const p = typeof pin === "string" ? normalisePin(pin) : pin;
  if (!p || p.kind === "invalid") return false;
  const f = certFingerprints(cert);
  return p.kind === "der" ? f.der === p.value : f.spki === p.value;
}

const issuedBy = (child, parent) => child.checkIssued(parent) && child.verify(parent.publicKey);
function leafValidFor(leaf, hostname, now) {
  const t = now ?? Date.now();
  if (t < Date.parse(leaf.validFrom) || t > Date.parse(leaf.validTo)) return false;
  if (!hostname) return true;
  return net.isIP(hostname) ? leaf.checkIP(hostname) !== undefined : leaf.checkHost(hostname) !== undefined;
}

// pems: the presented chain, leaf first. Returns { ok, reason }.
function verifyPinned(pems, pin, { hostname, caPem, now } = {}) {
  const p = normalisePin(pin);
  if (!p || p.kind === "invalid") return { ok: false, reason: "invalid pin format" };
  let chain;
  try { chain = pems.map(toX509); } catch (e) { return { ok: false, reason: `unparseable certificate: ${e.message}` }; }
  if (!chain.length) return { ok: false, reason: "no certificate" };
  if (certMatchesPin(chain[0], p)) return { ok: true, reason: "leaf matches pin" };
  const leafOk = leafValidFor(chain[0], hostname, now);
  // pin names a CA presented in the chain: every link below it must be signed by its parent
  for (let i = 1; i < chain.length; i++) {
    if (!issuedBy(chain[i - 1], chain[i])) break;
    if (certMatchesPin(chain[i], p)) return leafOk ? { ok: true, reason: `issuer #${i} matches pin` } : { ok: false, reason: "leaf not valid for host/time" };
  }
  // pin names a CA not presented (the gateway sends only its leaf): use the separately obtained CA if it is the pinned one
  if (caPem) {
    let ca; try { ca = toX509(caPem); } catch { return { ok: false, reason: "unparseable CA" }; }
    if (!certMatchesPin(ca, p)) return { ok: false, reason: "supplied CA does not match pin" };
    let i = 0; while (i + 1 < chain.length && issuedBy(chain[i], chain[i + 1])) i++;
    if (!issuedBy(chain[i], ca)) return { ok: false, reason: "chain not issued by pinned CA" };
    return leafOk ? { ok: true, reason: "chain issued by pinned CA" } : { ok: false, reason: "leaf not valid for host/time" };
  }
  return { ok: false, reason: "no certificate matches pin" };
}

// PEMs of an Electron Certificate and its issuers (stops at a self-referencing self-signed root)
function electronChainPems(cert) {
  const out = [];
  for (let c = cert, i = 0; c && i < 16; c = c.issuerCert, i++) {
    if (!c.data || out.includes(c.data)) break;
    out.push(c.data);
  }
  return out;
}

module.exports = { normalisePin, pemToDer, certFingerprints, certMatchesPin, verifyPinned, electronChainPems };
