// Self-test for pin.js (no Electron): mints a throwaway CA + server certificate with the openssl CLI, then checks the
// accept/reject decisions the verify proc relies on. Run: `npm test` (CI runs it on every desktop build runner).
// Skips (exit 0 with a warning) when no openssl binary is on PATH.
const { execFileSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { verifyPinned, certFingerprints, normalisePin } = require("../pin");

try { execFileSync("openssl", ["version"], { stdio: "ignore" }); } catch {
  console.warn("pin self-test skipped: openssl not found on PATH");
  process.exit(0);
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pdp-pin-"));
const f = (n) => path.join(dir, n);
const ossl = (...a) => execFileSync("openssl", a, { stdio: ["ignore", "ignore", "pipe"] });

function mkCa(name) {
  ossl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
    "-subj", `/O=PDP test/CN=${name}`, "-keyout", f(`${name}.key`), "-out", f(`${name}.pem`),
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign");
  return fs.readFileSync(f(`${name}.pem`), "utf8");
}
function mkLeaf(name, ca, san) {
  ossl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", `/O=PDP test/CN=${name}`,
    "-keyout", f(`${name}.key`), "-out", f(`${name}.csr`));
  fs.writeFileSync(f(`${name}.ext`), `subjectAltName=${san}\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n`);
  ossl("x509", "-req", "-in", f(`${name}.csr`), "-CA", f(`${ca}.pem`), "-CAkey", f(`${ca}.key`), "-CAcreateserial",
    "-days", "1", "-extfile", f(`${name}.ext`), "-out", f(`${name}.pem`));
  return fs.readFileSync(f(`${name}.pem`), "utf8");
}

const ca = mkCa("ca"), rogueCa = mkCa("rogue");
const leaf = mkLeaf("leaf", "ca", "DNS:localhost,DNS:pdp.local");
const rogueLeaf = mkLeaf("rogueleaf", "rogue", "DNS:localhost");
const fp = certFingerprints(ca);
const colonUpper = fp.der.toUpperCase().match(/../g).join(":");

let fails = 0;
function check(cond, msg) { console.log((cond ? "PASS " : "FAIL ") + msg); fails += cond ? 0 : 1; }
const ok = (pems, pin, o) => verifyPinned(pems, pin, o).ok;

check(normalisePin(`sha256 Fingerprint=${colonUpper}`).value === fp.der, "openssl -fingerprint output normalises to the hex pin");
check(ok([leaf], fp.der, { hostname: "localhost", caPem: ca }), "leaf only + fetched CA matching the DER pin -> accepted");
check(ok([leaf], colonUpper, { hostname: "pdp.local", caPem: ca }), "upper-case colon pin accepted, second SAN name");
check(ok([leaf], fp.spki, { hostname: "localhost", caPem: ca }), "SPKI pin of the CA accepted");
check(ok([leaf, ca], fp.der, { hostname: "localhost" }), "CA presented in the chain -> accepted without a fetch");
check(ok([leaf], certFingerprints(leaf).der, { hostname: "anything" }), "pin of the leaf itself accepted");
check(!ok([leaf], fp.der, { hostname: "localhost" }), "CA pin but CA neither presented nor fetched -> rejected");
check(!ok([leaf], fp.der, { hostname: "127.0.0.1", caPem: ca }), "hostname/IP not in the SAN -> rejected");
check(!ok([leaf], fp.der, { hostname: "evil.example", caPem: ca }), "other hostname -> rejected");
check(!ok([rogueLeaf], fp.der, { hostname: "localhost", caPem: ca }), "leaf from another CA -> rejected");
check(!ok([rogueLeaf, ca], fp.der, { hostname: "localhost" }), "pinned CA appended to a foreign chain -> rejected");
check(!ok([rogueLeaf], fp.der, { hostname: "localhost", caPem: rogueCa }), "fetched CA that does not match the pin -> rejected");
check(!ok([leaf], "not-a-pin", { hostname: "localhost", caPem: ca }), "invalid pin -> rejected");
check(!ok([leaf], fp.der, { hostname: "localhost", caPem: ca, now: Date.now() + 5 * 86400e3 }), "expired leaf -> rejected");

fs.rmSync(dir, { recursive: true, force: true });
console.log("FAILURES:", fails);
process.exit(fails ? 1 : 0);
