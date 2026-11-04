# PDP Console desktop wrapper

An Electron wrapper around the analyst console, so operators can run it as a native app on Windows, macOS and
Linux instead of a browser tab. It loads the console served by the gateway over TLS and pins the server CA
certificate, so it trusts only your on-premises server (stricter than clicking through a browser warning).

## Develop / run

```
cd desktop
npm install
PDP_SERVER_URL=https://pdp.example.com PDP_CA_FINGERPRINT=<ca_sha256> npm start
```

Point it at the gateway's console port (443 by default; 8443 is the agent mTLS port and refuses the console). Both
are remappable (`PDP_CONSOLE_PORT`, `PDP_AGENT_PORT`): the L40S dev host publishes the console on 8443 and the agent
API on 9443, so there the URL is `https://localhost:8443`.
First run opens the settings page if the server is unreachable or the certificate is not trusted. Set the gateway
URL and, recommended, the CA fingerprint.

### Certificate pin

Accepted pin formats:

- **hex sha256 of the CA certificate DER** -- case-insensitive, `:` separators allowed, so the output of
  `openssl x509 -in ca.pem -noout -fingerprint -sha256` can be pasted as is. The console shows this value as the
  *CA fingerprint* (`ca_sha256`) when an admin creates an enrolment token. To compute it yourself:
  `curl -sk https://pdp.example.com/dl/ca.pem -o ca.pem && openssl x509 -in ca.pem -outform der | sha256sum`
  (verify it out of band; `-k` is fine because you compare the fingerprint).
- **`sha256/<base64>` SPKI pin** -- base64 sha256 of the SubjectPublicKeyInfo DER of the CA (or of the server
  certificate): `openssl x509 -in ca.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`.

How the pin is checked (`pin.js`): the connection is accepted if the server (leaf) certificate itself matches the
pin, or if it chains by signature to a certificate matching the pin and is valid for the hostname and current time
-- even though the self-signed CA is not in the OS trust store. The gateway presents only its leaf, so the wrapper
fetches `<server>/dl/ca.pem` and uses it only if it matches the pin (a CA certificate is public; possessing a copy
proves nothing, which is why the leaf's signature is verified against it). Anything else is rejected. With no pin
configured, only `localhost` / `127.0.0.1` are trusted (first-run convenience).

## Package installers

Release installers are built by CI, one native runner per OS (`.github/workflows/release.yml`, job `desktop`), on a
`vX.Y.Z` tag or by hand (*Actions -> release -> Run workflow*). Each runner runs `npm ci`, the CA-pin self-test
(`npm test`, `scripts/pin-selftest.js`), sets the version from the tag, and runs `electron-builder --publish never`:

| runner | artifacts | signing |
|---|---|---|
| `macos-latest` | `pdp-console-<v>-mac-{x64,arm64}.dmg`, `pdp-console-<v>-mac-{x64,arm64}.zip` | Developer ID + hardened runtime (`resources/entitlements.mac.plist`), then notarized by the `afterSign` hook `scripts/notarize.js` |
| `windows-latest` | `pdp-console-<v>-win-x64-setup.exe` (NSIS, per-user, install dir selectable), `pdp-console-<v>-win-x64.zip` | Authenticode |
| `ubuntu-latest` | `pdp-console-<v>-linux-x86_64.AppImage`, `pdp-console_<v>_amd64.deb` | none (integrity via `SHA256SUMS`, optionally GPG-signed) |

The `release` job collects every artifact into one `SHA256SUMS` (+ `SHA256SUMS.asc` when `GPG_PRIVATE_KEY` is set)
and, on tags, opens a **draft** GitHub release. `publish` is `null`: electron-builder never uploads anything itself.

**Signing secrets** (repository -> Settings -> Secrets and variables -> Actions). Each one is optional; when it is
missing the job builds an *unsigned* artifact and prints a warning instead of failing:

| secret | used for |
|---|---|
| `CSC_LINK`, `CSC_KEY_PASSWORD` | macOS "Developer ID Application" certificate as a base64 `.p12` and its password |
| `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID` | notarization (notarytool via `@electron/notarize`); only runs when the app was signed and all three are set |
| `WIN_CSC_LINK`, `WIN_CSC_KEY_PASSWORD` | Windows Authenticode certificate as a base64 `.pfx` and its password (an EV/HSM certificate needs a custom `win.sign` hook instead) |
| `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE` | detached signature of `SHA256SUMS` |

`base64 -i cert.p12 | pbcopy` (macOS) or `base64 -w0 cert.pfx` (Linux) produces the value. When a certificate is
present the job also verifies the result (`codesign --verify --deep --strict`, `xcrun stapler validate` and
`spctl --assess` after notarization; `Get-AuthenticodeSignature` on Windows). Unsigned macOS builds need right-click
-> Open (or `xattr -dr com.apple.quarantine "/Applications/PDP Console.app"`); unsigned Windows installers trigger
SmartScreen.

**Verify a download:** `sha256sum -c SHA256SUMS --ignore-missing` (and `gpg --verify SHA256SUMS.asc SHA256SUMS`).

Local builds (unsigned; `dist/` is git-ignored):

```
npm run dist:linux  # AppImage + deb; on any Linux host, e.g. in a container:
                    #   docker run --rm -v "$PWD:/project" -w /project electronuserland/builder:20 \
                    #     sh -c 'npm ci && npm run dist:linux'
npm run dist:mac    # on a Mac (signs if a Developer ID identity is in the keychain or CSC_LINK is set)
npm run dist:win    # on Windows
```

Icons live in `resources/` (`icon.icns`, `icon.ico`, `icons/<n>x<n>.png`), generated by `resources/make-icons.py`
(a plain shield with a small graph; rerun it to change them). The Linux `.deb` installs to `/opt/PDP Console/`
with a `/usr/bin/pdp-console` link and declares its runtime libraries (including `libasound2`, which
electron-builder's default list omits and without which the app does not start on a minimal Ubuntu 24.04).

### Checking the CA pin against a running gateway (Linux, headless)

How the Linux build was checked against the console (2026-11-04): install the `.deb` in a throwaway
`ubuntu:24.04` container on the host network, add `xvfb`, start the app with
`PDP_SERVER_URL=https://localhost:8443 PDP_CA_FINGERPRINT=<fp> xvfb-run -a pdp-console --no-sandbox --remote-debugging-port=19222`,
and read the loaded page from `http://127.0.0.1:19222/json/list`:

| case | result |
|---|---|
| correct pin: hex, `openssl -fingerprint` colon form, `sha256/<base64>` SPKI | console loads (`https://localhost:8443/#/login`) |
| wrong pin | settings page; log `rejecting certificate for localhost: no certificate matches pin` |
| correct pin, but `https://127.0.0.1:8443` (not in the certificate's SAN) | settings page; `leaf not valid for host/time` |
| the AppImage (`APPIMAGE_EXTRACT_AND_RUN=1`), correct / wrong pin | console / settings page |

Every other HTTPS host is rejected too while a pin is set (seen in the log for Chromium's own background requests,
e.g. `redirector.gvt1.com`), so the console must not load resources from third-party origins.

The wrapper holds no credentials and no detection logic: it is a thin, cert-pinned shell over the same web
console the gateway serves. All detection runs on the endpoints and the server.
