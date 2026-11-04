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

Point it at the gateway's console port (443 by default; 8443 is the agent mTLS port and refuses the console).
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

```
npm run dist        # current platform (dmg/nsis/AppImage)
npm run dist:all    # mac + windows + linux (needs the platform toolchains / CI)
```

The wrapper holds no credentials and no detection logic: it is a thin, cert-pinned shell over the same web
console the gateway serves. All detection runs on the endpoints and the server.
