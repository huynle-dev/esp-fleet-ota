# Trusted firmware signing keys (public)

The single source of the public keys devices built with esp-fleet-ota trust. Firmware and the browser flashing
page embed these at build time; nothing fetches them at runtime.

| File | key_id | Signature format | Fingerprint (SHA-256 of the DER SubjectPublicKeyInfo) |
|---|---|---|---|
| `esp-fleet-ota-v1.pem` | `esp-fleet-ota`, version 1 | `vault:v1:<base64 DER>` (OpenBao transit) | `c47d4ef66aabd9cabc15d27b7d7437bb3c5eadb9ae1c17fe091c28125d1b661e` |

A break-glass key (bare base64 DER signatures) will be added as its own file and key_id.

Check a file: `openssl pkey -pubin -in <file> -outform DER | shasum -a 256`.
