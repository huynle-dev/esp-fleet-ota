# Decisions

Design decisions of the library, with the alternatives that were considered. Where a choice was not forced, the
safest reversible option was taken.

## D1 Layout: pure logic in `src/`, ESP glue in `src/esp/`, host crypto in `src/host/`
Everything in `src/*.{h,cpp}` is plain C++17 with no Arduino headers and is tested natively (`pio test -e native`,
`test_build_src = yes`). `src/esp/` compiles only with `ESP_PLATFORM && ARDUINO`; `src/host/` only with
`FLEET_OTA_WITH_OPENSSL`. One `library.json` at the root; `libArchive: false` so the `verifyRollbackLater` override
always links. Alternative: separate core/glue libraries (rejected: two packages for one consumer).

## D2 Hand-written strict manifest parser instead of ArduinoJson
The parser runs on untrusted bytes before the signature check (D6), so it must be bounded and strict: no heap,
2048-byte limit, fixed field sizes, rejects unknown keys, duplicate keys, floats, negative numbers, booleans/null for
typed fields, nested values, escapes other than `\" \\ \/`, control characters and trailing data. ArduinoJson
allocates and silently accepts duplicates. Consequence: manifest JSON must stay flat ASCII.

## D3 Crypto behind interfaces; mbedTLS on device, OpenSSL for the host tests; known-answer test on the device
`ISha256` / `IEcdsaP256Verifier`. Device: mbedTLS 3.6 from the Arduino libs (`mbedtls_pk_parse_public_key`, curve
check secp256r1, `mbedtls_pk_verify`). Host: OpenSSL libcrypto (Homebrew `openssl@3`), because the mbedTLS sources are
not available locally (the Arduino libs ship headers + prebuilt archives only) and fetching/vendoring them was
avoided. Rejected: vendoring micro-ecc (a second crypto implementation in firmware), building mbedTLS for the host
(network fetch). Consequence: the mbedTLS adapter is compile-tested only; to cover it, `cryptoSelfCheck()` (SHA-256
"abc" vector + a P-256 known answer + three must-fail cases) runs before the first check on the device and FleetOta
fails closed (`crypto_self_check_failed`, D14). The native env needs `-I/-L` for OpenSSL (`platformio.ini`).

## D4 Trusted keys: a table of (key_id, N) -> public key; N = 0 for non-vault keys
`vault:vN:` selects the entry (key_id, N); a bare base64 signature selects (key_id, 0). Unknown key_id:
`unknown_key_id`; known key_id but no entry for that N: `key_version_mismatch`. So a bare signature is refused for a
key that only has vault entries, and `vault:v0:` is a format error. Several entries may share a key_id (rotation).

## D5 Signatures cover the exact manifest bytes; the .sig file is trimmed
Manifest bytes are hashed as received (no trimming, no normalisation); `.sig` leading/trailing whitespace and
newlines are ignored, inner whitespace is a format error. Base64 is strict (padding required, canonical tail bits).

## D6 Parse before verify
`key_id` is inside the manifest, so the (bounded, strict) parser runs first, then the signature is verified, then
the policy checks. Alternative: put key_id in the signature envelope (rejected: it would change the OpenBao transit `.sig` format).

## D7 Board: from the build flag `FOTA_BOARD`; a manifest board must match exactly
PlatformIO does not expose the board id as a macro. Empty `FOTA_BOARD` refuses manifests that name a board.

## D8 URL policy
https only, port 443 only (explicit `:443` allowed), no userinfo, no IPv6 literals, exact case-insensitive host
allow-list, no wildcards; applies to the manifest URL, the signature URL and the image URL. The ESP glue does not
follow redirects and uses HTTP/1.0 (no chunked encoding on the raw stream).

## D9 Anti-downgrade floor
Floor = highest `min_version` of images that passed their self-test, stored in NVS (`floor`), raised only after the
pass. A corrupt stored floor is ignored (version > running still holds) rather than blocking all updates forever;
`nextFloor` replaces it with the new min_version.

## D10 Download engine
Incremental `step()` (one read + write per call) so the device loop keeps running; one buffer of 2048 B (clamped to
256..4096) allocated at start and freed at the end; stall timeout 10 s (< 15 s watchdog), total 10 min; a declared
Content-Length that differs from the manifest size is refused before writing; extra bytes = `oversize`; early EOF =
`truncated`; `commit()` (esp_ota_end + set_boot_partition) only after the SHA-256 matched; every failure calls
`abort()`. `esp_ota_begin(..., OTA_WITH_SEQUENTIAL_WRITES, ...)` avoids one long erase.

## D11 Rollback handling
The library defines `verifyRollbackLater()` (strong, C linkage, returns true); opt-out
`-DFLEET_OTA_NO_ROLLBACK_OVERRIDE`. `markValid()` only after `selfTest()` returns pass; `rolled_back` is persisted and
the `pending` record removed before `markInvalidAndReboot()` (which does not return). Boot reconciliation: pending
verify -> self-test; a `pending` record whose version is not running -> `rolled_back|boot_failed`; a record whose
version is running but not pending (marked valid, power lost before recording) -> `ok`. A failed `markValid()` rolls
back (`boot_failed`).

## D12 `update()` re-checks and requires the exact version
`ota_update` fetches and verifies a fresh manifest and refuses unless its version equals the caller's
(`version_mismatch`). Refusals by an update are persisted (`refused|<reason>|<version>`); results of `ota_check` are
not (in-memory `last_check`), so periodic checks do not wear NVS.

## D13 Auto-check
Off by default; interval clamped to >= 1 h; the first check happens one interval after boot (not during boot);
installs only when `canUpdateNow()` agrees, otherwise waits for the next interval.

## D14 Fail closed on a broken crypto backend
See D3. The known-answer test runs once, lazily, at the first check (no boot delay).

## D15 Release tool
Python stdlib + `cryptography`. OpenBao via HTTP (default) or the `bao` CLI; address and token only from
`BAO_ADDR`/`BAO_TOKEN` (or `VAULT_*`), never arguments or files (the CLI backend refuses without an env token, since
`bao` would otherwise read `~/.vault-token`); https required except loopback; `--public-key/--key-version` verifies a
new signature before writing it. Manifests are compact JSON in a fixed key order without a trailing newline; the C++
test fixture is generated through the tool's encoder, so the device parser is tested on tool output.

## D16 Test keys
`test/fixtures/fota_test_vectors.h` holds TEST_ONLY_* keys/signatures generated by `tools/gen_test_vectors.py`;
controller and tool tests generate keys at run time; the example uses a TEST-ONLY placeholder. No private key is
committed.

## D17 Out of scope: Secure Boot v2, flash encryption, eFuse anti-rollback
Irreversible per device; decide per product. With Secure Boot v2, `esp_ota_end` also verifies the image signature.

## D18 Example partition table
`examples/minimal/partitions.csv` is a 4 MB flash table with two 1.875 MB slots, used for both C3 and S3.

## D19 Image layout lives in the release tool only
Manifest `<base>/<product>/<chip>/<channel>/manifest.json` (+ `.sig`), image `<base>/<product>/<version>/<chip>/
firmware.bin`. The device does not derive the image path; it takes the signed manifest's `url` (https, allow-listed
host). `fota_release.py manifest` derives it from `--base-url` (required unless `--url` is given; the tool has no
built-in firmware host).
Test: `test_installs_from_any_allowed_image_url_in_manifest`, tools `TestLayout`.

## D20 Key ids are data; test and example ids are test-only
The key table is configured per device; no code depends on a particular key id. `esp-fleet-ota` is only the tool's
example default `--key-id`. Tests and the example use `test-only-esp-fleet-ota` / `test-only-esp-fleet-ota-breakglass`.
The example's keys are generated with the fixtures (`tools/gen_test_vectors.py` writes both) and
`test/test_example_keys` fails if they drift.

## D21 Factory descriptor for browser flashing is a separate format
`factory.json` (schema 1, keys in a fixed order: schema, product, chip, board?, version, factory_url, factory_sha256,
factory_size, key_id, released_at) describes a merged full-flash image for first install and recovery from a web
page. Devices never read it, so the OTA manifest format and the device parser are unchanged (deployed devices reject
unknown keys); the device parser refuses a factory descriptor (`UnknownKey`, `test_factory_descriptor_is_refused_as_manifest`)
and the tool detects the kind by `factory_url` and validates it strictly as that kind. It is signed with the same keys
and the same `sign` path. Alternative: optional factory keys in the OTA manifest (rejected: breaks deployed parsers).
`merge` wraps `esptool merge_bin` (bootloader 0x0, or 0x1000 on esp32/esp32s2; partitions 0x8000; app 0x10000; dio;
4MB); a merged image overwrites NVS and otadata.

## D22 Channel `dev`
Context: bench and development builds need their own release stream that stable and beta devices never take.
Decision: the closed channel set becomes `stable | beta | dev` in the device parser and in `fota_release.py`
(`manifest`, `verify`, the layout helper); any other value is still `BadValue`/refused, so the parser stays flat,
allocation-free and fail-closed (D2), and every manifest a deployed device can fetch today parses exactly as before.
Consequences: `cfg.channel` must equal the manifest's channel, so only a device configured for `dev` installs a dev
manifest. Devices built with an older release refuse `dev` (`manifest_invalid`), so no server may publish a dev
manifest to a channel path an older device reads; dev manifests live under `<product>/<chip>/dev/` only.
Tests: `test_channel_set`, `test_dev_channel_only_for_dev_devices`, tools `test_channel_set_stable_beta_dev`,
`test_cli_manifest_and_verify_dev_channel`.
