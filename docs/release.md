# Releasing firmware

Firmware is served over HTTPS from your firmware host, `https://fw.example.com` in these examples. Devices verify its
certificate with the CA bundle (which includes the ISRG roots used by Let's Encrypt) and check the host name. A layout
that works well, and the one `fota_release.py` derives from `--base-url`:

```
https://fw.example.com/<product>/<chip>/<channel>/manifest.json        manifest, per product + chip + channel
https://fw.example.com/<product>/<chip>/<channel>/manifest.json.sig    its detached signature
https://fw.example.com/<product>/<version>/<chip>/firmware.bin         image, per product + version + chip
```

The device is configured with the manifest URL only. It never derives the image path: it downloads the `url` that
the signed manifest names, as long as it is https on an allow-listed host. The image layout is applied by
`fota_release.py manifest` from `--base-url` (required unless you pass an explicit `--url`; there is no built-in
host).

Key ids: in these examples the OpenBao transit key has key_id `esp-fleet-ota` (also the tool's default `--key-id`) and
its signatures carry the key version N (`vault:vN:`); the transit key *name* is `esp-fleet-ota` too. The break-glass
key has its own key id of your choice. Use the key ids and public keys you configure in your devices, exactly.

All commands use `tools/fota_release.py` (Python 3, `pip install cryptography`). Run `tools/fota_release.py -h`.

## 1. Build

```sh
cd <device>/firmware
~/pio-venv/bin/pio run -e esp32c3 < /dev/null          # FIRMWARE_VERSION in platformio.ini = the release version
cp .pio/build/esp32c3/firmware.bin /tmp/rel/firmware.bin
```

The version compiled into the image (`FIRMWARE_VERSION`) must equal the manifest `version`: after the reboot the
device compares the running version with the installed record (`rolled_back|boot_failed` otherwise).

## 2. Manifest

```sh
tools/fota_release.py manifest --bin /tmp/rel/firmware.bin \
  --product example-psu --chip esp32c3 [--board esp32-c3-devkitm-1] --channel stable \
  --version 1.4.0 [--min-version 1.2.0] --base-url https://fw.example.com -o /tmp/rel/manifest.json
# url    = https://fw.example.com/example-psu/1.4.0/esp32c3/firmware.bin    (derived; or pass --url)
# key_id = esp-fleet-ota                                                  (default; --key-id for break-glass)
```

The command prints where to publish the image and the manifest.

The file is compact JSON with no trailing newline. **Do not edit or reformat it after signing**: the signature covers
its exact bytes, and any change, even an added newline, makes every device refuse it (`signature_invalid`).
`--min-version` raises the device's anti-downgrade floor once this release has passed its self-test: later manifests
below it are refused (`below_floor`). Use it when an older version must never come back (security fix, data format).

## 3. Sign with OpenBao transit

One-time setup (an operator with admin rights):

```sh
bao secrets enable transit
bao write -f transit/keys/esp-fleet-ota type=ecdsa-p256 exportable=false allow_plaintext_backup=false
bao policy write fw-sign - <<'HCL'
path "transit/sign/esp-fleet-ota/sha2-256" { capabilities = ["update"] }
path "transit/keys/esp-fleet-ota"          { capabilities = ["read"] }
HCL
bao read -format=json transit/keys/esp-fleet-ota | jq -r '.data.keys["1"].public_key' > esp-fleet-ota-v1.pem
tools/fota_release.py c-key --public-key esp-fleet-ota-v1.pem --key-id esp-fleet-ota --key-version 1 \
  --name kEspFleetOtaV1
```

Each release (token from the environment only; the tool has no token option and never reads token files):

```sh
export BAO_ADDR=https://bao.example.internal:8200      # or VAULT_ADDR
export BAO_TOKEN=...                                    # or VAULT_TOKEN; a short-lived token with policy fw-sign
tools/fota_release.py sign --manifest /tmp/rel/manifest.json --key-name esp-fleet-ota \
  --public-key esp-fleet-ota-v1.pem --key-version 1             # verifies before writing manifest.json.sig
```

The HTTP backend POSTs `{"input": base64(manifest bytes), "marshaling_algorithm": "asn1"}` to
`$BAO_ADDR/v1/transit/sign/esp-fleet-ota/sha2-256` (OpenBao hashes the exact input with SHA-256, not `prehashed`) and writes
the reply `vault:v<N>:<base64 DER>` plus a newline to `manifest.json.sig`. `--backend cli` runs
`bao write -field=signature transit/sign/esp-fleet-ota/sha2-256 input=... marshaling_algorithm=asn1` instead (it also
requires `BAO_ADDR`/`BAO_TOKEN` in the environment). `--public-key/--key-version` makes the tool refuse to write a
signature whose N is not the one the devices trust.

## 4. Verify and publish

```sh
tools/fota_release.py verify --manifest /tmp/rel/manifest.json --public-key esp-fleet-ota-v1.pem --key-version 1 \
  --bin /tmp/rel/firmware.bin
```

Upload `firmware.bin` (to `<product>/<version>/<chip>/firmware.bin`) first, then `manifest.json.sig` and `manifest.json` together (serve the manifest with a short
cache lifetime). A device that catches the two files out of step gets a transient `signature_invalid` and retries
later; it never installs. Download the published files again and rerun `verify` against them.

Install on one device first: `ota_check`, then `ota_update {"version":"1.4.0"}`, then `ota_status` after the reboot
must show `last_result` `ok|none|1.4.0`.

## Factory image (browser flashing)

For a first install over USB from a web page (Web Serial + esptool-js) and for recovery of a device that no longer
boots, publish a full flash image with a signed descriptor next to the OTA image:

```
https://fw.example.com/<product>/<version>/<chip>/firmware.bin       OTA image (devices download this)
https://fw.example.com/<product>/<version>/<chip>/factory.bin        merged full-flash image (browser only)
https://fw.example.com/<product>/<version>/<chip>/factory.json       its descriptor
https://fw.example.com/<product>/<version>/<chip>/factory.json.sig   its signature
```

**The descriptor is separate from the OTA manifest on purpose.** Devices never read `factory.json`, and its format
is not an OTA manifest: the device parser refuses it (`UnknownKey`, tested in `test/test_manifest`), and
`fota_release.py` refuses to treat one as the other. Changing the OTA manifest format would break deployed devices,
which reject unknown keys, so the two evolve independently.

### 1. Merge

```sh
tools/fota_release.py merge --build-dir .pio/build/esp32c3 --chip esp32c3 -o /tmp/rel/factory.bin
```

This runs `esptool.py --chip <chip> merge_bin -o factory.bin --flash_mode dio --flash_size 4MB` with

| Offset | File | Contents |
|---|---|---|
| `0x0` (`0x1000` on esp32 and esp32s2) | `bootloader.bin` | second-stage bootloader |
| `0x8000` | `partitions.bin` | partition table |
| `0x10000` | `firmware.bin` | the app, in the first OTA slot (`app0`) |

`--esptool <path>` picks a specific esptool (`pip install esptool`); `--flash-size` changes the size. The offsets
match the partition table in `examples/minimal/partitions.csv`; check yours.

**A merged image is for first install and recovery only.** `merge_bin` fills the gaps between the parts with `0xFF`,
so flashing it erases NVS (`0x9000`: Wi-Fi credentials, the OTA `last_result` and anti-downgrade floor, device
settings) and `otadata` (`0xe000`), and the device boots `app0`. Routine updates go through OTA.

### 2. Descriptor

```sh
tools/fota_release.py factory --bin /tmp/rel/factory.bin --product example-psu --chip esp32c3 \
  [--board esp32-c3-devkitm-1] --version 1.4.0 --base-url https://fw.example.com -o /tmp/rel/factory.json
```

Flat ASCII JSON, no trailing newline, keys in exactly this order (`board` only when given):

```json
{"schema":1,"product":"example-psu","chip":"esp32c3","version":"1.4.0",
 "factory_url":"https://fw.example.com/example-psu/1.4.0/esp32c3/factory.bin",
 "factory_sha256":"<64 lowercase hex>","factory_size":1310720,"key_id":"esp-fleet-ota",
 "released_at":"2026-11-22T10:00:00Z"}
```

(shown wrapped; the file is one line). `--url` replaces the derived `factory_url`; `--key-id` defaults to
`esp-fleet-ota`; `--released-at` defaults to now. The same validation as the manifest applies (slugs, chip names,
semver, https only, safe path parts).

### 3. Sign, verify, publish

Signing is the same as for a manifest, with the same keys:

```sh
tools/fota_release.py sign --manifest /tmp/rel/factory.json --key-name esp-fleet-ota \
  --public-key keys/esp-fleet-ota-v1.pem --key-version 1               # -> factory.json.sig (vault:v1:...)
tools/fota_release.py verify --manifest /tmp/rel/factory.json --public-key keys/esp-fleet-ota-v1.pem \
  --key-version 1 --bin /tmp/rel/factory.bin                           # detects the kind by its keys
```

(break-glass: `--der-signature`, bare base64, as for manifests). Upload `factory.bin`, then `factory.json.sig` and
`factory.json` into the same directory as the release's `firmware.bin`, and verify the published copies again.

### 4. Verifying in the web page

The flashing page must check the descriptor and the image before writing anything:

1. Fetch `factory.json` as bytes (`response.arrayBuffer()`) and verify those exact bytes; do not re-serialize the
   parsed JSON.
2. Fetch `factory.json.sig` as text and trim whitespace. `vault:v<N>:<base64>` means key version N; a bare base64
   string means N = 0 (break-glass). Base64-decode the rest: it is an ASN.1 DER `ECDSA-Sig-Value`
   (`SEQUENCE { INTEGER r, INTEGER s }`).
3. Pick the public key by the descriptor's `key_id` **and** N from the keys embedded in the page at build time
   (the PEM files in `keys/`; never fetched at runtime). Unknown (key_id, N): refuse.
4. WebCrypto wants the raw `r || s` form (64 bytes for P-256), not DER: parse the two INTEGERs, drop a leading `0x00`
   sign byte, left-pad each to 32 bytes, concatenate.
5. `crypto.subtle.importKey("spki", der, {name: "ECDSA", namedCurve: "P-256"}, false, ["verify"])` and
   `crypto.subtle.verify({name: "ECDSA", hash: "SHA-256"}, key, rawSig, descriptorBytes)`.
6. Check `product`, `chip` (against the chip esptool-js detects) and `factory_url` (https, your host), then download
   `factory.bin`, check `factory_size` and `crypto.subtle.digest("SHA-256", image)` against `factory_sha256`, and only
   then flash it at offset `0x0`.

```js
function derToRaw(der) {                       // ECDSA-Sig-Value (DER) -> r||s, 32 bytes each for P-256
  let i = 0;
  if (der[i++] !== 0x30) throw new Error("not a SEQUENCE");
  if (der[i] & 0x80) i += 1 + (der[i] & 0x7f); else i += 1;
  const out = new Uint8Array(64);
  for (const off of [0, 32]) {
    if (der[i++] !== 0x02) throw new Error("not an INTEGER");
    let len = der[i++], v = der.subarray(i, i + len);
    i += len;
    while (v.length > 32 && v[0] === 0) v = v.subarray(1);
    if (v.length > 32) throw new Error("integer too long");
    out.set(v, off + 32 - v.length);
  }
  return out;
}
```

## Key rotation (OpenBao)

Devices trust (key_id, N) pairs compiled into the firmware, so a new key version must be shipped before it is used:

1. `bao write -f transit/keys/esp-fleet-ota/rotate` (version N+1). Transit signs with the newest version by default, so do
   this right before step 2's build, or sign step 2 with the old version still trusted.
2. Export `.data.keys["N+1"].public_key`, add `{"esp-fleet-ota", N+1, ...}` to the device table **next to** `{"esp-fleet-ota", N, ...}`,
   release that firmware signed with a version the fleet already trusts, and wait until devices report it `ok`.
3. Sign further releases with N+1 (`--key-version N+1`).
4. When no device needs N any more, release firmware without the `{"esp-fleet-ota", N}` entry. Optionally
   `bao write transit/keys/esp-fleet-ota/config min_decryption_version=N+1` and trim old versions.

A device that missed step 2 cannot verify N+1 releases (`key_version_mismatch`); it needs one release signed with N
(or the break-glass key) that carries the new table.

## Break-glass key (YubiKey)

For when OpenBao is unavailable or its key is suspected compromised. Every device also trusts
`{"<break-glass key id>", 0, <YubiKey public key>}`; N = 0 means bare base64 signatures only. Use the same id in
the device table and in `--key-id`.

Setup, offline, once: generate the key on the YubiKey so it never exists outside it, e.g.
`yubico-piv-tool -a generate -s 9c -A ECCP256 -o breakglass.pem` (plus a self-signed certificate for slot 9c), store
the YubiKey and its PIN/management key separately, and compile `breakglass.pem` into every device
(`c-key --key-id <break-glass key id> --key-version 0`).

Signing:

```sh
tools/fota_release.py manifest ... --key-id <break-glass key id> -o manifest.json
yubico-piv-tool -a verify-pin -a sign -s 9c -A ECCP256 -H SHA256 -i manifest.json -o manifest.der
tools/fota_release.py sign --manifest manifest.json --der-signature manifest.der --public-key breakglass.pem
tools/fota_release.py verify --manifest manifest.json --public-key breakglass.pem --key-version 0 --bin firmware.bin
```

(check the `yubico-piv-tool` flags for your version: the input must be the manifest file itself, hashed with SHA-256
by the tool, and the output a DER ECDSA signature; `verify` catches any mismatch.)

Procedures:

- **OpenBao key compromised**: with the break-glass key, sign a release whose table drops every `esp-fleet-ota` entry and adds
  a new OpenBao key (new transit key name/key_id). Ship it with `--min-version` set to its own version so devices
  cannot be moved back to firmware that trusts the old key.
- **Break-glass key lost or compromised**: with OpenBao, sign a release that replaces the break-glass entry.
- Record every use of the break-glass key (who, why, which release) in your operations log.

Keys in this repository (`test/fixtures`, `examples/minimal`, `tools/tests`) are TEST-ONLY and must never appear in a
device's table.
