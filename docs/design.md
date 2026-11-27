# esp-fleet-ota design

Signed pull OTA for ESP32-family devices (ESP32-C3 first, ESP32-S3 next) on Arduino / PlatformIO (pioarduino).
Decisions and their rationale: docs/decisions.md.

## Flow

```
            ota_check / auto-check                          ota_update(expected_version)
device --GET manifest.json------> fw.example.com      device --(re-check)--> same as ota_check
       --GET manifest.json.sig-->                           --canUpdateNow()? onBeforeUpdate()
   strict parse (<= 2 KB) -> key (key_id, N) -> ECDSA P-256 --GET firmware.bin--> stream into spare slot,
   over the EXACT manifest bytes -> policy checks              SHA-256 on the fly, <= 4 KB buffer
   (product, chip, board, channel, newer, floor, size,       --hash ok--> esp_ota_end + set_boot_partition
    https + host allow-list, not a rejected version          --reboot--> pending_verify --selfTest()-->
    unless ota_update forces it)                               pass: mark valid, raise floor, last_result ok,
                                                                     forget rejected versions <= it
                                                               fail / 120 s deadline: last_result rolled_back,
                                                               remember the version as rejected,
                                                               mark invalid + reboot -> previous image
```

States: `idle, checking, available, downloading, verifying, rebooting, pending_verify, ok, failed`
(`src/fleet_ota.h`). Every refusal and failure has a stable snake_case reason code (`src/fota_reason.h`), reported by
`ota_status` and persisted in `last_result` as `<kind>|<reason>|<version>` with kind `ok | rolled_back | refused |
failed`.

## Components

| File | Role | Arduino? |
|---|---|---|
| `src/fota_semver.*` | strict SemVer 2.0.0 parse + precedence (prerelease rules) | no |
| `src/fota_manifest.*` | strict, bounded, allocation-free manifest parser (schema 1) | no |
| `src/fota_signature.*` | `vault:vN:` / bare base64 parsing, (key_id, N) key lookup, verify over exact bytes | no |
| `src/fota_crypto.h` | `ISha256`, `IEcdsaP256Verifier` | no |
| `src/fota_selfcheck.*` | crypto known-answer test (FleetOta fails closed when it fails) | no |
| `src/fota_checks.*` | policy checks before download, URL host extraction, floor update | no |
| `src/fota_download.*` | incremental download + hash + write, clean abort | no |
| `src/fota_result.*` | `last_result` text form and persistence | no |
| `src/fota_rejected.*` | rejected-version memory: bounded list (8), text form and persistence | no |
| `src/fleet_ota.*` | the state machine, `check()`, `update()`, `status()`, JSON status | no |
| `src/fota_io.h` | device interfaces: clock/watchdog, HTTPS source, partition writer, OTA platform, store, hooks | no |
| `src/fota_target.h` | `FOTA_CHIP` (= `CONFIG_IDF_TARGET`), `FOTA_BOARD` (build flag) | no |
| `src/esp/fota_esp.*` | ESP glue: `NetworkClientSecure` + CA bundle, `esp_ota_*`, NVS (`Preferences`), mbedTLS | yes |
| `src/host/fota_openssl.*` | host crypto for the native tests (OpenSSL libcrypto) | no |

## Threat model

### Assets

The firmware that runs on each device, and the devices' ability to keep running and to recover.

### What it protects against

| Attacker | Can | Cannot |
|---|---|---|
| Network (Wi-Fi, LAN, ISP, DNS spoofing, TLS interception) | delay, drop or corrupt traffic | install firmware: the manifest signature fails; a swapped image fails the SHA-256 in the signed manifest; URLs on other hosts are refused by the allow-list; redirects are not followed. TLS (CA bundle + host name check) is a second layer, not the root of trust |
| Compromised firmware host (`fw.example.com`, its storage, the CI that publishes but does not hold the key) | serve any bytes, replay old signed manifests | install unsigned firmware; install a signed image for another product/chip/board/channel; downgrade below the running version or below the floor (highest confirmed `min_version`); exhaust memory (bounded parser, <= 4 KB buffers, size checked against the slot) |
| Holder of a retired key version | sign manifests | have them accepted once that (key_id, N) entry is removed from the device table and that firmware is installed |
| A bad but genuinely signed release | install it | keep it: if the device self-test fails or does not pass within the deadline (120 s), the image is marked invalid and the bootloader returns to the previous one |
| A broken crypto backend (e.g. a verifier that accepts everything) | - | be used: FleetOta runs a known-answer test before its first check and refuses (`crypto_self_check_failed`) |

The signing key is an OpenBao transit key (`ecdsa-p256`, non-exportable): the private key never leaves OpenBao, and
signing needs a token allowed to `update` `transit/sign/<key>`. The break-glass key is a YubiKey PIV key, offline.

### What it does NOT protect against

- **Physical / serial access.** Without Secure Boot v2 and flash encryption anyone with the USB/UART port can flash any
  image (`esptool`), read the flash (including NVS and Wi-Fi credentials) and change the trusted key table. This
  library secures the network update path only. Secure Boot v2 (then `esp_ota_end` also verifies an image signature)
  and flash encryption are separate, largely irreversible eFuse decisions (docs/decisions.md D17).
- **Code already running on the device** (a bug or a malicious feature in the running firmware) can call `esp_ota_*`
  directly.
- **A compromised signer** (an OpenBao token with transit sign rights, or the YubiKey and its PIN) can sign anything for
  every device that trusts the key. Mitigation is operational: narrow policies, the OpenBao audit log, key rotation
  (docs/release.md).
- **Replay of an older signed manifest that is still newer than the device**: accepted by design (a legitimate
  release). A release that must never be installed again needs its key version retired, or a newer release with a
  higher `min_version` confirmed on the device.
- **Freeze attacks**: a host can keep serving an old manifest so devices never see a newer one. Devices report
  `last_check` and their version; the fleet view must notice stale devices. (There is no expiry in schema 1.)
- **Denial of service**: network and host attackers can always prevent updates. They cannot brick a device: a failed
  download aborts the spare slot, which never becomes bootable.
- **Images that crash before `FleetOta::loop()` runs**: the ESP-IDF bootloader handles those (an image left in
  `PENDING_VERIFY` is not booted again) and the next boot records `rolled_back|boot_failed|<version>`. This relies on
  `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y`, which the pioarduino Arduino libs ship for esp32c3 and esp32s3.
- **Bootloader-level anti-rollback**: the floor is a policy of the running firmware, not the eFuse-backed secure
  version (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`). Serial flashing an old image is not prevented.

## Memory and time budgets

Measured by `test/test_memory` with a tracking allocator (library allocations only): `check()` needs one 2049-byte
buffer (the manifest) at a time; an update needs one chunk buffer (2048 B default, clamped to 256..4096), freed at the
end. `FleetOta` is ~1 KB and is meant to have static storage. Not counted: the TLS session of the download
(`NetworkClientSecure`, tens of KB in mbedTLS) and mbedTLS bignums during verify (`calloc`, a few KB, short-lived).
A C3 device that already holds two TLS sessions may have only ~57 KB free / ~47 KB in its largest block; such an
integration must close or pause one TLS session in `onBeforeUpdate()` before the download opens its own (docs/integration.md).

Watchdog: `Downloader::step()` does at most one read + write and feeds the watchdog; a stall times out after 10 s
(below the 15 s task watchdog). The TLS handshake blocks inside mbedTLS; the glue takes the task off the watchdog for
that call only. `esp_ota_begin` uses `OTA_WITH_SEQUENTIAL_WRITES`, so the 1.875 MB slot is
erased sector by sector while writing instead of in one long call. `check()` is blocking but bounded by
`fetch_timeout_ms` (15 s) per file plus the TLS handshake.
