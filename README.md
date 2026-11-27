# esp-fleet-ota

Signed pull over-the-air updates for ESP32-family devices (ESP32-C3, ESP32-S3, ...), Arduino on PlatformIO
(pioarduino platform).

Devices pull a signed manifest over HTTPS and verify it: ECDSA P-256 over the exact manifest bytes, accepting
OpenBao/Vault transit `vault:vN:` signatures or bare base64 signatures from a break-glass key, with keys compiled into
the firmware as (key_id, N) entries. They then check product, chip, board, channel, version, an anti-downgrade floor,
image size and a host allow-list. The image is streamed into the spare OTA slot with a SHA-256 check and bounded
memory, the device reboots, and the new image is kept only after a device-defined self-test passes; otherwise the
bootloader rolls back. Updates are triggered through an API meant to be exposed as device tools (`ota_status`,
`ota_check`, `ota_update <version>`) or MQTT, with an optional automatic check (off by default).

## Features

| Feature | Notes |
|---|---|
| Signed manifests | ECDSA P-256 over the exact bytes; OpenBao/Vault transit `vault:vN:` or bare break-glass signatures |
| Several trusted keys | (key_id, N) table; a signature is checked only against the key matching the manifest's key_id; bench builds may trust an extra dev key, production builds must not |
| Strict, allocation-free parser | flat JSON, 2 KB limit, unknown keys and anything outside the schema refused |
| Channels | `stable`, `beta`, `dev`; a device installs only manifests for its configured channel |
| Policy checks | product, chip, board, newer than running, anti-downgrade floor, image size, https + host allow-list |
| Safe install | streamed into the spare slot with SHA-256, bounded memory, self-test after reboot, bootloader rollback |
| Rejected-version memory | a version that failed its self-test or rolled back is refused (`rejected`) unless `update(v, force)`; last 8 kept, cleared by a newer confirmed install |
| Device API | `ota_status`, `ota_check`, `ota_update <version> [force]`, optional auto-check (off by default) |
| Release tool | `tools/fota_release.py`: manifest, sign (OpenBao transit), verify, factory descriptor, merge (esptool 5 `merge-bin`, falls back to esptool 4 `merge_bin`) |

**Status: library verified on the host; hardware validation pending** (see [docs/verification.md](docs/verification.md)).

| | |
|---|---|
| Design and threat model | [docs/design.md](docs/design.md) |
| Adding it to a device | [docs/integration.md](docs/integration.md) |
| Releasing (manifest, OpenBao transit signing, key rotation, break-glass, factory image for browser flashing) | [docs/release.md](docs/release.md) |
| Decisions | [docs/decisions.md](docs/decisions.md) |
| Verification report | [docs/verification.md](docs/verification.md) |

## Build and test

Requirements: [PlatformIO Core](https://platformio.org/install/cli), a host C++17 compiler, OpenSSL 3 headers and
libcrypto for the host tests (the native env in `platformio.ini` points at Homebrew's `/opt/homebrew/opt/openssl@3`;
change the `-I`/`-L` paths on other systems), and Python 3 with `cryptography` for the release tool.

```sh
pio test -e native                                # host unit tests of the pure logic (Unity)
python3 -m unittest discover -s tools/tests       # release tool tests (no signing service needed)
python3 tools/mutation_check.py                   # disables each security check; every one must break a test
pio run -d examples/minimal -e esp32c3            # example firmware for ESP32-C3
pio run -d examples/minimal -e esp32s3            # example firmware for ESP32-S3
```

Run the builds one after another (concurrent builds in one directory delete each other's output).

## Use in a device

Add the library to the device's `lib_deps`, use a partition table with two OTA slots, configure the manifest URL,
allowed hosts and trusted keys, and implement the device hooks (`canUpdateNow`, `onBeforeUpdate`, `selfTest`).
`examples/minimal` is a complete sketch; [docs/integration.md](docs/integration.md) walks through each step.
All keys and key ids in this repository are TEST-ONLY.

## License

MIT (see `library.json`).
