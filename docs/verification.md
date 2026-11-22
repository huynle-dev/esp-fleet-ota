# Verification report

What is verified on the host, with the output of the last run, and what still needs hardware.

Environment of this run: macOS, PlatformIO Core 6.2.0, pioarduino platform (framework-arduinoespressif32 3.3.12,
mbedTLS 3.6.6), Python 3.13 + cryptography 46.0.3, OpenSSL 3. No hardware, no network access to real hosts.
Reproduce with the commands in the README.

## Native tests: `pio test -e native`

```
Environment    Test               Status    Duration
-------------  -----------------  --------  ------------
native         test_checks        PASSED    00:00:00.949
native         test_download      PASSED    00:00:00.852
native         test_selfcheck     PASSED    00:00:00.851
native         test_result        PASSED    00:00:00.857
native         test_memory        PASSED    00:00:00.880
native         test_signature     PASSED    00:00:00.907
native         test_fleet_ota     PASSED    00:00:00.901
native         test_semver        PASSED    00:00:00.813
native         test_manifest      PASSED    00:00:00.841
native         test_example_keys  PASSED    00:00:00.838
================ 117 test cases: 117 succeeded in 00:00:08.690 ================
```

## Release tool tests: `python3 -m unittest discover -s tools/tests`

```
Ran 28 tests in 0.151s
OK
```

The OpenBao transit call and the `bao` CLI are mocked; keys are generated per run.

## Memory budget: `pio test -e native -f test_memory -v` (library allocations only)

```
[mem] check (manifest + sig)   max single  2049 B, peak extra  2113 B, allocations 3
[mem] sizeof(FleetOta) = 1016 B (static on the device), sizeof(Manifest) = 544 B
[mem] update, chunk 2048       max single  2049 B, peak extra  2113 B, allocations 5
[mem] update, chunk 4096       max single  4096 B, peak extra  4152 B, allocations 5
[mem] update, chunk 65536      max single  4096 B, peak extra  4152 B, allocations 5
```

Not counted: the download's TLS session (owned by the ESP glue) and mbedTLS bignums during verify. Removing the
4096-byte clamp on the chunk buffer fails `test_oversized_chunk_request_is_clamped`.

## Mutation check of the security checks: `python3 tools/mutation_check.py`

Each line disables one check in the source, runs the whole native suite and restores the file. A mutation is
"KILLED" when at least one test fails. (PlatformIO counts each errored suite as an extra case, so failing runs
report 118-120 "test cases".)

```
KILLED   signature check removed                  118 test cases: 5 failed, 112 succeeded in 00:00:09.059 | first failing: test_check_tampered_manifest_refused, test_manifest_trailing_newline_breaks_signature
KILLED   signature: key version N ignored         120 test cases: 11 failed, 106 succeeded in 00:00:09.104 | first failing: test_openbao_rotated_key_version_valid, test_openbao_unknown_key_version_refused
KILLED   signature: manifest bytes trimmed        119 test cases: 3 failed, 114 succeeded in 00:00:09.103 | first failing: test_any_manifest_byte_change_fails_even_whitespace, test_manifest_trailing_newline_breaks_signature
KILLED   crypto self-check ignored                118 test cases: 1 failed, 116 succeeded in 00:00:09.053 | first failing: test_fails_closed_when_crypto_self_check_fails
KILLED   chip check removed                       119 test cases: 2 failed, 115 succeeded in 00:00:09.115 | first failing: test_chip_must_match, test_policy_refusals_after_signature
KILLED   product check removed                    119 test cases: 2 failed, 115 succeeded in 00:00:08.976 | first failing: test_product_must_match, test_policy_refusals_after_signature
KILLED   anti-downgrade floor removed             119 test cases: 2 failed, 115 succeeded in 00:00:08.996 | first failing: test_anti_downgrade_floor, test_anti_downgrade_floor_from_store
KILLED   newer-than-running removed               119 test cases: 2 failed, 115 succeeded in 00:00:09.012 | first failing: test_must_be_newer_than_running, test_policy_refusals_after_signature
KILLED   image https check removed                118 test cases: 1 failed, 116 succeeded in 00:00:09.062 | first failing: test_url_must_be_https_on_allowed_host
KILLED   image host allow-list removed            119 test cases: 2 failed, 115 succeeded in 00:00:09.085 | first failing: test_url_must_be_https_on_allowed_host, test_policy_refusals_after_signature
KILLED   manifest URL https/allow-list removed    118 test cases: 1 failed, 116 succeeded in 00:00:08.823 | first failing: test_manifest_url_must_be_https_and_allowed
KILLED   signature URL https/allow-list removed   118 test cases: 1 failed, 116 succeeded in 00:00:08.943 | first failing: test_signature_url_must_be_https_and_allowed
KILLED   image hash check removed                 119 test cases: 3 failed, 114 succeeded in 00:00:09.204 | first failing: test_wrong_hash_aborts, test_tampered_byte_in_transit_aborts
KILLED   abort on failure removed                 119 test cases: 6 failed, 111 succeeded in 00:00:09.351 | first failing: test_wrong_hash_aborts, test_truncated_body
KILLED   size check removed                       119 test cases: 2 failed, 115 succeeded in 00:00:09.035 | first failing: test_size_must_fit_spare_slot, test_image_must_fit_spare_slot
KILLED   mark valid at boot (before self-test)    118 test cases: 4 failed, 113 succeeded in 00:00:08.882 | first failing: test_self_test_pass_marks_valid_and_raises_floor, test_self_test_fail_rolls_back
KILLED   self-test failure treated as pass        118 test cases: 1 failed, 116 succeeded in 00:00:09.127 | first failing: test_self_test_fail_rolls_back
KILLED   self-test deadline ignored               118 test cases: 1 failed, 116 succeeded in 00:00:09.135 | first failing: test_self_test_deadline_rolls_back
KILLED   expected version not enforced            118 test cases: 1 failed, 116 succeeded in 00:00:09.135 | first failing: test_update_requires_expected_version
KILLED   device canUpdateNow ignored              118 test cases: 1 failed, 116 succeeded in 00:00:09.586 | first failing: test_update_refused_by_device_hook

20/20 mutations killed
```

## Example builds: `pio run -d examples/minimal -e esp32c3` and `-e esp32s3`

```
esp32c3
RAM:   [=         ]  12.2% (used 39856 bytes from 327680 bytes)
Flash: [======    ]  61.3% (used 1204727 bytes from 1966080 bytes)
========================= [SUCCESS] Took 8.17 seconds =========================
esp32c3        SUCCESS   00:00:08.174
esp32s3
RAM:   [=         ]  14.7% (used 48048 bytes from 327680 bytes)
Flash: [======    ]  55.6% (used 1092796 bytes from 1966080 bytes)
========================= [SUCCESS] Took 9.39 seconds =========================
esp32s3        SUCCESS   00:00:09.391
```

Flash is relative to one 1.875 MB OTA slot; most of the image is WiFi + TLS + HTTPClient. No warnings come from the
library sources (`-Wall -Wextra`). The library's strong `verifyRollbackLater()` is linked in both images, not the
core's weak default:

```
esp32c3: 42008216 T verifyRollbackLater
esp32s3: 420af120 T verifyRollbackLater
```

## Needs hardware (not verified yet)

- A real flash write through `esp_ota_begin(OTA_WITH_SEQUENTIAL_WRITES)/write/end/set_boot_partition`, including
  `esp_ota_end` rejecting a corrupt image and `abort` leaving the boot partition unchanged.
- Rollback on the real bootloader: the new image boots `PENDING_VERIFY`; self-test pass ->
  `esp_ota_mark_app_valid_cancel_rollback`; fail or deadline -> `esp_ota_mark_app_invalid_rollback_and_reboot` boots
  the previous slot and the next boot reports `rolled_back|...`; an image that crashes in early boot -> bootloader
  rollback -> `rolled_back|boot_failed`. Also that `verifyRollbackLater()` returning true keeps the image pending
  through `initArduino()`.
- A real TLS download with the CA bundle and host name check, refusal of a certificate for another host, and
  end-of-body detection with `NetworkClientSecure` over HTTP/1.0.
- The mbedTLS adapters (`MbedtlsEcdsaP256`, `MbedtlsSha256`) at run time. On the device `cryptoSelfCheck()` covers
  them (FleetOta refuses with `crypto_self_check_failed` if they misbehave), but they are compile-tested only here.
- Timing against a 15 s task watchdog: TLS handshake (task removed from the watchdog for that call only), chunk writes
  with sequential erase, NVS writes, and the worst-case duration of `check()` inside a device request.
- Heap on a C3 that already holds two TLS sessions, plus the download's session (expected not to fit unless
  `onBeforeUpdate()` closes one).
- NVS persistence across real reboots (`Preferences`, namespace `fleet_ota`).
