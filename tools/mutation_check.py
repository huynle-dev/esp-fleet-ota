#!/usr/bin/env python3
"""Mutation check of the security checks: disable each one in the source, run the native tests, and require a failure.
Restores every file afterwards (also on Ctrl-C). Run from the repository root:

    python3 tools/mutation_check.py [--pio ~/pio-venv/bin/pio] [--only NAME]
"""
import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# name, file, original text, mutated text
MUTATIONS = [
    ("signature check removed", "src/fleet_ota.cpp",
     "else r = sigToReason(verifyManifestSignature(text, textLen, m.key_id, sig, sigLen, cfg_.keys, cfg_.key_count,\n"
     "                                                     d_.sha, d_.ecdsa));",
     "else r = Reason::none;"),
    ("signature: key version N ignored", "src/fota_signature.cpp",
     "const TrustedKey* key = findTrustedKey(keyId, vault ? version : 0, keys, keyCount);",
     "const TrustedKey* key = findTrustedKey(keyId, keys[0].key_version, keys, keyCount);"),
    ("signature: manifest bytes trimmed", "src/fota_signature.cpp",
     "    sha.update((const uint8_t*)manifest, manifestLen);",
     "    while (manifestLen && (manifest[manifestLen - 1] == '\\n' || manifest[manifestLen - 1] == ' ')) manifestLen--;\n"
     "    sha.update((const uint8_t*)manifest, manifestLen);"),
    ("crypto self-check ignored", "src/fleet_ota.cpp",
     "if (cryptoOk_ < 0) cryptoOk_ = cryptoSelfCheck(d_.sha, d_.ecdsa) ? 1 : 0;",
     "cryptoOk_ = 1;"),
    ("manifest unknown-key rejection removed", "src/fota_manifest.cpp",
     "    if (unknown) { bad = unknownName; return ManifestError::UnknownKey; }\n", ""),
    ("chip check removed", "src/fota_checks.cpp",
     "    if (empty(dev.chip) || strcmp(m.chip, dev.chip) != 0) return Reason::wrong_chip;\n", ""),
    ("product check removed", "src/fota_checks.cpp",
     "    if (empty(dev.product) || strcmp(m.product, dev.product) != 0) return Reason::wrong_product;\n", ""),
    ("anti-downgrade floor removed", "src/fota_checks.cpp",
     "    if (!empty(floor) && parseSemVer(floor, fl) && compareSemVer(offered, fl) < 0) return Reason::below_floor;\n",
     ""),
    ("newer-than-running removed", "src/fota_checks.cpp",
     "    if (compareSemVer(offered, running) <= 0) return Reason::not_newer;\n", ""),
    ("image https check removed", "src/fota_checks.cpp",
     "    if (strncmp(m.url, \"https://\", 8) != 0) return Reason::url_not_https;\n", ""),
    ("image host allow-list removed", "src/fota_checks.cpp",
     "    if (!urlHostAllowed(m.url, cfg.allowed_hosts, cfg.allowed_host_count)) return Reason::host_not_allowed;\n",
     ""),
    ("manifest URL https/allow-list removed", "src/fleet_ota.cpp",
     "    Reason r = checkUrl(cfg_.manifest_url, cfg_);", "    Reason r = Reason::none;"),
    ("signature URL https/allow-list removed", "src/fleet_ota.cpp",
     "        r = checkUrl(sigUrl, cfg_);", "        r = Reason::none;"),
    ("image hash check removed", "src/fota_download.cpp",
     "    if (memcmp(got, expected_, 32) != 0) return fail(Reason::hash_mismatch);\n", ""),
    ("abort on failure removed", "src/fota_download.cpp",
     "    if (writerOpen_) { writer_.abort(); writerOpen_ = false; }\n", ""),
    ("size check removed", "src/fota_checks.cpp",
     "    if (m.size == 0 || m.size > spareSlotBytes) return Reason::too_large;\n", ""),
    ("mark valid at boot (before self-test)", "src/fleet_ota.cpp",
     "        verifyDeadline_ = now + cfg_.self_test_deadline_ms;\n",
     "        verifyDeadline_ = now + cfg_.self_test_deadline_ms;\n        d_.platform.markValid();\n"),
    ("self-test failure treated as pass", "src/fleet_ota.cpp",
     "            fail = Reason::self_test_failed;\n",
     "            if (d_.platform.markValid()) { confirmInstalled(pendingVersion_, pendingMin_); return; }\n"
     "            fail = Reason::self_test_failed;\n"),
    ("self-test deadline ignored", "src/fleet_ota.cpp",
     "    if (now >= verifyDeadline_) {", "    if (false) {"),
    ("expected version not enforced", "src/fleet_ota.cpp",
     "    if (!expectedVersion || strcmp(expectedVersion, available_.version) != 0) {", "    if (false) {"),
    ("device canUpdateNow ignored", "src/fleet_ota.cpp",
     "    if (!d_.hooks.canUpdateNow(why, sizeof(why))) {\n        finishFailure",
     "    if (false) {\n        finishFailure"),
    ("channel set widened to any value", "src/fota_manifest.cpp",
     "    return !strcmp(s, \"stable\") || !strcmp(s, \"beta\") || !strcmp(s, \"dev\");",
     "    return s != nullptr;"),
    ("rejected-version check skipped", "src/fleet_ota.cpp",
     "    if (r == Reason::none && !force && rejected_.contains(m.version)) r = Reason::rejected;\n", ""),
    ("rejected check always forced", "src/fleet_ota.cpp",
     "    Reason r = checkWith(force);", "    Reason r = checkWith(true);"),
    ("rejected version not remembered", "src/fleet_ota.cpp",
     "    if (rejected_.add(version)) saveRejected(d_.store, rejected_);", "    (void)version;"),
    ("signature: key_id matching dropped", "src/fota_signature.cpp",
     "        if (keys[i].key_id && !strcmp(keys[i].key_id, keyId) && keys[i].key_version == keyVersion) return &keys[i];",
     "        if (keys[i].key_id && keys[i].key_version == keyVersion) return &keys[i];"),
]


def run_tests(pio):
    r = subprocess.run([pio, "test", "-e", "native"], cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True,
                       text=True)
    out = r.stdout + r.stderr
    summary = [l for l in out.splitlines() if "test cases:" in l]
    failed = [l.split(":")[2].strip() for l in out.splitlines() if "[FAILED]" in l and l.count(":") >= 2]
    return r.returncode, (summary[-1].strip("= ") if summary else "exit %d, no summary" % r.returncode), failed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pio", default=os.path.expanduser("~/pio-venv/bin/pio"))
    ap.add_argument("--only")
    a = ap.parse_args()
    results = []
    for name, rel, old, new in MUTATIONS:
        if a.only and a.only not in name:
            continue
        path = os.path.join(ROOT, rel)
        with open(path) as f:
            original = f.read()
        if original.count(old) != 1:
            print("SETUP ERROR %-40s pattern not found exactly once in %s" % (name, rel))
            results.append((name, False))
            continue
        try:
            with open(path, "w") as f:
                f.write(original.replace(old, new))
            code, summary, failed = run_tests(a.pio)
        finally:
            with open(path, "w") as f:
                f.write(original)
        killed = code != 0
        results.append((name, killed))
        print("%-8s %-40s %s | first failing: %s" % ("KILLED" if killed else "SURVIVED", name, summary,
                                                     ", ".join(failed[:2]) or "-"))
    survived = [n for n, k in results if not k]
    print("\n%d/%d mutations killed" % (len(results) - len(survived), len(results)))
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
