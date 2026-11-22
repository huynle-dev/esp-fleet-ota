#!/usr/bin/env python3
"""esp-fleet-ota release helper: build a manifest from firmware.bin, sign it, verify it.

    fota_release.py manifest --bin firmware.bin --product P --chip esp32c3 --version 1.4.0 \
                             (--url https://... | --base-url https://fw.example.com) [--key-id esp-fleet-ota] \
                             [--board B] [--channel stable] [--min-version 1.2.0] -o manifest.json
    fota_release.py sign --manifest manifest.json --key-name esp-fleet-ota [--backend http|cli] [--mount transit]
                         [--public-key pub.pem --key-version N]          # OpenBao transit -> vault:vN:<b64 DER>
    fota_release.py sign --manifest manifest.json --der-signature sig.der # break-glass (YubiKey) -> bare base64
    fota_release.py sign --manifest manifest.json --local-key test.pem    # TEST ONLY
    fota_release.py verify --manifest manifest.json [--sig manifest.json.sig] --public-key pub.pem
                           [--key-version N] [--bin firmware.bin]
    fota_release.py merge --build-dir .pio/build/esp32c3 --chip esp32c3 [-o factory.bin]   # wraps esptool merge_bin
    fota_release.py factory --bin factory.bin --product P --chip esp32c3 --version 1.4.0 \
                            (--url https://... | --base-url https://fw.example.com) [-o factory.json]
    fota_release.py c-key --public-key pub.pem --key-id esp-fleet-ota --key-version N --name kEspFleetOtaV1

Layout derived from --base-url when --url is not given:
    manifest  <base>/<product>/<chip>/<channel>/manifest.json (+ .sig)
    image     <base>/<product>/<version>/<chip>/firmware.bin
    factory   <base>/<product>/<version>/<chip>/factory.bin (+ factory.json, factory.json.sig)
The factory descriptor (factory.json) is for browser flashing only; devices never read it, and it is deliberately
not an OTA manifest (the device parser refuses it). `sign` and `verify` accept both kinds.
Devices do not derive the image path: they download whatever https URL on an allow-listed host the signed manifest
names.

The OpenBao address and token come ONLY from the environment (BAO_ADDR/BAO_TOKEN, or VAULT_ADDR/VAULT_TOKEN):
there is no option to pass a token, and none is ever read from a file or printed. The manifest file is written
without a trailing newline; its exact bytes are what gets signed. Stdlib + `cryptography`.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import urllib.parse
import urllib.request

MAX_MANIFEST_BYTES = 2048
DEFAULT_KEY_ID = "esp-fleet-ota"          # example default key_id; use the key ids your devices are configured with
FIELDS = ["schema", "product", "chip", "board", "channel", "version", "min_version", "url", "size", "sha256",
          "key_id", "released_at"]
REQUIRED = {"schema", "product", "chip", "channel", "version", "url", "size", "sha256", "key_id", "released_at"}
# Factory descriptor (browser flashing): this exact key order; board is the only optional key.
FACTORY_FIELDS = ["schema", "product", "chip", "board", "version", "factory_url", "factory_sha256", "factory_size",
                  "key_id", "released_at"]
FACTORY_REQUIRED = set(FACTORY_FIELDS) - {"board"}

_SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$")
_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_CHIP = re.compile(r"^[a-z0-9]+$")
_KEY_ID = re.compile(r"^[A-Za-z0-9._-]+$")
_TS = re.compile(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$")
_VAULT = re.compile(r"^vault:v([1-9]\d*):(.+)$", re.S)
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class ReleaseError(Exception):
    pass


# ---------------------------------------------------------------- semver
def parse_semver(v):
    m = _SEMVER.match(v or "") if isinstance(v, str) else None
    if not m or len(v) > 64:
        raise ReleaseError("not a semantic version: %r" % (v,))
    nums = tuple(int(m.group(i)) for i in (1, 2, 3))
    if any(n > 0xFFFFFFFF for n in nums):
        raise ReleaseError("version number too large: %r" % (v,))
    pre = m.group(4).split(".") if m.group(4) else []
    return nums, pre


def compare_semver(a, b):
    (na, pa), (nb, pb) = parse_semver(a), parse_semver(b)
    if na != nb:
        return -1 if na < nb else 1
    if not pa or not pb:
        return (0 if not pa and not pb else (1 if not pa else -1))
    for x, y in zip(pa, pb):
        if x == y:
            continue
        dx, dy = x.isdigit(), y.isdigit()
        if dx and dy:
            return -1 if int(x) < int(y) else 1
        if dx != dy:
            return -1 if dx else 1
        return -1 if x < y else 1
    return (len(pa) > len(pb)) - (len(pa) < len(pb))


# ---------------------------------------------------------------- manifest
def _check_str(name, value, pattern=None, maxlen=32):
    if not isinstance(value, str) or not value:
        raise ReleaseError("%s must be a non-empty string" % name)
    if len(value) > maxlen:
        raise ReleaseError("%s longer than %d characters" % (name, maxlen))
    if pattern and not pattern.match(value):
        raise ReleaseError("%s has an invalid value: %r" % (name, value))


def validate_manifest(m):
    """The same rules as the device parser (src/fota_manifest.cpp)."""
    if set(m) - set(FIELDS):
        raise ReleaseError("unknown keys: %s" % sorted(set(m) - set(FIELDS)))
    if REQUIRED - set(m):
        raise ReleaseError("missing keys: %s" % sorted(REQUIRED - set(m)))
    if type(m["schema"]) is not int or m["schema"] != 1:
        raise ReleaseError("schema must be 1")
    _check_str("product", m["product"], _SLUG)
    _check_str("chip", m["chip"], _CHIP, 16)
    if "board" in m:
        _check_str("board", m["board"], _SLUG)
    if m["channel"] not in ("stable", "beta"):
        raise ReleaseError("channel must be stable or beta")
    _check_str("version", m["version"], None)
    parse_semver(m["version"])
    if "min_version" in m:
        _check_str("min_version", m["min_version"], None)
        if compare_semver(m["min_version"], m["version"]) > 0:
            raise ReleaseError("min_version is above version")
    _check_url("url", m["url"])
    if type(m["size"]) is not int or not 0 < m["size"] <= 0x7FFFFFFF:
        raise ReleaseError("size must be an integer in 1..2^31-1")
    if not isinstance(m["sha256"], str) or not re.match(r"^[0-9a-f]{64}$", m["sha256"]):
        raise ReleaseError("sha256 must be 64 lowercase hex characters")
    _check_str("key_id", m["key_id"], _KEY_ID)
    if not isinstance(m["released_at"], str) or not _TS.match(m["released_at"]):
        raise ReleaseError("released_at must be YYYY-MM-DDTHH:MM:SSZ")


def _check_url(name, url):
    _check_str(name, url, None, 256)
    if not url.startswith("https://") or len(url) == 8 or any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in url):
        raise ReleaseError("%s must be an https URL without spaces: %r" % (name, url))


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_factory(m):
    """Factory descriptor rules: the manifest's rules for the shared fields, flat, no extra keys."""
    if list(m) != [k for k in FACTORY_FIELDS if k in m]:
        raise ReleaseError("factory descriptor keys are not in the required order")
    if set(m) - set(FACTORY_FIELDS):
        raise ReleaseError("unknown keys: %s" % sorted(set(m) - set(FACTORY_FIELDS)))
    if FACTORY_REQUIRED - set(m):
        raise ReleaseError("missing keys: %s" % sorted(FACTORY_REQUIRED - set(m)))
    if type(m["schema"]) is not int or m["schema"] != 1:
        raise ReleaseError("schema must be 1")
    _check_str("product", m["product"], _SLUG)
    _check_str("chip", m["chip"], _CHIP, 16)
    if "board" in m:
        _check_str("board", m["board"], _SLUG)
    _check_str("version", m["version"], None)
    parse_semver(m["version"])
    _check_url("factory_url", m["factory_url"])
    if not isinstance(m["factory_sha256"], str) or not re.match(r"^[0-9a-f]{64}$", m["factory_sha256"]):
        raise ReleaseError("factory_sha256 must be 64 lowercase hex characters")
    if type(m["factory_size"]) is not int or not 0 < m["factory_size"] <= 0x7FFFFFFF:
        raise ReleaseError("factory_size must be an integer in 1..2^31-1")
    _check_str("key_id", m["key_id"], _KEY_ID)
    if not isinstance(m["released_at"], str) or not _TS.match(m["released_at"]):
        raise ReleaseError("released_at must be YYYY-MM-DDTHH:MM:SSZ")


def encode_factory(m):
    ordered = {k: m[k] for k in FACTORY_FIELDS if k in m}
    validate_factory(ordered)
    data = json.dumps(ordered, separators=(",", ":"), ensure_ascii=True).encode()
    if len(data) > MAX_MANIFEST_BYTES:
        raise ReleaseError("factory descriptor is %d bytes, the limit is %d" % (len(data), MAX_MANIFEST_BYTES))
    return data


def build_factory(bin_path, product, chip, version, url, key_id, board=None, released_at=None):
    with open(bin_path, "rb") as f:
        image = f.read()
    m = {"schema": 1, "product": product, "chip": chip}
    if board:
        m["board"] = board
    m.update({"version": version, "factory_url": url, "factory_sha256": hashlib.sha256(image).hexdigest(),
              "factory_size": len(image), "key_id": key_id, "released_at": released_at or _now()})
    return encode_factory(m)


def encode_manifest(m):
    validate_manifest(m)
    ordered = {k: m[k] for k in FIELDS if k in m}
    data = json.dumps(ordered, separators=(",", ":"), ensure_ascii=True).encode()
    if len(data) > MAX_MANIFEST_BYTES:
        raise ReleaseError("manifest is %d bytes, the device limit is %d" % (len(data), MAX_MANIFEST_BYTES))
    return data


def build_manifest(bin_path, product, chip, version, url, key_id, channel="stable", board=None, min_version=None,
                   released_at=None):
    with open(bin_path, "rb") as f:
        image = f.read()
    m = {"schema": 1, "product": product, "chip": chip}
    if board:
        m["board"] = board
    m.update({"channel": channel, "version": version})
    if min_version:
        m["min_version"] = min_version
    m.update({"url": url, "size": len(image), "sha256": hashlib.sha256(image).hexdigest(), "key_id": key_id,
              "released_at": released_at or _now()})
    return encode_manifest(m)


def _load_flat_json(data):
    if len(data) > MAX_MANIFEST_BYTES:
        raise ReleaseError("file larger than %d bytes" % MAX_MANIFEST_BYTES)

    def no_dupes(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ReleaseError("duplicate keys")
        return dict(pairs)
    try:
        m = json.loads(data.decode("ascii"), object_pairs_hook=no_dupes)
    except (UnicodeDecodeError, ValueError) as e:
        raise ReleaseError("manifest is not valid JSON: %s" % e)
    if not isinstance(m, dict):
        raise ReleaseError("manifest is not an object")
    return m


def parse_manifest_bytes(data):
    """An OTA manifest, with the device parser's rules (a factory descriptor is refused)."""
    m = _load_flat_json(data)
    validate_manifest(m)
    return m


def parse_factory_bytes(data):
    m = _load_flat_json(data)
    validate_factory(m)
    return m


def parse_signed_bytes(data):
    """Returns ("manifest" | "factory", dict). The kind is decided by the keys: factory_url means a factory
    descriptor; it is then validated strictly as that kind, so a mix of both kinds is refused."""
    m = _load_flat_json(data)
    if "factory_url" in m:
        validate_factory(m)
        return "factory", m
    validate_manifest(m)
    return "manifest", m


# ---------------------------------------------------------------- default layout
def _base(base):
    u = urllib.parse.urlparse(base or "")
    if u.scheme != "https" or not u.hostname or u.query or u.fragment:
        raise ReleaseError("base URL must be https://host[/path]: %r" % (base,))
    return base.rstrip("/")


def image_url(base, product, version, chip):
    """<base>/<product>/<version>/<chip>/firmware.bin"""
    _check_str("product", product, _SLUG)
    parse_semver(version)
    _check_str("chip", chip, _CHIP, 16)
    return "%s/%s/%s/%s/firmware.bin" % (_base(base), product, version, chip)


def factory_url(base, product, version, chip):
    """<base>/<product>/<version>/<chip>/factory.bin"""
    return image_url(base, product, version, chip)[:-len("firmware.bin")] + "factory.bin"


def manifest_url(base, product, chip, channel):
    """<base>/<product>/<chip>/<channel>/manifest.json"""
    _check_str("product", product, _SLUG)
    _check_str("chip", chip, _CHIP, 16)
    if channel not in ("stable", "beta"):
        raise ReleaseError("channel must be stable or beta")
    return "%s/%s/%s/%s/manifest.json" % (_base(base), product, chip, channel)


# ---------------------------------------------------------------- signatures
def _b64_strict(text):
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, TypeError):
        raise ReleaseError("signature is not valid base64")
    if not raw or base64.b64encode(raw).decode() != text:
        raise ReleaseError("signature is not canonical base64")
    return raw


def parse_signature(text):
    """Returns (key_version, der): key_version N for vault:vN:, 0 for bare base64."""
    t = (text or "").strip()
    if not t:
        raise ReleaseError("empty signature")
    if t.startswith("vault:"):
        m = _VAULT.match(t)
        if not m:
            raise ReleaseError("malformed vault:v<N>: signature")
        return int(m.group(1)), _b64_strict(m.group(2))
    return 0, _b64_strict(t)


def _load_p256_public(pem_or_der):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        if pem_or_der.lstrip().startswith(b"-----BEGIN"):
            key = serialization.load_pem_public_key(pem_or_der)
        else:
            key = serialization.load_der_public_key(pem_or_der)
    except ValueError as e:
        raise ReleaseError("cannot read public key: %s" % e)
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise ReleaseError("public key is not ECDSA P-256")
    return key


def verify_bytes(manifest, sig_text, public_key, key_version=None):
    """Verify like the device: exact manifest bytes, (key, N) match. key_version None accepts any N (or bare);
    0 requires a bare signature; N >= 1 requires vault:vN:. Returns the signature's N (0 for bare)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    n, der = parse_signature(sig_text)
    if key_version is not None and n != key_version:
        raise ReleaseError("signature key version %d, expected %d" % (n, key_version))
    key = _load_p256_public(public_key)
    try:
        key.verify(der, manifest, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise ReleaseError("signature does not verify")
    return n


def _env(*names):
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return None


def sign_openbao_http(manifest, key_name, mount="transit", timeout=30):
    """POST <addr>/v1/<mount>/sign/<key>/sha2-256; OpenBao hashes the exact input bytes with SHA-256."""
    addr = _env("BAO_ADDR", "VAULT_ADDR")
    token = _env("BAO_TOKEN", "VAULT_TOKEN")
    if not addr or not token:
        raise ReleaseError("set BAO_ADDR and BAO_TOKEN (or VAULT_ADDR and VAULT_TOKEN) in the environment")
    u = urllib.parse.urlparse(addr)
    if u.scheme != "https" and not (u.scheme == "http" and u.hostname in _LOOPBACK):
        raise ReleaseError("BAO_ADDR must be https (plain http only for loopback)")
    url = "%s/v1/%s/sign/%s/sha2-256" % (addr.rstrip("/"), urllib.parse.quote(mount.strip("/")),
                                         urllib.parse.quote(key_name))
    body = json.dumps({"input": base64.b64encode(manifest).decode(), "marshaling_algorithm": "asn1"}).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("X-Vault-Token", token)
    req.add_header("Content-Type", "application/json")
    ns = _env("BAO_NAMESPACE", "VAULT_NAMESPACE")
    if ns:
        req.add_header("X-Vault-Namespace", ns)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
            reply = json.loads(resp.read())
    except OSError as e:     # URLError/HTTPError; the message never contains the token
        raise ReleaseError("transit/sign failed: %s" % e)
    sig = (reply.get("data") or {}).get("signature")
    if not isinstance(sig, str):
        raise ReleaseError("transit/sign reply has no signature")
    parse_signature(sig)
    return sig.strip()


def sign_openbao_cli(manifest, key_name, mount="transit", timeout=60):
    """`bao write -field=signature <mount>/sign/<key>/sha2-256 input=<b64> marshaling_algorithm=asn1`.
    The bao CLI reads BAO_ADDR / BAO_TOKEN from the inherited environment. Both must be set: otherwise the CLI
    would fall back to its token helper file (~/.vault-token), and tokens must come from the environment only."""
    if not _env("BAO_ADDR", "VAULT_ADDR") or not _env("BAO_TOKEN", "VAULT_TOKEN"):
        raise ReleaseError("set BAO_ADDR and BAO_TOKEN (or VAULT_ADDR and VAULT_TOKEN) in the environment")
    cmd = ["bao", "write", "-field=signature", "%s/sign/%s/sha2-256" % (mount.strip("/"), key_name),
           "input=" + base64.b64encode(manifest).decode(), "marshaling_algorithm=asn1"]
    try:
        r = subprocess.run(cmd, capture_output=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ReleaseError("bao CLI failed: %s" % e)
    if r.returncode != 0:
        raise ReleaseError("bao write failed: %s" % r.stderr.decode(errors="replace").strip())
    sig = r.stdout.decode().strip()
    parse_signature(sig)
    return sig


def sign_local(manifest, private_key_path):
    """TEST ONLY: sign with a local PEM private key; bare base64 DER (the break-glass format)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    with open(private_key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise ReleaseError("local key is not ECDSA P-256")
    return base64.b64encode(key.sign(manifest, ec.ECDSA(hashes.SHA256()))).decode()


# ---------------------------------------------------------------- CLI
def build_parser():
    p = argparse.ArgumentParser(prog="fota_release.py", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    p._fota_sub = {}

    m = sub.add_parser("manifest", help="build manifest.json from firmware.bin")
    m.add_argument("--bin", required=True)
    m.add_argument("--product", required=True)
    m.add_argument("--chip", required=True)
    m.add_argument("--board")
    m.add_argument("--channel", default="stable")
    m.add_argument("--version", required=True)
    m.add_argument("--min-version")
    m.add_argument("--url", help="image URL; default <base-url>/<product>/<version>/<chip>/firmware.bin")
    m.add_argument("--base-url", help="https base of the firmware host; required unless --url is given")
    m.add_argument("--key-id", default=DEFAULT_KEY_ID)
    m.add_argument("--released-at")
    m.add_argument("-o", "--output", default="manifest.json")
    p._fota_sub["manifest"] = m

    f = sub.add_parser("factory", help="build factory.json (browser flashing descriptor) from a merged factory.bin")
    f.add_argument("--bin", required=True, help="merged image (see `merge`)")
    f.add_argument("--product", required=True)
    f.add_argument("--chip", required=True)
    f.add_argument("--board")
    f.add_argument("--version", required=True)
    f.add_argument("--url", help="factory image URL; default <base-url>/<product>/<version>/<chip>/factory.bin")
    f.add_argument("--base-url", help="https base of the firmware host; required unless --url is given")
    f.add_argument("--key-id", default=DEFAULT_KEY_ID)
    f.add_argument("--released-at")
    f.add_argument("-o", "--output", default="factory.json")
    p._fota_sub["factory"] = f

    g = sub.add_parser("merge", help="merge a PlatformIO build into one factory.bin (esptool merge_bin)")
    g.add_argument("--build-dir", required=True, help="e.g. .pio/build/esp32c3 (bootloader/partitions/firmware.bin)")
    g.add_argument("--chip", required=True)
    g.add_argument("--esptool", help="esptool executable; default esptool.py or esptool on PATH")
    g.add_argument("--flash-size", default="4MB")
    g.add_argument("-o", "--output", default="factory.bin")
    p._fota_sub["merge"] = g

    s = sub.add_parser("sign", help="sign manifest.json or factory.json (OpenBao transit, break-glass DER, TEST key)")
    s.add_argument("--manifest", required=True, help="manifest.json or factory.json")
    src = s.add_mutually_exclusive_group(required=True)
    src.add_argument("--key-name", help="OpenBao transit key name")
    src.add_argument("--der-signature", help="DER signature made elsewhere (YubiKey break-glass)")
    src.add_argument("--local-key", help="TEST ONLY: local PEM private key")
    s.add_argument("--backend", choices=["http", "cli"], default="http")
    s.add_argument("--mount", default="transit")
    s.add_argument("--public-key", help="verify the new signature with this key before writing it")
    s.add_argument("--key-version", type=int, help="expected OpenBao key version N (with --public-key)")
    s.add_argument("-o", "--output", help="default: <manifest>.sig")
    p._fota_sub["sign"] = s

    v = sub.add_parser("verify", help="verify manifest.json or factory.json + signature (kind detected by its keys)")
    v.add_argument("--manifest", required=True, help="manifest.json or factory.json")
    v.add_argument("--sig", help="default: <manifest>.sig")
    v.add_argument("--public-key", required=True)
    v.add_argument("--key-version", type=int)
    v.add_argument("--bin", help="also check size and sha256 of this image")
    p._fota_sub["verify"] = v

    c = sub.add_parser("c-key", help="print a TrustedKey table entry for a public key")
    c.add_argument("--public-key", required=True)
    c.add_argument("--key-id", required=True)
    c.add_argument("--key-version", type=int, required=True, help="OpenBao N, or 0 for a break-glass key")
    c.add_argument("--name", required=True, help="C identifier for the PEM array")
    p._fota_sub["c-key"] = c
    return p


def subparser(parser, name):
    return parser._fota_sub[name]


def _read(path, mode="rb"):
    with open(path, mode) as f:
        return f.read()


def cmd_manifest(a):
    if not a.url and not a.base_url:
        raise ReleaseError("give --base-url (https://your-firmware-host) or an explicit --url")
    url = a.url or image_url(a.base_url, a.product, a.version, a.chip)
    data = build_manifest(a.bin, a.product, a.chip, a.version, url, a.key_id, channel=a.channel, board=a.board,
                          min_version=a.min_version, released_at=a.released_at)
    with open(a.output, "wb") as f:
        f.write(data)                       # no trailing newline: these exact bytes are signed
    print("wrote %s (%d bytes)" % (a.output, len(data)))
    print("publish image    -> %s" % url)
    if a.base_url:
        print("publish manifest -> %s (+ .sig)" % manifest_url(a.base_url, a.product, a.chip, a.channel))


def cmd_factory(a):
    if not a.url and not a.base_url:
        raise ReleaseError("give --base-url (https://your-firmware-host) or an explicit --url")
    url = a.url or factory_url(a.base_url, a.product, a.version, a.chip)
    data = build_factory(a.bin, a.product, a.chip, a.version, url, a.key_id, board=a.board, released_at=a.released_at)
    with open(a.output, "wb") as f:
        f.write(data)                       # no trailing newline: these exact bytes are signed
    print("wrote %s (%d bytes)" % (a.output, len(data)))
    print("publish factory image -> %s (+ factory.json, factory.json.sig next to it)" % url)


# Where the second-stage bootloader sits in flash, per chip (ESP-IDF CONFIG_BOOTLOADER_OFFSET_IN_FLASH). Explicit on
# purpose: a chip that is not listed is refused, because a wrong offset builds an image that does not boot.
_BOOTLOADER_AT = {
    "esp32": "0x1000", "esp32s2": "0x1000",
    "esp32c2": "0x0", "esp32c3": "0x0", "esp32c6": "0x0", "esp32h2": "0x0", "esp32s3": "0x0",
    "esp32c5": "0x2000", "esp32p4": "0x2000",
}


def merge_command(esptool, chip, build_dir, output, flash_size="4MB"):
    _check_str("chip", chip, _CHIP, 16)
    if chip not in _BOOTLOADER_AT:
        raise ReleaseError("no known bootloader offset for chip %s (known: %s); add it to _BOOTLOADER_AT after "
                           "checking the chip's bootloader offset" % (chip, ", ".join(sorted(_BOOTLOADER_AT))))
    parts = [(_BOOTLOADER_AT[chip], "bootloader.bin"), ("0x8000", "partitions.bin"),
             ("0x10000", "firmware.bin")]
    cmd = [esptool, "--chip", chip, "merge_bin", "-o", output, "--flash_mode", "dio", "--flash_size", flash_size]
    for off, name in parts:
        path = os.path.join(build_dir, name)
        if not os.path.isfile(path):
            raise ReleaseError("missing %s (build the firmware first)" % path)
        cmd += [off, path]
    return cmd


def cmd_merge(a):
    _check_str("chip", a.chip, _CHIP, 16)
    esptool = a.esptool or shutil.which("esptool.py") or shutil.which("esptool")
    if not esptool:
        raise ReleaseError("esptool not found: install it (pip install esptool) or pass --esptool <path>")
    cmd = merge_command(esptool, a.chip, a.build_dir, a.output, a.flash_size)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ReleaseError("esptool failed: %s" % e)
    if r.returncode != 0:
        raise ReleaseError("esptool merge_bin failed: %s" % (r.stderr or r.stdout).strip())
    print("wrote %s (first install / recovery only: it overwrites NVS at 0x9000 and otadata)" % a.output)


def cmd_sign(a):
    manifest = _read(a.manifest)
    parse_signed_bytes(manifest)
    if a.key_name:
        sig = (sign_openbao_cli if a.backend == "cli" else sign_openbao_http)(manifest, a.key_name, a.mount)
    elif a.der_signature:
        sig = base64.b64encode(_read(a.der_signature)).decode()
    else:
        sig = sign_local(manifest, a.local_key)
    if a.public_key:
        n = verify_bytes(manifest, sig, _read(a.public_key), a.key_version)
        print("signature verified with %s (key version %d)" % (a.public_key, n))
    out = a.output or a.manifest + ".sig"
    with open(out, "w") as f:
        f.write(sig + "\n")
    print("wrote %s (key version %d)" % (out, parse_signature(sig)[0]))


def cmd_verify(a):
    manifest = _read(a.manifest)
    kind, m = parse_signed_bytes(manifest)
    n = verify_bytes(manifest, _read(a.sig or a.manifest + ".sig", "r"), _read(a.public_key), a.key_version)
    if kind == "factory":
        if a.bin:
            image = _read(a.bin)
            if len(image) != m["factory_size"]:
                raise ReleaseError("factory image size %d, descriptor says factory_size %d" %
                                   (len(image), m["factory_size"]))
            if hashlib.sha256(image).hexdigest() != m["factory_sha256"]:
                raise ReleaseError("factory image sha256 does not match factory_sha256")
        print("OK: factory %s %s for %s signed by %s key version %d" % (m["product"], m["version"], m["chip"],
                                                                       m["key_id"], n))
        return
    if a.bin:
        image = _read(a.bin)
        if len(image) != m["size"] or hashlib.sha256(image).hexdigest() != m["sha256"]:
            raise ReleaseError("firmware.bin does not match the manifest size/sha256")
    print("OK: %s %s %s for %s signed by %s key version %d" % (m["product"], m["version"], m["channel"], m["chip"],
                                                              m["key_id"], n))


def cmd_c_key(a):
    pem = _read(a.public_key)
    _load_p256_public(pem)
    if not re.match(r"^[A-Za-z_]\w*$", a.name):
        raise ReleaseError("--name must be a C identifier")
    _check_str("key_id", a.key_id, _KEY_ID)
    lines = pem.decode().strip().splitlines()
    print("static const char %s[] =" % a.name)
    for i, line in enumerate(lines):
        print('    "%s\\n"%s' % (line, ";" if i == len(lines) - 1 else ""))
    print('// in the TrustedKey table:\n{"%s", %d, (const uint8_t*)%s, sizeof(%s) - 1},' %
          (a.key_id, a.key_version, a.name, a.name))


def main(argv=None):
    a = build_parser().parse_args(argv)
    try:
        {"manifest": cmd_manifest, "factory": cmd_factory, "merge": cmd_merge, "sign": cmd_sign, "verify": cmd_verify, "c-key": cmd_c_key}[a.cmd](a)
    except (ReleaseError, OSError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
