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
    fota_release.py c-key --public-key pub.pem --key-id esp-fleet-ota --key-version N --name kEspFleetOtaV1

Layout derived from --base-url when --url is not given:
    manifest  <base>/<product>/<chip>/<channel>/manifest.json (+ .sig)
    image     <base>/<product>/<version>/<chip>/firmware.bin
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
    url = m["url"]
    _check_str("url", url, None, 256)
    if not url.startswith("https://") or len(url) == 8 or any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in url):
        raise ReleaseError("url must be an https URL without spaces: %r" % url)
    if type(m["size"]) is not int or not 0 < m["size"] <= 0x7FFFFFFF:
        raise ReleaseError("size must be an integer in 1..2^31-1")
    if not isinstance(m["sha256"], str) or not re.match(r"^[0-9a-f]{64}$", m["sha256"]):
        raise ReleaseError("sha256 must be 64 lowercase hex characters")
    _check_str("key_id", m["key_id"], _KEY_ID)
    if not isinstance(m["released_at"], str) or not _TS.match(m["released_at"]):
        raise ReleaseError("released_at must be YYYY-MM-DDTHH:MM:SSZ")


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
              "released_at": released_at or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
    return encode_manifest(m)


def parse_manifest_bytes(data):
    if len(data) > MAX_MANIFEST_BYTES:
        raise ReleaseError("manifest larger than %d bytes" % MAX_MANIFEST_BYTES)

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
    validate_manifest(m)
    return m


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

    s = sub.add_parser("sign", help="sign manifest.json (OpenBao transit, break-glass DER, or a TEST key)")
    s.add_argument("--manifest", required=True)
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

    v = sub.add_parser("verify", help="verify manifest + signature like the device does")
    v.add_argument("--manifest", required=True)
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


def cmd_sign(a):
    manifest = _read(a.manifest)
    parse_manifest_bytes(manifest)
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
    m = parse_manifest_bytes(manifest)
    n = verify_bytes(manifest, _read(a.sig or a.manifest + ".sig", "r"), _read(a.public_key), a.key_version)
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
        {"manifest": cmd_manifest, "sign": cmd_sign, "verify": cmd_verify, "c-key": cmd_c_key}[a.cmd](a)
    except (ReleaseError, OSError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
