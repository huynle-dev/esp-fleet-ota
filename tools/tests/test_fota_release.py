"""Tests for tools/fota_release.py. Stdlib unittest + cryptography; no OpenBao: the transit call is mocked.

    python3 -m unittest discover -s tools/tests -v
"""
import base64
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import fota_release as fr  # noqa: E402


def make_key():
    """A TEST-ONLY P-256 key, generated per test run (never written outside the temp dir)."""
    return ec.generate_private_key(ec.SECP256R1())


def pub_pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def priv_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


class FakeTransitResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.bin = os.path.join(self.dir, "firmware.bin")
        self.image = bytes((i * 7 + 3) & 0xFF for i in range(70000))
        with open(self.bin, "wb") as f:
            f.write(self.image)
        self.key = make_key()
        self.pub = os.path.join(self.dir, "pub.pem")
        with open(self.pub, "wb") as f:
            f.write(pub_pem(self.key))

    def tearDown(self):
        self.tmp.cleanup()

    def path(self, name):
        return os.path.join(self.dir, name)

    def run_cli(self, *args, env=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env or {}, clear=env is not None), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = fr.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def build_manifest(self, **over):
        args = dict(product="example-psu", chip="esp32c3", version="1.4.0", channel="stable",
                    url="https://fw.example.com/example-psu/1.4.0/esp32c3/firmware.bin",
                    key_id="test-only-esp-fleet-ota", released_at="2026-11-22T10:00:00Z", min_version="1.2.0", board=None)
        args.update(over)
        return fr.build_manifest(self.bin, **args)


class TestManifest(Base):
    def test_fields_size_and_sha(self):
        m = json.loads(self.build_manifest())
        self.assertEqual(m["schema"], 1)
        self.assertEqual(m["size"], len(self.image))
        self.assertEqual(m["sha256"], hashlib.sha256(self.image).hexdigest())
        self.assertEqual(m["chip"], "esp32c3")
        self.assertEqual(m["min_version"], "1.2.0")
        self.assertNotIn("board", m)

    def test_exact_compact_bytes_no_newline(self):
        b = self.build_manifest()
        self.assertIsInstance(b, bytes)
        self.assertFalse(b.endswith(b"\n"))
        self.assertNotIn(b" ", b)
        self.assertTrue(b.startswith(b'{"schema":1,"product":"example-psu","chip":"esp32c3"'))
        self.assertLessEqual(len(b), fr.MAX_MANIFEST_BYTES)

    def test_board_optional(self):
        m = json.loads(self.build_manifest(board="esp32-c3-devkitm-1"))
        self.assertEqual(m["board"], "esp32-c3-devkitm-1")

    def test_rejects_what_the_device_rejects(self):
        bad = [dict(version="1.4"), dict(version="v1.4.0"), dict(chip="ESP32C3"), dict(channel="nightly"),
               dict(url="http://fw.example.com/x.bin"), dict(min_version="1.5.0"), dict(product="Bad Name"),
               dict(released_at="yesterday"), dict(key_id="")]
        for b in bad:
            with self.subTest(**b), self.assertRaises(fr.ReleaseError):
                self.build_manifest(**b)

    def test_cli_writes_file_without_newline(self):
        out = self.path("manifest.json")
        code, _, err = self.run_cli("manifest", "--bin", self.bin, "--product", "example-psu", "--chip", "esp32c3",
                                    "--version", "1.4.0", "--url", "https://fw.example.com/a/firmware.bin",
                                    "--key-id", "test-only-esp-fleet-ota", "--released-at", "2026-11-22T10:00:00Z", "-o", out)
        self.assertEqual(code, 0, err)
        with open(out, "rb") as f:
            data = f.read()
        self.assertFalse(data.endswith(b"\n"))
        self.assertEqual(json.loads(data)["size"], len(self.image))


class TestLayout(Base):
    """Default layout: manifest per product/chip/channel, image per product/version/chip."""

    def test_image_url_layout(self):
        self.assertEqual(fr.image_url("https://fw.example.com", "example-psu", "1.4.0", "esp32c3"),
                         "https://fw.example.com/example-psu/1.4.0/esp32c3/firmware.bin")
        self.assertEqual(fr.image_url("https://fw.example.com/", "example-psu", "2.0.0-rc.1", "esp32s3"),
                         "https://fw.example.com/example-psu/2.0.0-rc.1/esp32s3/firmware.bin")

    def test_manifest_url_layout(self):
        self.assertEqual(fr.manifest_url("https://fw.example.com", "example-psu", "esp32c3", "stable"),
                         "https://fw.example.com/example-psu/esp32c3/stable/manifest.json")

    def test_layout_rejects_bad_components(self):
        for args in (("https://fw.example.com", "a/b", "1.0.0", "esp32c3"),
                     ("https://fw.example.com", "p", "../1.0.0", "esp32c3"),
                     ("https://fw.example.com", "p", "1.0.0", "ESP32"),
                     ("http://fw.example.com", "p", "1.0.0", "esp32c3")):
            with self.subTest(args=args), self.assertRaises(fr.ReleaseError):
                fr.image_url(*args)

    def test_cli_manifest_derives_image_url_from_base_url(self):
        out = self.path("manifest.json")
        code, stdout, err = self.run_cli("manifest", "--bin", self.bin, "--product", "example-psu", "--chip",
                                         "esp32c3", "--version", "1.4.0", "--base-url", "https://fw.example.com",
                                         "--released-at", "2026-11-22T10:00:00Z", "-o", out)
        self.assertEqual(code, 0, err)
        with open(out, "rb") as f:
            m = json.loads(f.read())
        self.assertEqual(m["url"], "https://fw.example.com/example-psu/1.4.0/esp32c3/firmware.bin")
        self.assertEqual(m["key_id"], fr.DEFAULT_KEY_ID)
        self.assertEqual(fr.DEFAULT_KEY_ID, "esp-fleet-ota")
        self.assertIn("https://fw.example.com/example-psu/1.4.0/esp32c3/firmware.bin", stdout)
        self.assertIn("https://fw.example.com/example-psu/esp32c3/stable/manifest.json", stdout)

    def test_cli_manifest_requires_base_url_or_url(self):
        # no hard-coded firmware host: the publisher must say where the image lives
        self.assertFalse(hasattr(fr, "DEFAULT_BASE_URL"))
        out = self.path("manifest.json")
        code, _, err = self.run_cli("manifest", "--bin", self.bin, "--product", "example-psu", "--chip", "esp32c3",
                                    "--version", "1.4.0", "--released-at", "2026-11-22T10:00:00Z", "-o", out)
        self.assertNotEqual(code, 0)
        self.assertIn("--base-url", err)
        self.assertFalse(os.path.exists(out))
        self.assertNotIn("default", fr.subparser(fr.build_parser(), "manifest").format_help().split("--base-url")[1]
                         .split("--")[0])

    def test_cli_manifest_with_url_only_does_not_print_manifest_location(self):
        out = self.path("manifest.json")
        code, stdout, err = self.run_cli("manifest", "--bin", self.bin, "--product", "example-psu", "--chip",
                                         "esp32c3", "--version", "1.4.0", "--url", "https://fw.example.com/x/fw.bin",
                                         "--released-at", "2026-11-22T10:00:00Z", "-o", out)
        self.assertEqual(code, 0, err)
        self.assertIn("https://fw.example.com/x/fw.bin", stdout)
        self.assertNotIn("manifest.json (+ .sig)", stdout)

    def test_cli_manifest_base_url_and_explicit_url(self):
        out = self.path("manifest.json")
        code, _, err = self.run_cli("manifest", "--bin", self.bin, "--product", "p", "--chip", "esp32s3",
                                    "--version", "1.0.0", "--channel", "beta", "--base-url", "https://mirror.example.org",
                                    "--released-at", "2026-11-22T10:00:00Z", "-o", out)
        self.assertEqual(code, 0, err)
        with open(out, "rb") as f:
            self.assertEqual(json.loads(f.read())["url"], "https://mirror.example.org/p/1.0.0/esp32s3/firmware.bin")
        code, _, err = self.run_cli("manifest", "--bin", self.bin, "--product", "p", "--chip", "esp32s3",
                                    "--version", "1.0.0", "--url", "https://fw.example.com/any/where.bin",
                                    "--released-at", "2026-11-22T10:00:00Z", "-o", out)
        self.assertEqual(code, 0, err)
        with open(out, "rb") as f:
            self.assertEqual(json.loads(f.read())["url"], "https://fw.example.com/any/where.bin")


class TestSignOpenBao(Base):
    def transit_reply(self, sig_text):
        return FakeTransitResponse(json.dumps({"data": {"signature": sig_text, "key_version": 3}}).encode())

    def fake_transit(self, captured, version=3):
        key = self.key

        def urlopen(req, timeout=None, context=None):
            captured["url"] = req.full_url
            captured["headers"] = dict(req.header_items())
            body = json.loads(req.data)
            captured["body"] = body
            msg = base64.b64decode(body["input"])
            der = key.sign(msg, ec.ECDSA(hashes.SHA256()))
            return self.transit_reply("vault:v%d:%s" % (version, base64.b64encode(der).decode()))
        return urlopen

    def test_http_transit_sign_uses_env_only(self):
        manifest = self.build_manifest()
        captured = {}
        env = {"BAO_ADDR": "https://bao.example.org:8200", "BAO_TOKEN": "s.testtoken"}
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(fr.urllib.request, "urlopen", self.fake_transit(captured)):
            sig = fr.sign_openbao_http(manifest, key_name="test-only-esp-fleet-ota", mount="transit")
        self.assertTrue(sig.startswith("vault:v3:"))
        self.assertEqual(captured["url"], "https://bao.example.org:8200/v1/transit/sign/test-only-esp-fleet-ota/sha2-256")
        self.assertEqual(captured["headers"].get("X-vault-token"), "s.testtoken")
        self.assertEqual(captured["body"]["marshaling_algorithm"], "asn1")
        self.assertNotIn("prehashed", captured["body"])
        self.assertEqual(base64.b64decode(captured["body"]["input"]), manifest)    # exact bytes
        self.assertEqual(fr.verify_bytes(manifest, sig, pub_pem(self.key), key_version=3), 3)

    def test_vault_env_names_accepted(self):
        captured = {}
        env = {"VAULT_ADDR": "https://vault.example.org", "VAULT_TOKEN": "t"}
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(fr.urllib.request, "urlopen", self.fake_transit(captured)):
            fr.sign_openbao_http(self.build_manifest(), key_name="k")
        self.assertTrue(captured["url"].startswith("https://vault.example.org/v1/transit/sign/k/"))

    def test_missing_env_refused(self):
        for env in ({}, {"BAO_ADDR": "https://x"}, {"BAO_TOKEN": "t"}):
            with self.subTest(env=env), mock.patch.dict(os.environ, env, clear=True), \
                    self.assertRaises(fr.ReleaseError):
                fr.sign_openbao_http(b"{}", key_name="k")

    def test_plain_http_refused_except_loopback(self):
        with mock.patch.dict(os.environ, {"BAO_ADDR": "http://bao.example.org", "BAO_TOKEN": "t"}, clear=True), \
                self.assertRaises(fr.ReleaseError):
            fr.sign_openbao_http(b"{}", key_name="k")

    def test_no_token_argument_exists(self):
        parser = fr.build_parser()
        help_text = parser.format_help()
        for sub in ("sign", "manifest", "verify"):
            sp = fr.subparser(parser, sub)
            self.assertNotIn("--token", sp.format_help())
        self.assertNotIn("--token", help_text)

    def test_cli_sign_writes_sig_and_verifies_with_public_key(self):
        man = self.path("manifest.json")
        with open(man, "wb") as f:
            f.write(self.build_manifest())
        captured = {}
        env = {"BAO_ADDR": "https://bao.example.org", "BAO_TOKEN": "t"}
        with mock.patch.object(fr.urllib.request, "urlopen", self.fake_transit(captured)):
            code, out, err = self.run_cli("sign", "--manifest", man, "--key-name", "test-only-esp-fleet-ota",
                                          "--public-key", self.pub, "--key-version", "3", env=env)
        self.assertEqual(code, 0, err)
        with open(man + ".sig") as f:
            sig = f.read()
        self.assertTrue(sig.startswith("vault:v3:") and sig.endswith("\n"))
        self.assertNotIn("t\n", out + err)                            # token never printed

    def test_cli_sign_refuses_wrong_key_version(self):
        man = self.path("manifest.json")
        with open(man, "wb") as f:
            f.write(self.build_manifest())
        env = {"BAO_ADDR": "https://bao.example.org", "BAO_TOKEN": "t"}
        with mock.patch.object(fr.urllib.request, "urlopen", self.fake_transit({}, version=4)):
            code, _, err = self.run_cli("sign", "--manifest", man, "--key-name", "test-only-esp-fleet-ota",
                                        "--public-key", self.pub, "--key-version", "3", env=env)
        self.assertNotEqual(code, 0)
        self.assertFalse(os.path.exists(man + ".sig"))

    def test_bao_cli_backend(self):
        manifest = self.build_manifest()
        key = self.key

        def fake_run(cmd, input=None, capture_output=None, check=None, env=None, timeout=None):
            self.assertEqual(cmd[:3], ["bao", "write", "-field=signature"])
            self.assertIn("transit/sign/test-only-esp-fleet-ota/sha2-256", cmd)
            self.assertIn("marshaling_algorithm=asn1", cmd)
            self.assertFalse(any("token" in c.lower() for c in cmd))   # token comes from the environment
            arg = [c for c in cmd if c.startswith("input=")][0]
            der = key.sign(base64.b64decode(arg[len("input="):]), ec.ECDSA(hashes.SHA256()))
            return subprocess.CompletedProcess(cmd, 0, stdout=("vault:v1:" + base64.b64encode(der).decode() + "\n").encode(),
                                               stderr=b"")
        env = {"BAO_ADDR": "https://bao.example.org", "BAO_TOKEN": "t"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(fr.subprocess, "run", fake_run):
            sig = fr.sign_openbao_cli(manifest, key_name="test-only-esp-fleet-ota")
        self.assertEqual(fr.verify_bytes(manifest, sig, pub_pem(key), key_version=1), 1)

    def test_bao_cli_refuses_without_env_token(self):
        # without BAO_TOKEN/VAULT_TOKEN the bao CLI would fall back to its token helper file (~/.vault-token)
        calls = []
        for env in ({}, {"BAO_ADDR": "https://bao.example.org"}, {"BAO_TOKEN": "t"}):
            with self.subTest(env=env), mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(fr.subprocess, "run", lambda *a, **k: calls.append(a)), \
                    self.assertRaises(fr.ReleaseError):
                fr.sign_openbao_cli(b"{}", key_name="k")
        self.assertEqual(calls, [])


class TestLocalAndVerify(Base):
    def setUp(self):
        super().setUp()
        self.priv = self.path("test-only-key.pem")
        with open(self.priv, "wb") as f:
            f.write(priv_pem(self.key))

    def test_local_sign_is_bare_base64(self):
        m = self.build_manifest()
        sig = fr.sign_local(m, self.priv)
        self.assertNotIn(":", sig)
        base64.b64decode(sig, validate=True)
        self.assertEqual(fr.verify_bytes(m, sig, pub_pem(self.key)), 0)

    def test_verify_rejects_tampering_and_wrong_key(self):
        m = self.build_manifest()
        sig = fr.sign_local(m, self.priv)
        with self.assertRaises(fr.ReleaseError):
            fr.verify_bytes(m + b"\n", sig, pub_pem(self.key))          # trailing newline in manifest
        with self.assertRaises(fr.ReleaseError):
            fr.verify_bytes(m.replace(b"esp32c3", b"esp32s3"), sig, pub_pem(self.key))
        with self.assertRaises(fr.ReleaseError):
            fr.verify_bytes(m, sig, pub_pem(make_key()))
        self.assertEqual(fr.verify_bytes(m, sig + "\n  ", pub_pem(self.key)), 0)   # whitespace in .sig is fine

    def test_verify_key_version_rules(self):
        m = self.build_manifest()
        der = self.key.sign(m, ec.ECDSA(hashes.SHA256()))
        vault = "vault:v2:" + base64.b64encode(der).decode()
        self.assertEqual(fr.verify_bytes(m, vault, pub_pem(self.key), key_version=2), 2)
        with self.assertRaises(fr.ReleaseError):
            fr.verify_bytes(m, vault, pub_pem(self.key), key_version=1)
        with self.assertRaises(fr.ReleaseError):                       # bare sig for a vault key entry
            fr.verify_bytes(m, base64.b64encode(der).decode(), pub_pem(self.key), key_version=2)
        for bad in ("vault:v0:QQ==", "vault:vx:QQ==", "nope!", ""):
            with self.subTest(bad=bad), self.assertRaises(fr.ReleaseError):
                fr.verify_bytes(m, bad, pub_pem(self.key))

    def test_verify_rejects_non_p256_key(self):
        m = self.build_manifest()
        k = ec.generate_private_key(ec.SECP384R1())
        der = k.sign(m, ec.ECDSA(hashes.SHA256()))
        with self.assertRaises(fr.ReleaseError):
            fr.verify_bytes(m, base64.b64encode(der).decode(), pub_pem(k))

    def test_cli_verify_checks_binary_too(self):
        man = self.path("manifest.json")
        with open(man, "wb") as f:
            f.write(self.build_manifest())
        code, _, err = self.run_cli("sign", "--manifest", man, "--local-key", self.priv)
        self.assertEqual(code, 0, err)
        code, out, err = self.run_cli("verify", "--manifest", man, "--public-key", self.pub, "--bin", self.bin)
        self.assertEqual(code, 0, err)
        self.assertIn("OK", out)
        with open(self.bin, "ab") as f:
            f.write(b"x")
        code, _, err = self.run_cli("verify", "--manifest", man, "--public-key", self.pub, "--bin", self.bin)
        self.assertNotEqual(code, 0)

    def test_wrap_der_for_breakglass(self):
        m = self.build_manifest()
        der_path = self.path("sig.der")
        with open(der_path, "wb") as f:
            f.write(self.key.sign(m, ec.ECDSA(hashes.SHA256())))
        man = self.path("manifest.json")
        with open(man, "wb") as f:
            f.write(m)
        code, _, err = self.run_cli("sign", "--manifest", man, "--der-signature", der_path, "--public-key", self.pub)
        self.assertEqual(code, 0, err)
        with open(man + ".sig") as f:
            self.assertEqual(fr.verify_bytes(m, f.read(), pub_pem(self.key)), 0)

    def test_c_key_table_output(self):
        code, out, err = self.run_cli("c-key", "--public-key", self.pub, "--key-id", "test-only-esp-fleet-ota",
                                      "--key-version", "1", "--name", "kTestOnlyV1")
        self.assertEqual(code, 0, err)
        self.assertIn('{"test-only-esp-fleet-ota", 1,', out)
        self.assertIn("-----BEGIN PUBLIC KEY-----", out)


if __name__ == "__main__":
    unittest.main()
