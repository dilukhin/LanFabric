#!/usr/bin/env python3
"""Локальные проверки сохранения и строгой валидации профилей AWG."""

import base64
import importlib.util
import os
import tempfile
import unittest
from unittest.mock import patch


_SRV_PATH = os.path.join(os.path.dirname(__file__), "..", "vsrv-admin.py")
_spec = importlib.util.spec_from_file_location("vsrv_admin_awg31", _SRV_PATH)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


def legacy_params():
    return dict(Jc=7, Jmin=40, Jmax=90, S1=15, S2=15, H1=5, H2=6, H3=7, H4=8)


class TestAwg31Params(unittest.TestCase):

    def test_generator_has_complete_upstream_profile_and_fresh_key(self):
        first = srv.generate_awg_params("awg31")
        second = srv.generate_awg31_params()
        self.assertEqual(set(first), set(srv.AWG31_PARAM_KEYS))
        self.assertNotEqual(first["HeaderProtectionKey"], second["HeaderProtectionKey"])
        self.assertEqual(len(base64.b64decode(first["HeaderProtectionKey"], validate=True)), 32)
        self.assertEqual(srv.validate_awg_params(first), first)
        self.assertTrue(4 <= first["Jc"] <= 6)
        for key in ("S1", "S2", "S3", "S4"):
            self.assertEqual(first[key], 12)

    def test_legacy_default_remains_compatible(self):
        self.assertEqual(set(srv.generate_awg_params()), set(srv.AWG_PARAM_KEYS))
        params = legacy_params()
        self.assertEqual(srv.validate_awg_params(params), params)
        self.assertEqual(len(srv.format_awg_params(params).splitlines()), 9)

    def test_modern_roundtrip_export_and_setconf_preserve_every_field(self):
        params = srv.generate_awg31_params()
        params["H1"] = "100-110"
        with tempfile.TemporaryDirectory() as tmp:
            state = os.path.join(tmp, "awg_params")
            pub = os.path.join(tmp, "wg0.public")
            with open(pub, "w") as file:
                file.write("A" * 43 + "=")
            with patch.object(srv, "AWG_PARAMS_PATH", state), patch.object(srv, "REMOTE_DIR", tmp), \
                 patch.object(srv, "WG_DIR", tmp), patch.object(srv, "require_backend", return_value="awg"):
                srv.write_awg_params_file(params)
                self.assertEqual(srv.read_awg_params_file(), params)
                self.assertEqual(os.stat(state).st_mode & 0o777, 0o600)
                server = srv.build_setconf("B" * 43 + "=", "awg")
                row = dict(privkey="C" * 43 + "=", ip="10.8.0.2", internet=1)
                # build_client_config сохраняет прежний абсолютный путь public key.
                original_open = open
                def read_public(path, *args, **kwargs):
                    if path == "/etc/wireguard/wg0.public":
                        path = pub
                    return original_open(path, *args, **kwargs)
                with patch("builtins.open", side_effect=read_public):
                    client = srv.build_client_config(row, endpoint="198.51.100.42")
                for key, value in params.items():
                    self.assertIn(f"{key} = {value}\n", server)
                    self.assertIn(f"{key} = {value}\n", client)

    def test_unknown_cps_and_duplicate_fields_fail_without_values(self):
        secret = "sensitive-value-do-not-include"
        for key in ("I1", "UnknownParameter"):
            params = dict(legacy_params(), **{key: secret})
            with self.assertRaises(RuntimeError) as caught:
                srv.validate_awg_params(params)
            self.assertNotIn(secret, str(caught.exception))
        with tempfile.TemporaryDirectory() as tmp:
            state = os.path.join(tmp, "awg_params")
            for content in (f"HeaderProtectionKey = {secret}\nHeaderProtectionKey = {secret}\n", secret):
                with open(state, "w") as file:
                    file.write(content)
                with patch.object(srv, "AWG_PARAMS_PATH", state):
                    with self.assertRaises(RuntimeError) as caught:
                        srv.read_awg_params_file()
                self.assertNotIn(secret, str(caught.exception))

    def test_incomplete_modern_profile_is_not_treated_as_legacy(self):
        for missing in srv.AWG31_PARAM_KEYS:
            params = srv.generate_awg31_params()
            del params[missing]
            with self.subTest(missing=missing), self.assertRaises(RuntimeError):
                srv.validate_awg_params(params)
        with self.assertRaises(RuntimeError):
            srv.validate_awg_params(dict(legacy_params(), S3=12))

    def test_key_errors_never_include_supplied_value(self):
        for value in ("sensitive-not-base64", base64.b64encode(b"short").decode(), "a\nsecret"):
            params = dict(srv.generate_awg31_params(), HeaderProtectionKey=value)
            with self.assertRaises(RuntimeError) as caught:
                srv.validate_awg_params(params)
            self.assertNotIn(value, str(caught.exception))

    def test_range_bounds_and_overlap_are_rejected(self):
        bad = {"S3": 11, "S4": 65536, "H1": "1-2", "H3": "4294967296", 
               "RekeyTimeout": "7-3", "ContentPaddingAddition": "0-65536",
               "RandomTrailers": "yes", "Jc": "1\nPrivateKey=secret"}
        for key, value in bad.items():
            params = dict(srv.generate_awg31_params(), **{key: value})
            with self.subTest(key=key), self.assertRaises(RuntimeError) as caught:
                srv.validate_awg_params(params)
            self.assertNotIn("PrivateKey=secret", str(caught.exception))
        params = dict(srv.generate_awg31_params(), H1="100-110", H2="111-120")
        self.assertEqual(srv.validate_awg_params(params)["H1"], "100-110")

    def test_legacy_header_and_size_limits_are_preserved(self):
        for changes in (dict(H1=1), dict(H1="5-6"), dict(S1=1133), dict(Jc=129)):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                srv.validate_awg_params(dict(legacy_params(), **changes))

    def test_existing_state_is_never_regenerated_or_rewritten(self):
        for profile, params in (("legacy", legacy_params()), ("awg31", srv.generate_awg31_params())):
            with tempfile.TemporaryDirectory() as tmp:
                state = os.path.join(tmp, "awg_params")
                text = "# Сохранённый профиль\n" + srv.format_awg_params(params) + "\n"
                with open(state, "w") as file:
                    file.write(text)
                with patch.object(srv, "AWG_PARAMS_PATH", state), \
                     patch.object(srv, "generate_awg_params") as generate, \
                     patch.object(srv, "write_awg_params_file") as write:
                    self.assertEqual(srv.get_or_create_awg_params(profile), params)
                    with self.assertRaises(RuntimeError):
                        srv.get_or_create_awg_params("awg31" if profile == "legacy" else "legacy")
                    generate.assert_not_called()
                    write.assert_not_called()
                with open(state) as file:
                    self.assertEqual(file.read(), text)

    def test_bad_profile_is_rejected_before_file_reads(self):
        with patch.object(srv, "read_awg_params_file") as read:
            with self.assertRaises(RuntimeError):
                srv.get_or_create_awg_params("unknown")
            read.assert_not_called()
        with self.assertRaises(RuntimeError):
            srv.generate_awg_params("unknown")


if __name__ == "__main__":
    unittest.main()
