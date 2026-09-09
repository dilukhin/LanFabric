#!/usr/bin/env python3
"""Unit-тесты Windows-адаптации full-tunnel без реального сервера и API Windows."""

import importlib.util
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


_CLI_PATH = os.path.join(os.path.dirname(__file__), "..", "vcli-admin.py")
_SPEC = importlib.util.spec_from_file_location("vcli_admin_windows_test", _CLI_PATH)
cli = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cli)


class WindowsFullTunnelTests(unittest.TestCase):
    def setUp(self):
        self.config = (
            "[Interface]\n"
            "PrivateKey = PRIVATE-KEY-MUST-NOT-CHANGE\n"
            "Address = 10.8.0.4/32\n"
            "Jc = 3\nJmin = 10\nJmax = 50\nS1 = 1\nS2 = 2\n"
            "H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n"
            "[Peer]\n"
            "PublicKey = PUBLIC-KEY\n"
            "Endpoint = 198.51.100.42:51820\n"
            "AllowedIPs = 0.0.0.0/0\n"
        )

    def test_exact_full_tunnel_is_adapted(self):
        self.assertTrue(cli.is_ipv4_full_tunnel(self.config))
        adapted = cli.adapt_windows_full_tunnel(self.config)
        self.assertIn("AllowedIPs = 0.0.0.0/1, 128.0.0.0/1\n", adapted)

    def test_whitespace_is_handled_and_other_lines_are_unchanged(self):
        source = "Before\n  AllowedIPs   =   0.0.0.0/0  \nAfter\n"
        self.assertEqual(
            cli.adapt_windows_full_tunnel(source),
            "Before\n  AllowedIPs   =   0.0.0.0/1, 128.0.0.0/1  \nAfter\n",
        )

    def test_split_and_unrelated_allowed_ips_are_unchanged(self):
        for allowed_ips in ("10.8.0.0/24", "10.8.0.0/25, 10.8.0.128/25", "::/0"):
            source = f"AllowedIPs = {allowed_ips}\n"
            self.assertFalse(cli.is_ipv4_full_tunnel(source))
            self.assertEqual(cli.adapt_windows_full_tunnel(source), source)

    def test_sensitive_and_awg_lines_are_preserved(self):
        adapted = cli.adapt_windows_full_tunnel(self.config)
        for line in (
            "PrivateKey = PRIVATE-KEY-MUST-NOT-CHANGE\n",
            "Endpoint = 198.51.100.42:51820\n",
            "Jc = 3\n", "Jmin = 10\n", "Jmax = 50\n", "S1 = 1\n", "S2 = 2\n",
            "H1 = 1\n", "H2 = 2\n", "H3 = 3\n", "H4 = 4\n",
        ):
            self.assertIn(line, adapted)
        self.assertTrue(adapted.endswith("\n"))

    def test_cmd_config_windows_writes_adapted_content_and_checks_route(self):
        args = SimpleNamespace(
            name="bob-e2e", host="198.51.100.42", user="donpedro", auth="key",
            key="test-key", debug=False,
        )
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(cli, "ensure_remote_version_compatible"), \
                patch.object(cli, "exec_remote", return_value=self.config), \
                patch.object(cli, "ensure_windows_endpoint_route") as route, \
                patch.object(cli.platform, "system", return_value="Windows"), \
                patch.object(cli.os, "chmod"):
            old_dir = os.getcwd()
            try:
                os.chdir(temp_dir)
                cli.cmd_config(args)
            finally:
                os.chdir(old_dir)
            with open(os.path.join(temp_dir, "bob-e2e.conf"), encoding="utf-8") as config_file:
                saved = config_file.read()
        self.assertIn("AllowedIPs = 0.0.0.0/1, 128.0.0.0/1\n", saved)
        self.assertNotIn("AllowedIPs = 0.0.0.0/0", saved)
        route.assert_called_once_with(args, allow_elevate=True)

    def test_cmd_config_non_windows_preserves_server_full_tunnel(self):
        args = SimpleNamespace(
            name="bob-e2e", host="198.51.100.42", user="donpedro", auth="key",
            key="test-key", debug=False,
        )
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(cli, "ensure_remote_version_compatible"), \
                patch.object(cli, "exec_remote", return_value=self.config), \
                patch.object(cli, "ensure_windows_endpoint_route") as route, \
                patch.object(cli.platform, "system", return_value="Linux"), \
                patch.object(cli.os, "chmod"):
            old_dir = os.getcwd()
            try:
                os.chdir(temp_dir)
                cli.cmd_config(args)
            finally:
                os.chdir(old_dir)
            with open(os.path.join(temp_dir, "bob-e2e.conf"), encoding="utf-8") as config_file:
                saved = config_file.read()
        self.assertIn("AllowedIPs = 0.0.0.0/0\n", saved)
        route.assert_not_called()


if __name__ == "__main__":
    unittest.main()
