#!/usr/bin/env python3
"""Локальные regression-тесты инициализации LanFabric."""

import importlib.util
import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, call, mock_open, patch


_SRV_PATH = os.path.join(os.path.dirname(__file__), "..", "vsrv-admin.py")
_spec = importlib.util.spec_from_file_location("vsrv_admin", _SRV_PATH)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


class TestAmneziaInstall(unittest.TestCase):

    def test_amnezia_install_preserves_existing_dkms_config_noninteractively(self):
        commands = []

        class StopAfterPackages(Exception):
            pass

        def run_cmd(command, check=True):
            commands.append((command, check))
            if "iptables-persistent" in command:
                raise StopAfterPackages
            return ""

        with patch.object(srv, "ensure_dirs"), patch.object(srv, "run_cmd", side_effect=run_cmd):
            with self.assertRaises(StopAfterPackages):
                srv.cmd_init(SimpleNamespace(no_amnezia=False))

        install_line = next(
            command for command, _ in commands
            if "install -y amneziawg" in command
        )

        self.assertIn("DEBIAN_FRONTEND=noninteractive", install_line)
        self.assertIn("--force-confdef", install_line)
        self.assertIn("--force-confold", install_line)

    def test_no_amnezia_does_not_install_amnezia_packages(self):
        commands = []

        class StopAfterPackages(Exception):
            pass

        def run_cmd(command, check=True):
            commands.append(command)
            if "iptables-persistent" in command:
                raise StopAfterPackages
            return ""

        with patch.object(srv, "ensure_dirs"), patch.object(srv, "run_cmd", side_effect=run_cmd):
            with self.assertRaises(StopAfterPackages):
                srv.cmd_init(SimpleNamespace(no_amnezia=True))

        self.assertTrue(any("install -y wireguard" in command for command in commands))
        self.assertFalse(any("install -y amneziawg" in command for command in commands))


class TestInitDirectories(unittest.TestCase):

    def test_ensure_dirs_creates_state_and_wireguard_directories(self):
        state_dir = Mock()
        wireguard_dir = Mock()
        with patch.object(srv, "Path", side_effect=[state_dir, wireguard_dir]) as path_mock:
            srv.ensure_dirs()

        self.assertEqual(
            [call(srv.CONF_DIR), call(srv.WG_DIR)],
            path_mock.call_args_list,
        )
        state_dir.mkdir.assert_called_once_with(parents=True, exist_ok=True)
        wireguard_dir.mkdir.assert_called_once_with(parents=True, exist_ok=True, mode=0o700)
        wireguard_dir.chmod.assert_called_once_with(0o700)

    def test_private_file_is_created_with_restricted_permissions(self):
        file_handle = mock_open()
        with (
            patch.object(srv.os, "open", return_value=42) as os_open,
            patch.object(srv.os, "fchmod") as fchmod,
            patch.object(srv.os, "fdopen", return_value=file_handle()) as fdopen,
        ):
            srv.write_private_file("/etc/wireguard/wg0.private", "secret")

        os_open.assert_called_once_with(
            "/etc/wireguard/wg0.private",
            srv.os.O_WRONLY | srv.os.O_CREAT | srv.os.O_TRUNC,
            0o600,
        )
        fchmod.assert_called_once_with(42, 0o600)
        fdopen.assert_called_once_with(42, "w", encoding="utf-8")
        file_handle().write.assert_called_once_with("secret")


class TestServerVersion(unittest.TestCase):

    def test_server_version_is_0_0_17(self):
        self.assertEqual(srv.__version__, "0.0.17")


if __name__ == "__main__":
    unittest.main()
