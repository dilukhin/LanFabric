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
            patch.object(srv.os, "fchmod", create=True) as fchmod,
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


class TestInternetNatInterface(unittest.TestCase):

    def test_uses_interface_from_ipv4_route(self):
        with patch.object(srv, "run_cmd", return_value="1.1.1.1 via 95.81.118.129 dev ens3 src 95.81.118.143"):
            self.assertEqual(srv.get_wan_interface(), "ens3")

    def test_rejects_missing_or_vpn_interface(self):
        for route in ("", "1.1.1.1 dev wg0 src 10.8.0.1", "1.1.1.1 dev bad;name"):
            with self.subTest(route=route), patch.object(srv, "run_cmd", return_value=route):
                with self.assertRaises(RuntimeError):
                    srv.get_wan_interface()

    def test_internet_rules_use_real_interface_and_keep_drop_last(self):
        commands = []
        with (
            patch.object(srv, "get_wan_interface", return_value="ens3"),
            patch.object(srv, "delete_iptables_rule", side_effect=commands.append),
            patch.object(srv, "ensure_iptables_rule", side_effect=commands.append),
        ):
            srv.ensure_client_internet_rules("10.8.0.2")
        self.assertIn("iptables -t nat -A POSTROUTING -s 10.8.0.2 -o ens3 -j MASQUERADE", commands)
        self.assertEqual(commands[-1], "iptables -A FORWARD -i wg0 -j DROP")

    def test_missing_route_does_not_change_forward_rules(self):
        with (
            patch.object(srv, "get_wan_interface", side_effect=RuntimeError("маршрут отсутствует")),
            patch.object(srv, "delete_iptables_rule") as delete_rule,
            patch.object(srv, "ensure_iptables_rule") as ensure_rule,
        ):
            with self.assertRaises(RuntimeError):
                srv.ensure_client_internet_rules("10.8.0.2")
        delete_rule.assert_not_called()
        ensure_rule.assert_not_called()

    def test_removes_only_exact_client_nat_rules_without_route(self):
        rules = []
        with (
            patch.object(srv, "run_cmd", return_value="\n".join((
                "-A POSTROUTING -s 10.8.0.2/32 -o ens3 -j MASQUERADE",
                "-A POSTROUTING -s 10.8.0.2/32 -o eth0 -j MASQUERADE",
                "-A POSTROUTING -s 10.8.0.3/32 -o ens3 -j MASQUERADE",
                "-A POSTROUTING -s 10.8.0.2/32 -o ens3 -j ACCEPT",
                "-A POSTROUTING -s 10.8.0.2/32 -o wg0 -j MASQUERADE",
            ))),
            patch.object(srv, "delete_iptables_rule", side_effect=rules.append),
        ):
            srv.delete_client_nat_rules("10.8.0.2")
        self.assertEqual(rules, [
            "iptables -t nat -A POSTROUTING -s 10.8.0.2 -o ens3 -j MASQUERADE",
            "iptables -t nat -A POSTROUTING -s 10.8.0.2 -o eth0 -j MASQUERADE",
        ])


if __name__ == "__main__":
    unittest.main()
