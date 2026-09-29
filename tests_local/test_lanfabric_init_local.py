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

    def route_output(self, command, check=True):
        if command == "ip -4 rule show":
            return "0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default"
        if command == "ip -4 route show table main default" or command.startswith("ip -4 route show table main match "):
            return "default via 95.81.118.129 dev ens3 onlink"
        if command.startswith("ip -4 route get "):
            return command.split()[4] + " via 95.81.118.129 dev ens3 src 95.81.118.143"
        if command == "ip -d -j link show dev ens3":
            return '[{"ifname":"ens3","link_type":"ether","flags":["UP","LOWER_UP"]}]'
        raise AssertionError(command)

    def test_uses_unambiguous_forwarded_ipv4_route(self):
        with patch.object(srv, "run_cmd", side_effect=self.route_output) as run:
            self.assertEqual(srv.get_wan_interface("10.8.0.2"), "ens3")
        self.assertTrue(any("from 10.8.0.2 iif wg0" in c.args[0] for c in run.call_args_list))

    def test_rejects_specific_probe_route_and_nonphysical_interface(self):
        def specific(command, check=True):
            if command.endswith("match 1.1.1.1/32"):
                return "1.1.1.1 via 95.81.118.129 dev ens3"
            return self.route_output(command, check)

        with patch.object(srv, "run_cmd", side_effect=specific):
            with self.assertRaises(RuntimeError):
                srv.get_wan_interface("10.8.0.2")

        def tunnel(command, check=True):
            if command == "ip -d -j link show dev ens3":
                return '[{"ifname":"ens3","link_type":"none","flags":["UP"]}]'
            return self.route_output(command, check)

        with patch.object(srv, "run_cmd", side_effect=tunnel):
            with self.assertRaises(RuntimeError):
                srv.get_wan_interface("10.8.0.2")

    def test_rejects_lo_and_extra_routing_policy(self):
        def loopback(command, check=True):
            if command.startswith("ip -4 route get "):
                return "local 1.1.1.1 dev lo"
            return self.route_output(command, check)

        with patch.object(srv, "run_cmd", side_effect=loopback):
            with self.assertRaises(RuntimeError):
                srv.get_wan_interface("10.8.0.2")

        def policy(command, check=True):
            if command == "ip -4 rule show":
                return self.route_output(command) + "\n100: from 10.8.0.0/24 lookup other"
            return self.route_output(command, check)

        with patch.object(srv, "run_cmd", side_effect=policy):
            with self.assertRaises(RuntimeError):
                srv.get_wan_interface("10.8.0.2")

        def virtual_ether(command, check=True):
            if command == "ip -d -j link show dev ens3":
                return '[{"ifname":"ens3","link_type":"ether","linkinfo":{"info_kind":"vxlan"},"flags":["UP"]}]'
            return self.route_output(command, check)

        with patch.object(srv, "run_cmd", side_effect=virtual_ether):
            with self.assertRaises(RuntimeError):
                srv.get_wan_interface("10.8.0.2")

    def test_internet_rules_use_real_interface_and_keep_drop_last(self):
        commands = []
        with (
            patch.object(srv, "get_wan_interface", return_value="ens3"),
            patch.object(srv, "list_client_nat_rules", return_value=[]),
            patch.object(srv, "delete_iptables_rule", side_effect=commands.append),
            patch.object(srv, "ensure_iptables_rule", side_effect=commands.append),
            patch.object(srv, "verify_client_internet_rules") as verify,
        ):
            srv.ensure_client_internet_rules("10.8.0.2")
        self.assertIn(srv.client_nat_rule("10.8.0.2", "ens3"), commands)
        self.assertEqual(commands[-1], "iptables -A FORWARD -i wg0 -j DROP")
        verify.assert_called_once_with("10.8.0.2", "ens3")

    def test_forward_accept_after_drop_is_rejected(self):
        rules = "-A FORWARD -i wg0 -j DROP\n-A FORWARD -s 10.8.0.2/32 -m comment --comment lanfabric-client-forward-v1 -j ACCEPT"
        with (
            patch.object(srv, "list_client_nat_rules", return_value=["ens3"]),
            patch.object(srv, "run_cmd", return_value=rules),
        ):
            with self.assertRaisesRegex(RuntimeError, "после DROP"):
                srv.verify_client_internet_rules("10.8.0.2", "ens3")

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

    def test_foreign_rule_identical_except_marker_is_preserved(self):
        foreign = "-A POSTROUTING -s 10.8.0.2/32 -o ens3 -j MASQUERADE"
        with patch.object(srv, "run_cmd", return_value=foreign), patch.object(srv, "delete_iptables_rule") as delete:
            with self.assertRaisesRegex(RuntimeError, "принадлежность"):
                srv.delete_client_nat_rules("10.8.0.2")
        delete.assert_not_called()

    def test_deletes_only_owned_nat_on_old_and_new_interfaces(self):
        old = "-A POSTROUTING -s 10.8.0.2/32 -o eth0 -m comment --comment lanfabric-client-nat-v1 -j MASQUERADE"
        new = "-A POSTROUTING -s 10.8.0.2/32 -o ens3 -m comment --comment lanfabric-client-nat-v1 -j MASQUERADE"
        foreign = "-A POSTROUTING -s 10.8.0.3/32 -o ens3 -j MASQUERADE"
        commands = []

        def iptables(command, check=True):
            commands.append(command)
            if command == "iptables -t nat -S POSTROUTING":
                return "\n".join([old, new, foreign]) if not any(" -D POSTROUTING " in c for c in commands) else foreign
            return ""

        with patch.object(srv, "run_cmd", side_effect=iptables):
            srv.delete_client_nat_rules("10.8.0.2")
        self.assertEqual(len([c for c in commands if " -D POSTROUTING " in c]), 2)
        self.assertNotIn("10.8.0.3", " ".join(c for c in commands if " -D POSTROUTING " in c))

    def test_failed_nat_delete_is_not_reported_as_success(self):
        owned = "-A POSTROUTING -s 10.8.0.2/32 -o ens3 -m comment --comment lanfabric-client-nat-v1 -j MASQUERADE"
        with patch.object(srv, "run_cmd", return_value=owned):
            with self.assertRaises(RuntimeError):
                srv.delete_client_nat_rules("10.8.0.2")

    def test_failed_forward_delete_is_not_reported_as_success(self):
        owned = "-A FORWARD -s 10.8.0.2/32 -m comment --comment lanfabric-client-forward-v1 -j ACCEPT"
        with patch.object(srv, "run_cmd", return_value=owned):
            with self.assertRaises(RuntimeError):
                srv.delete_client_forward_rules("10.8.0.2")


class TestInternetLifecycleSafety(unittest.TestCase):

    def test_add_internet_without_route_does_not_create_user_or_peer(self):
        conn = Mock()
        conn.execute.return_value.fetchone.return_value = None
        args = SimpleNamespace(name="bob", admin=False, internet=True, block=False, comment="")
        with (
            patch.object(srv, "init_db", return_value=conn),
            patch.object(srv, "allocate_ip", return_value="10.8.0.2"),
            patch.object(srv, "get_wan_interface", side_effect=RuntimeError("нет WAN")),
            patch.object(srv, "run_cmd") as run,
        ):
            with self.assertRaises(RuntimeError):
                srv.cmd_add(args)
        self.assertEqual(conn.execute.call_count, 1)
        conn.commit.assert_not_called()
        run.assert_not_called()

    def test_add_reports_partial_db_write_without_enabling_peer_if_wan_changes(self):
        conn = Mock()
        conn.execute.return_value.fetchone.return_value = None
        args = SimpleNamespace(name="bob", admin=False, internet=True, block=False, comment="")
        commands = []

        def run(command, check=True):
            commands.append(command)
            return "testkey"

        with (
            patch.object(srv, "init_db", return_value=conn),
            patch.object(srv, "allocate_ip", return_value="10.8.0.2"),
            patch.object(srv, "get_wan_interface", side_effect=["ens3", "eth1"]),
            patch.object(srv, "list_client_nat_rules", return_value=[]),
            patch.object(srv, "get_wg_cmd", return_value="awg"),
            patch.object(srv, "ensure_client_internet_rules"),
            patch.object(srv, "run_cmd", side_effect=run),
        ):
            with self.assertRaisesRegex(RuntimeError, "частичным"):
                srv.cmd_add(args)
        conn.commit.assert_called_once()
        self.assertFalse(any("set wg0 peer" in c for c in commands))

    def test_block_revokes_peer_and_records_block_when_nat_list_fails(self):
        conn = Mock()
        conn.execute.return_value.fetchone.return_value = ("public", "10.8.0.2", 1)
        commands = []

        def run(command, check=True):
            commands.append(command)
            if command == "awg show wg0 peers":
                return ""
            return ""

        with (
            patch.object(srv, "init_db", return_value=conn),
            patch.object(srv, "get_wg_cmd", return_value="awg"),
            patch.object(srv, "run_cmd", side_effect=run),
            patch.object(srv, "delete_client_forward_rules"),
            patch.object(srv, "delete_client_nat_rules", side_effect=RuntimeError("таблица NAT недоступна")),
        ):
            with self.assertRaisesRegex(RuntimeError, "очистк"):
                srv.cmd_block(SimpleNamespace(name="bob"))

        self.assertIn("awg set wg0 peer public remove", commands)
        self.assertIn("awg show wg0 peers", commands)
        self.assertIn(call("UPDATE users SET blocked=1 WHERE name=?", ("bob",)), conn.execute.call_args_list)
        conn.commit.assert_called_once()

    def test_block_preserves_unmarked_foreign_nat_after_revoking_peer(self):
        conn = Mock()
        conn.execute.return_value.fetchone.return_value = ("public", "10.8.0.2", 1)
        commands = []

        def run(command, check=True):
            commands.append(command)
            if command == "iptables -t nat -S POSTROUTING":
                return "-A POSTROUTING -s 10.8.0.2/32 -o ens3 -j MASQUERADE"
            return ""

        with (
            patch.object(srv, "init_db", return_value=conn),
            patch.object(srv, "get_wg_cmd", return_value="awg"),
            patch.object(srv, "run_cmd", side_effect=run),
        ):
            with self.assertRaisesRegex(RuntimeError, "принадлежность"):
                srv.cmd_block(SimpleNamespace(name="bob"))
        self.assertIn("awg set wg0 peer public remove", commands)
        self.assertNotIn(" -D POSTROUTING ", " ".join(commands))
        conn.commit.assert_called_once()

    def test_sync_without_internet_does_not_need_wan(self):
        conn = Mock()
        conn.execute.side_effect = lambda sql: Mock(fetchall=lambda: [
            ("pub", "10.8.0.2", 0, 0)
        ] if "WHERE blocked=0" in sql else [("10.8.0.2",)])
        with (
            patch.object(srv, "init_db", return_value=conn),
            patch.object(srv, "get_wg_cmd", return_value="awg"),
            patch.object(srv, "get_wan_interface", side_effect=RuntimeError("нет WAN")) as route,
            patch.object(srv, "run_cmd", return_value=""),
            patch.object(srv, "delete_client_nat_rules"),
            patch.object(srv, "delete_client_forward_rules"),
            patch.object(srv, "ensure_iptables_rule"),
            patch.object(srv, "delete_iptables_rule"),
        ):
            srv.cmd_sync()
        route.assert_not_called()

    def test_sync_stops_before_peer_changes_on_unowned_nat(self):
        conn = Mock()
        conn.execute.side_effect = lambda sql: Mock(fetchall=lambda: [
            ("pub", "10.8.0.2", 1, 0)
        ] if "WHERE blocked=0" in sql else [("10.8.0.2",)])
        with (
            patch.object(srv, "init_db", return_value=conn),
            patch.object(srv, "run_cmd", return_value="-A POSTROUTING -s 10.8.0.2/32 -o ens3 -j MASQUERADE") as run,
        ):
            with self.assertRaisesRegex(RuntimeError, "принадлежность"):
                srv.cmd_sync()
        self.assertNotIn("show wg0 peers", " ".join(c.args[0] for c in run.call_args_list))

    def test_sync_detects_wan_change_without_reporting_success(self):
        conn = Mock()
        conn.execute.side_effect = lambda sql: Mock(fetchall=lambda: [
            ("pub", "10.8.0.2", 1, 0)
        ] if "WHERE blocked=0" in sql else [("10.8.0.2",)])
        with (
            patch.object(srv, "init_db", return_value=conn),
            patch.object(srv, "get_wg_cmd", return_value="awg"),
            patch.object(srv, "get_wan_interface", side_effect=["ens3", "eth1"]),
            patch.object(srv, "run_cmd", return_value=""),
            patch.object(srv, "delete_client_nat_rules"),
            patch.object(srv, "delete_client_forward_rules"),
            patch.object(srv, "ensure_iptables_rule"),
            patch.object(srv, "delete_iptables_rule"),
        ):
            with self.assertRaisesRegex(RuntimeError, "изменил"):
                srv.cmd_sync()


if __name__ == "__main__":
    unittest.main()
