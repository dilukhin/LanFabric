#!/usr/bin/env python3
"""Проверки переноса WAN и принадлежности правил в защищённый AWG runtime."""

import importlib.util
import os
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


_spec = importlib.util.spec_from_file_location(
    "vsrv_admin_wan_policy", os.path.join(os.path.dirname(__file__), "..", "vsrv-admin.py")
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


def snapshot(internet=1):
    return {"backend": "awg", "users": [
        {"ip": "10.8.0.2", "pubkey": "test-peer", "internet": internet, "blocked": 0}
    ]}


class TestPythonMinimum(unittest.TestCase):

    def test_python310_reaches_backend_validation(self):
        with patch.object(srv.sys, "version_info", (3, 10, 20)), \
             patch.object(srv, "require_backend", side_effect=RuntimeError("проверка backend")):
            with self.assertRaisesRegex(RuntimeError, "проверка backend"):
                srv.load_state_snapshot()

    def test_python39_is_rejected_before_backend(self):
        with patch.object(srv.sys, "version_info", (3, 9, 0)), \
             patch.object(srv, "require_backend") as backend:
            with self.assertRaisesRegex(RuntimeError, "Python 3.10"):
                srv.load_state_snapshot()
        backend.assert_not_called()

    def test_python310_keeps_root_path_checks(self):
        path = MagicMock()
        path.is_file.return_value = True
        path.parents = []
        path.stat.return_value = SimpleNamespace(st_uid=0, st_mode=0o100755)
        path.__str__.return_value = "/usr/bin/python3.10"
        with patch.object(srv.sys, "version_info", (3, 10, 20)), patch.object(srv, "Path", return_value=path):
            self.assertEqual(srv.trusted_python_path(), "/usr/bin/python3.10")
            path.stat.return_value = SimpleNamespace(st_uid=1000, st_mode=0o100755)
            with self.assertRaisesRegex(RuntimeError, "root"):
                srv.trusted_python_path()


class TestWanRoute(unittest.TestCase):

    def route_output(self, command, check=True):
        if command == "ip -4 rule show":
            return "0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default"
        if command == "ip -4 route show table main default" or command.startswith("ip -4 route show table main match "):
            return "default via 198.51.100.1 dev ens3 onlink"
        if command.startswith("ip -4 route get "):
            return command.split()[4] + " via 198.51.100.1 dev ens3"
        if command == "ip -d -j link show dev ens3":
            return '[{"ifname":"ens3","link_type":"ether","flags":["UP","LOWER_UP"]}]'
        raise AssertionError(command)

    def test_forwarded_route_uses_client_source_and_input_interface(self):
        with patch.object(srv, "run_cmd", side_effect=self.route_output) as run:
            self.assertEqual(srv.get_wan_interface("10.8.0.2"), "ens3")
        routes = [c.args[0] for c in run.call_args_list if c.args[0].startswith("ip -4 route get ")]
        self.assertEqual(len(routes), 2)
        self.assertTrue(all("from 10.8.0.2 iif wg0" in route for route in routes))

    def test_missing_multiple_policy_and_virtual_routes_are_rejected(self):
        cases = [
            ("ip -4 route show table main default", ""),
            ("ip -4 route show table main default", "default via 198.51.100.1 dev ens3\ndefault via 198.51.100.2 dev eth1"),
            ("ip -4 rule show", self.route_output("ip -4 rule show") + "\n100: from all lookup other"),
            ("ip -d -j link show dev ens3", '[{"ifname":"ens3","link_type":"none","flags":["UP"]}]'),
            ("ip -d -j link show dev ens3", '[{"ifname":"ens3","link_type":"ether","linkinfo":{"info_kind":"vxlan"},"flags":["UP"]}]'),
            ("ip -4 route show table main match 1.1.1.1/32", "1.1.1.1 via 198.51.100.1 dev ens3"),
            ("ip -4 route get 8.8.8.8 from 10.8.0.2 iif wg0", "8.8.8.8 via 198.51.100.1 dev eth1"),
        ]
        for command, output in cases:
            with self.subTest(command=command, output=output), patch.object(
                srv, "run_cmd", side_effect=lambda c, check=True: output if c == command else self.route_output(c, check)
            ):
                with self.assertRaises(RuntimeError):
                    srv.get_wan_interface("10.8.0.2")

    def test_outside_vpn_address_is_rejected_without_commands(self):
        with patch.object(srv, "run_cmd") as run:
            with self.assertRaises(RuntimeError):
                srv.get_wan_interface("192.0.2.2")
        run.assert_not_called()


class TestOwnedPublicRules(unittest.TestCase):

    def test_clean_install_without_iptables_does_not_attempt_rule_deletion(self):
        with patch.object(srv, "command_succeeds", return_value=False), \
             patch.object(srv, "interface_exists", return_value=False), \
             patch.object(srv, "run_cmd") as run:
            srv.cleanup_owned_firewall(allow_missing=True)
        run.assert_not_called()

    def test_missing_iptables_with_existing_interface_blocks_install(self):
        with patch.object(srv, "command_succeeds", return_value=False), \
             patch.object(srv, "interface_exists", return_value=True), \
             patch.object(srv, "run_cmd") as run:
            with self.assertRaisesRegex(RuntimeError, "установка остановлена"):
                srv.cleanup_owned_firewall(allow_missing=True)
        run.assert_not_called()

    def test_unmarked_client_rules_are_preserved_and_require_migration(self):
        rules = [
            "-A POSTROUTING -s 10.8.0.2/32 -o ens3 -j MASQUERADE",
            "-A POSTROUTING -s 10.8.0.0/24 -j MASQUERADE",
            "-A FORWARD -s 10.8.0.2/32 -j ACCEPT",
        ]
        for rule in rules:
            with self.subTest(rule=rule), patch.object(srv, "run_cmd", return_value=rule), \
                 patch.object(srv, "_delete_rule_all") as delete:
                with self.assertRaisesRegex(RuntimeError, "миграц"):
                    srv._remove_owned_public_client_rules()
            delete.assert_not_called()

    def test_owned_old_interface_rules_removed_and_foreign_subnet_preserved(self):
        outputs = {
            "iptables -S FORWARD": "-A FORWARD -s 192.0.2.2/32 -j ACCEPT",
            "iptables -t nat -S POSTROUTING": "-A POSTROUTING -s 10.8.0.2/32 -o eth0 -m comment --comment lanfabric-client-nat-v1 -j MASQUERADE",
        }
        calls = []
        def delete(table, chain, spec):
            calls.append((table, chain, spec))
            outputs["iptables -t nat -S POSTROUTING"] = "-A POSTROUTING -s 192.0.2.2/32 -o eth0 -j MASQUERADE"
        with patch.object(srv, "run_cmd", side_effect=lambda c, check=True: outputs[c]), \
             patch.object(srv, "_delete_rule_all", side_effect=delete):
            srv._remove_owned_public_client_rules()
        self.assertEqual(len(calls), 1)
        self.assertIn("eth0", calls[0][2])
        self.assertIn("lanfabric-client-nat-v1", calls[0][2])

    def test_failed_deletion_or_remaining_owned_rule_is_an_error(self):
        rule = "-A POSTROUTING -s 10.8.0.2/32 -o ens3 -m comment --comment lanfabric-client-nat-v1 -j MASQUERADE"
        for error in (None, RuntimeError("ошибка удаления")):
            with self.subTest(error=error), patch.object(srv, "run_cmd", return_value=rule), \
                 patch.object(srv, "_delete_rule_all", side_effect=error):
                with self.assertRaises(RuntimeError):
                    srv._remove_owned_public_client_rules()


class TestGuardedWanPolicy(unittest.TestCase):

    def test_readiness_checks_current_wan_and_owned_nat_exactly(self):
        state = snapshot()
        chains = {
            ("filter", "FORWARD"): ["-A FORWARD -i wg0 -j LANFABRIC-GUARD"],
            ("filter", "LANFABRIC-GUARD"): ["-A LANFABRIC-GUARD -j LANFABRIC-FWD"],
            ("filter", "LANFABRIC-FWD"): [
                "-A LANFABRIC-FWD -o wg0 -j ACCEPT",
                "-A LANFABRIC-FWD -s 10.8.0.2/32 -j ACCEPT",
                "-A LANFABRIC-FWD -j DROP",
            ],
            ("nat", "LANFABRIC-NAT"): ["-A LANFABRIC-NAT -s 10.8.0.2/32 -o ens3 -j MASQUERADE"],
            ("nat", "POSTROUTING"): ["-A POSTROUTING -s 10.8.0.0/24 -j LANFABRIC-NAT"],
        }
        with patch.object(srv, "get_wan_interface", return_value="ens3"), \
             patch.object(srv, "public_client_firewall_rules", return_value=[]), \
             patch.object(srv, "_chain_rule_lines", side_effect=lambda table, chain: chains[(table, chain)]):
            self.assertEqual(srv.firewall_readiness_errors(state), [])
            chains[("nat", "LANFABRIC-NAT")][0] = "-A LANFABRIC-NAT -s 10.8.0.2/32 -o eth0 -j MASQUERADE"
            self.assertTrue(srv.firewall_readiness_errors(state))
            chains[("nat", "LANFABRIC-NAT")][0] = "-A LANFABRIC-NAT -s 10.8.0.2/32 -o ens3 -j MASQUERADE"
            chains[("nat", "POSTROUTING")].insert(0, "-A POSTROUTING -j OTHER")
            self.assertTrue(srv.firewall_readiness_errors(state))

    def test_restore_selects_wan_after_interface_creation_and_before_peer_apply(self):
        state = dict(snapshot(), server_private_key="synthetic", awg_params={})
        events = []
        with patch.object(srv, "awg_interface_ownership", return_value="absent"), \
             patch.object(srv, "close_firewall_guard", side_effect=lambda **kw: events.append("close")), \
             patch.object(srv, "write_setconf", return_value="/tmp/synthetic"), \
             patch.object(srv, "get_wan_interface", side_effect=lambda ip: events.append("wan") or "ens3"), \
             patch.object(srv, "public_client_firewall_rules", return_value=[]), \
             patch.object(srv, "_apply_awg_peers", side_effect=lambda s: events.append("peers")), \
             patch.object(srv, "rebuild_policy_chains") as rebuild, \
             patch.object(srv, "_verify_awg_before_open"), patch.object(srv, "_verify_awg_ready"), \
             patch.object(srv, "open_firewall_guard", side_effect=lambda: events.append("open")), \
             patch.object(srv, "run_cmd", side_effect=lambda c, check=True: events.append(c) or ""):
            srv._restore_awg_runtime_locked(state)
        self.assertLess(events.index("ip link add wg0 type amneziawg"), events.index("wan"))
        self.assertLess(events.index("wan"), events.index("peers"))
        self.assertLess(events.index("peers"), events.index("open"))
        self.assertEqual(rebuild.call_args.args[0]["wan_interfaces"], {"10.8.0.2": "ens3"})

    def test_add_internet_preflight_failure_does_not_write_account_or_generate_keys(self):
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = None
        args = SimpleNamespace(name="test-user", admin=False, internet=True, block=False, comment="")
        with patch.object(srv, "init_db", return_value=conn), \
             patch.object(srv, "allocate_ip", return_value="10.8.0.2"), \
             patch.object(srv, "require_backend", return_value="awg"), \
             patch.object(srv, "get_wan_interface", side_effect=RuntimeError("нет маршрута")), \
             patch.object(srv, "run_cmd") as run:
            with self.assertRaisesRegex(RuntimeError, "нет маршрута"):
                srv.cmd_add(args)
        conn.commit.assert_not_called()
        self.assertFalse(any("INSERT" in c.args[0] for c in conn.execute.call_args_list))
        run.assert_not_called()

    def test_route_change_during_readiness_prevents_guard_opening(self):
        with patch.object(srv, "awg_interface_ownership", return_value="owned"), \
             patch.object(srv, "close_firewall_guard") as close, \
             patch.object(srv, "get_wan_interface", side_effect=["ens3", "eth1"]), \
             patch.object(srv, "public_client_firewall_rules", return_value=[]), \
             patch.object(srv, "_apply_awg_peers"), patch.object(srv, "rebuild_policy_chains"), \
             patch.object(srv, "runtime_readiness_errors", return_value=[]), \
             patch.object(srv, "open_firewall_guard") as open_guard:
            with self.assertRaisesRegex(RuntimeError, "изменился"):
                srv._sync_awg_runtime_locked(snapshot())
        self.assertGreaterEqual(close.call_count, 2)
        open_guard.assert_not_called()

    def test_rebuild_uses_validated_interface_in_owned_nat_chain(self):
        state = snapshot()
        state["wan_interfaces"] = {"10.8.0.2": "ens3"}
        commands = []
        with patch.object(srv, "get_wan_interface", return_value="ens3"), \
             patch.object(srv, "_remove_owned_public_client_rules"), \
             patch.object(srv, "_ensure_chain"), patch.object(srv, "_delete_rule_all"), \
             patch.object(srv, "run_cmd", side_effect=lambda c, check=True: commands.append(c) or ""):
            srv.rebuild_policy_chains(state)
        self.assertIn("iptables -t nat -A LANFABRIC-NAT -s 10.8.0.2/32 -o ens3 -j MASQUERADE", commands)
        self.assertFalse(any("eth0" in c or "-D FORWARD" in c for c in commands))

    def test_route_loss_blocks_before_peer_or_policy_replacement(self):
        with patch.object(srv, "awg_interface_ownership", return_value="owned"), \
             patch.object(srv, "close_firewall_guard") as close, \
             patch.object(srv, "get_wan_interface", side_effect=RuntimeError("маршрут исчез")), \
             patch.object(srv, "_apply_awg_peers") as peers, \
             patch.object(srv, "rebuild_policy_chains") as rebuild, \
             patch.object(srv, "open_firewall_guard") as open_guard:
            with self.assertRaisesRegex(RuntimeError, "маршрут исчез"):
                srv._sync_awg_runtime_locked(snapshot())
        self.assertGreaterEqual(close.call_count, 2)
        peers.assert_not_called()
        rebuild.assert_not_called()
        open_guard.assert_not_called()

    def test_route_change_before_rebuild_keeps_guard_closed(self):
        with patch.object(srv, "awg_interface_ownership", return_value="owned"), \
             patch.object(srv, "close_firewall_guard") as close, \
             patch.object(srv, "get_wan_interface", side_effect=["ens3", "eth1"]), \
             patch.object(srv, "_apply_awg_peers"), \
             patch.object(srv, "public_client_firewall_rules", return_value=[]), \
             patch.object(srv, "_remove_owned_public_client_rules"), \
             patch.object(srv, "run_cmd") as run, \
             patch.object(srv, "open_firewall_guard") as open_guard:
            with self.assertRaisesRegex(RuntimeError, "изменился"):
                srv._sync_awg_runtime_locked(snapshot())
        self.assertGreaterEqual(close.call_count, 2)
        run.assert_not_called()
        open_guard.assert_not_called()

    def test_policy_failure_never_opens_guard(self):
        with patch.object(srv, "awg_interface_ownership", return_value="owned"), \
             patch.object(srv, "close_firewall_guard") as close, \
             patch.object(srv, "get_wan_interface", return_value="ens3"), \
             patch.object(srv, "_apply_awg_peers"), \
             patch.object(srv, "public_client_firewall_rules", return_value=[]), \
             patch.object(srv, "rebuild_policy_chains", side_effect=RuntimeError("ошибка NAT")), \
             patch.object(srv, "open_firewall_guard") as open_guard:
            with self.assertRaisesRegex(RuntimeError, "ошибка NAT"):
                srv._sync_awg_runtime_locked(snapshot())
        self.assertGreaterEqual(close.call_count, 2)
        open_guard.assert_not_called()

    def test_no_internet_or_only_blocked_clients_need_no_wan(self):
        for state in (snapshot(0), {"backend": "awg", "users": [dict(snapshot()["users"][0], blocked=1)]}):
            with self.subTest(state=state), patch.object(srv, "get_wan_interface") as wan:
                self.assertEqual(srv.prepare_internet_policy(state)["wan_interfaces"], {})
            wan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
