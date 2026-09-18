#!/usr/bin/env python3
"""Локальные тесты строгого AWG lifecycle и autostart."""

import importlib.util
import os
import sqlite3
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


_SRV_PATH = os.path.join(os.path.dirname(__file__), "..", "vsrv-admin.py")
_spec = importlib.util.spec_from_file_location("vsrv_admin_awg_lifecycle", _SRV_PATH)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


class TestStrictState(unittest.TestCase):

    def test_missing_db_is_not_created_by_read_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "missing.db")
            with patch.object(srv, "DB_PATH", db_path):
                with self.assertRaises(RuntimeError):
                    srv.init_db()
                self.assertFalse(os.path.exists(db_path))

    def test_explicit_create_builds_expected_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "vpn.db")
            with patch.object(srv, "DB_PATH", db_path):
                conn = srv.init_db(create=True)
                conn.close()
                self.assertTrue(os.path.exists(db_path))
                check = sqlite3.connect(db_path)
                columns = [row[1] for row in check.execute("PRAGMA table_info(users)")]
                check.close()
                self.assertEqual(
                    columns,
                    ["name", "pubkey", "privkey", "ip", "admin", "internet", "blocked", "comment"],
                )

    def test_awg_setconf_never_generates_missing_params(self):
        with patch.object(srv, "read_awg_params_file", side_effect=RuntimeError("нет params")), \
             patch.object(srv, "get_or_create_awg_params") as create:
            with self.assertRaises(RuntimeError):
                srv.build_setconf("A" * 43 + "=", "awg")
        create.assert_not_called()


class TestAutostartContract(unittest.TestCase):

    def test_unit_is_boot_only_oneshot(self):
        text = srv.awg_autostart_unit_text()
        self.assertIn("Type=oneshot", text)
        self.assertIn("_boot-awg", text)
        self.assertIn("TimeoutStartSec=60s", text)
        self.assertIn("After=systemd-sysctl.service netfilter-persistent.service", text)
        self.assertNotIn("RemainAfterExit=yes", text)
        self.assertNotIn("ExecStop=", text)
        self.assertNotIn("network-online.target", text)

    def test_disable_does_not_call_runtime_stop(self):
        commands = []
        with patch.object(srv, "run_cmd", side_effect=lambda command, check=True: commands.append(command) or ""):
            srv.disable_awg_autostart(remove_unit=False)
        self.assertTrue(any("systemctl disable --now lanfabric-awg.service" in command for command in commands))
        self.assertFalse(any("ip link del" in command for command in commands))

    def test_enable_validates_state_before_writing_unit(self):
        events = []
        with patch.object(srv, "load_state_snapshot", side_effect=lambda **kwargs: events.append("snapshot") or {}), \
             patch.object(srv, "ensure_state_permissions", side_effect=lambda: events.append("permissions")), \
             patch.object(srv, "state_permission_errors", return_value=[]), \
             patch.object(srv, "_atomic_write_root_file", side_effect=lambda *a, **k: events.append("write")), \
             patch.object(srv, "run_cmd", side_effect=lambda command, check=True: "enabled" if "is-enabled" in command else ""):
            srv.ensure_awg_autostart_unit()
        self.assertEqual(events[:3], ["snapshot", "permissions", "write"])


class TestFirewallGuard(unittest.TestCase):

    def test_close_guard_does_not_remove_existing_forward_hook(self):
        commands = []
        hook = f"-A FORWARD -i {srv.WG_IF} -j {srv.FW_GUARD_CHAIN}"
        with patch.object(srv, "_ensure_chain"), \
             patch.object(srv, "_chain_rule_lines", return_value=[hook]), \
             patch.object(srv, "run_cmd", side_effect=lambda command, check=True: commands.append(command) or ""):
            srv.close_firewall_guard(persist=False)
        self.assertFalse(any("-D FORWARD" in command for command in commands))
        self.assertTrue(any(f"-I {srv.FW_GUARD_CHAIN} 1 -j DROP" in command for command in commands))


if __name__ == "__main__":
    unittest.main()
