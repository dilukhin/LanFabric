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

    def test_user_key_pair_mismatch_is_rejected(self):
        row = {
            "name": "alice",
            "pubkey": "A" * 43 + "=",
            "privkey": "B" * 43 + "=",
            "ip": "10.8.0.2",
            "admin": 0,
            "internet": 0,
            "blocked": 0,
            "comment": "",
        }
        with patch.object(srv, "derive_public_key", return_value="C" * 43 + "="):
            with self.assertRaises(RuntimeError):
                srv.validate_user_rows([row], "awg")

    def test_awg_setconf_never_generates_missing_params(self):
        with patch.object(srv, "read_awg_params_file", side_effect=RuntimeError("нет params")), \
             patch.object(srv, "get_or_create_awg_params") as create:
            with self.assertRaises(RuntimeError):
                srv.build_setconf("A" * 43 + "=", "awg")
        create.assert_not_called()


class TestAutostartContract(unittest.TestCase):

    def test_unit_is_boot_only_oneshot(self):
        text = srv.awg_autostart_unit_text(python_path="/usr/bin/python3.12")
        self.assertIn("Type=oneshot", text)
        self.assertIn("_boot-awg", text)
        self.assertIn("ExecStart=/usr/bin/python3.12", text)
        self.assertIn("TimeoutStartSec=60s", text)
        self.assertIn("After=systemd-sysctl.service netfilter-persistent.service", text)
        self.assertNotIn("RemainAfterExit=yes", text)
        self.assertNotIn("ExecStop=", text)
        self.assertNotIn("network-online.target", text)

    def test_disable_does_not_call_runtime_stop(self):
        commands = []
        with patch.object(srv, "run_cmd", side_effect=lambda command, check=True: commands.append(command) or ""):
            srv.disable_awg_autostart(remove_unit=False)
        self.assertTrue(any("systemctl disable lanfabric-awg.service" in command for command in commands))
        self.assertFalse(any("disable --now" in command for command in commands))
        self.assertFalse(any("ip link del" in command for command in commands))

    def test_cancel_boot_is_separate_from_disable(self):
        commands = []
        with patch.object(srv, "run_cmd", side_effect=lambda command, check=True: commands.append(command) or ""):
            srv.cancel_awg_boot_before_lock()
        self.assertEqual(commands, ["systemctl stop lanfabric-awg.service 2>/dev/null || true"])

    def test_enable_validates_state_before_writing_unit(self):
        events = []
        with patch.object(srv, "load_state_snapshot", side_effect=lambda **kwargs: events.append("snapshot") or {}), \
             patch.object(srv, "ensure_state_permissions", side_effect=lambda: events.append("permissions")), \
             patch.object(srv, "state_permission_errors", return_value=[]), \
             patch.object(srv, "trusted_python_path", return_value="/usr/bin/python3.12"), \
             patch.object(srv, "_atomic_write_root_file", side_effect=lambda *a, **k: events.append("write")), \
             patch.object(srv, "run_cmd", side_effect=lambda command, check=True: "enabled" if "is-enabled" in command else ""):
            srv.ensure_awg_autostart_unit()
        self.assertEqual(events[:3], ["snapshot", "permissions", "write"])


class TestLockOrdering(unittest.TestCase):

    def test_boot_cancel_is_before_runtime_lock_in_lifecycle_branch(self):
        import inspect
        source = inspect.getsource(srv.main)
        lifecycle_source = source[source.index("cancel_boot_commands = "):]
        self.assertLess(
            lifecycle_source.index("cancel_awg_boot_before_lock()"),
            lifecycle_source.index("with runtime_lock():"),
        )


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



class TestSecretHandling(unittest.TestCase):

    def test_public_key_derivation_does_not_use_shell(self):
        fake = SimpleNamespace(returncode=0, stdout="A" * 43 + "=\n", stderr="")
        with patch.object(srv.subprocess, "run", return_value=fake) as run:
            result = srv.derive_public_key("B" * 43 + "=", "awg")
        self.assertEqual(result, "A" * 43 + "=")
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["awg", "pubkey"])
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["input"], "B" * 43 + "=\n")


class TestFailureSemantics(unittest.TestCase):

    def test_unknown_backend_never_falls_back_to_wg(self):
        with patch.object(srv, "get_backend", return_value="broken"):
            with self.assertRaises(RuntimeError):
                srv.get_wg_cmd()

    def test_health_returns_error_when_runtime_not_ready(self):
        snapshot = {"backend": "awg", "users": []}
        with patch.object(srv, "load_state_snapshot", return_value=snapshot), \
             patch.object(srv, "runtime_readiness_errors", return_value=["ошибка"]):
            with self.assertRaises(RuntimeError):
                srv.cmd_health()

    def test_sync_failure_keeps_guard_closed_and_never_opens_it(self):
        snapshot = {"backend": "awg", "users": []}
        with patch.object(srv, "awg_interface_ownership", return_value="owned"), \
             patch.object(srv, "close_firewall_guard") as close_guard, \
             patch.object(srv, "_apply_awg_peers", side_effect=RuntimeError("peer failure")), \
             patch.object(srv, "open_firewall_guard") as open_guard:
            with self.assertRaises(RuntimeError):
                srv._sync_awg_runtime_locked(snapshot)
        self.assertGreaterEqual(close_guard.call_count, 2)
        open_guard.assert_not_called()

    def test_foreign_wg0_is_not_deleted_by_awg_stop(self):
        with patch.object(srv, "load_runtime_identity", return_value={"server_public_key": "x"}), \
             patch.object(srv, "awg_interface_ownership", return_value="unknown"), \
             patch.object(srv, "run_cmd") as run:
            with self.assertRaises(RuntimeError):
                srv._stop_awg_runtime_locked()
        self.assertFalse(any("ip link del" in str(call) for call in run.call_args_list))


if __name__ == "__main__":
    unittest.main()
