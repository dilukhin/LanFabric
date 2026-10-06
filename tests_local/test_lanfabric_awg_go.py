"""Проверки штатной основы Go; без сервера, настоящих ключей и системных изменений."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("srv_go_tests", ROOT / "vsrv-admin.py")
srv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(srv)


class ImplementationTests(unittest.TestCase):
    def test_old_installation_remains_kernel_without_creating_state(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "implementation"
            with patch.object(srv, "IMPLEMENTATION_PATH", str(path)):
                self.assertEqual(srv.get_implementation("awg"), "kernel")
                self.assertEqual(srv.get_implementation("wg"), "kernel")
            self.assertFalse(path.exists())

    def test_corruption_and_wrong_protocol_do_not_fall_back(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "implementation"
            for backend, content in (("awg", ""), ("awg", "unknown-secret"), ("wg", "go")):
                path.write_text(content)
                with self.subTest(backend=backend, content=content), patch.object(srv, "IMPLEMENTATION_PATH", str(path)):
                    with self.assertRaises(RuntimeError) as caught:
                        srv.get_implementation(backend)
                    self.assertNotIn("unknown-secret", str(caught.exception))
                    self.assertEqual(path.read_text(), content)

    def test_go_tools_selected_only_by_saved_implementation(self):
        with patch.object(srv, "require_backend", return_value="awg"), \
                patch.object(srv, "get_implementation", return_value="go"):
            self.assertEqual(srv.get_wg_cmd(), srv.AWG_GO_TOOLS)
        with patch.object(srv, "require_backend", return_value="awg"), \
                patch.object(srv, "get_implementation", return_value="kernel"):
            self.assertEqual(srv.get_wg_cmd(), "awg")

    def test_init_cannot_destroy_saved_go_state(self):
        with patch.object(srv.os.path, "lexists", return_value=True), \
                patch.object(srv, "get_implementation", return_value="go"), \
                patch.object(srv, "run_cmd") as run, patch.object(srv, "ensure_dirs") as directories:
            with self.assertRaises(RuntimeError):
                srv.cmd_init(SimpleNamespace(no_amnezia=False))
            run.assert_not_called()
            directories.assert_not_called()

    def test_remove_and_purge_refuse_before_system_changes(self):
        for command, confirmation in ((srv.cmd_remove, "REMOVE"), (srv.cmd_purge, "PURGE")):
            with self.subTest(command=command.__name__), patch.object(srv, "get_implementation", return_value="go"), \
                    patch.object(srv, "run_cmd") as run, patch.object(srv, "disable_awg_autostart") as disable:
                with self.assertRaises(RuntimeError):
                    command(SimpleNamespace(confirm=confirmation))
                run.assert_not_called()
                disable.assert_not_called()


class ComponentTests(unittest.TestCase):
    def test_changed_binary_wrong_origin_and_malformed_manifest_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "amneziawg-go"
            tools = Path(temp) / "awg"
            manifest = Path(temp) / "manifest.json"
            binary.write_bytes(b"synthetic-go")
            tools.write_bytes(b"synthetic-tools")
            data = {"schema": 1, "platform": "linux-amd64",
                    "go_commit": "b5928efb6ca19f0153958460c3d141f04abc5c2e",
                    "tools_commit": "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843",
                    "sha256": {"amneziawg-go": hashlib.sha256(binary.read_bytes()).hexdigest(),
                               "awg": hashlib.sha256(tools.read_bytes()).hexdigest()}}
            with patch.object(srv, "AWG_GO_MANIFEST", str(manifest)), \
                    patch.object(srv, "AWG_GO_BINARY", str(binary)), patch.object(srv, "AWG_GO_TOOLS", str(tools)), \
                    patch.object(srv, "trusted_go_path"), \
                    patch.object(srv.os, "uname", create=True, return_value=SimpleNamespace(machine="x86_64")):
                manifest.write_text(json.dumps(data))
                srv.require_go_components()
                binary.write_bytes(b"replaced-go")
                with self.assertRaises(RuntimeError):
                    srv.require_go_components()
                binary.write_bytes(b"synthetic-go")
                data["go_commit"] = "unknown"
                manifest.write_text(json.dumps(data))
                with self.assertRaises(RuntimeError):
                    srv.require_go_components()
                manifest.write_text('{"secret": "do-not-report"')
                with self.assertRaises(RuntimeError) as caught:
                    srv.require_go_components()
                self.assertNotIn("do-not-report", str(caught.exception))

    def test_untrusted_parent_or_symlink_prevents_execution(self):
        for mode, uid in ((stat.S_IFLNK | 0o777, 0), (stat.S_IFREG | 0o755, 1000), (stat.S_IFREG | 0o777, 0)):
            with self.subTest(mode=mode, uid=uid), \
                    patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=mode, st_uid=uid)):
                with self.assertRaises(RuntimeError):
                    srv.trusted_go_path(srv.AWG_GO_BINARY, executable=True)

    def test_go_snapshot_does_not_probe_or_load_kernel(self):
        connection = Mock()
        connection.execute.return_value.fetchone.return_value = ["ok"]
        connection.execute.return_value.fetchall.return_value = []
        with patch.object(srv, "require_backend", return_value="awg"), \
                patch.object(srv, "get_implementation", return_value="go"), \
                patch.object(srv, "require_go_components") as components, \
                patch.object(srv.os.path, "exists", return_value=True), \
                patch.object(srv, "read_server_key_material", return_value=("synthetic-private", "synthetic-public")), \
                patch.object(srv, "read_awg_params_file", return_value=srv.generate_awg31_params()), \
                patch.object(srv, "read_listen_port", return_value=4387), \
                patch.object(srv, "init_db", return_value=connection), \
                patch.object(srv, "validate_user_rows"), patch.object(srv, "run_cmd") as run, \
                patch.object(srv, "command_succeeds") as succeeds:
            snapshot = srv.load_state_snapshot("awg")
        self.assertEqual(snapshot["implementation"], "go")
        self.assertEqual(snapshot["wg_bin"], srv.AWG_GO_TOOLS)
        components.assert_called_once()
        run.assert_not_called()
        succeeds.assert_not_called()


class ProcessTests(unittest.TestCase):
    def process(self, peer_pid=123, peer_uid=0, changed_pid=False, wrong_argv=False):
        calls = iter(["123", "124" if changed_pid else "123"])
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        connection.getsockopt.return_value = struct.pack("3i", peer_pid, peer_uid, 0)
        argv = [os.fsencode(srv.AWG_GO_BINARY), b"-f", b"wg0", b""]
        if wrong_argv:
            argv[2] = b"foreign-interface"
        with patch.object(srv, "require_go_unit"), patch.object(srv, "go_systemctl", side_effect=lambda *a: next(calls)), \
                patch.object(srv.os, "readlink", return_value=srv.AWG_GO_BINARY), \
                patch.object(Path, "read_bytes", return_value=b"\0".join(argv)), \
                patch.object(Path, "read_text", return_value="0::/system.slice/lanfabric-awg-go.service\n"), \
                patch.object(srv.os, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=0)), \
                patch.object(srv.socket, "socket", return_value=connection), \
                patch.object(srv.socket, "AF_UNIX", 1, create=True), \
                patch.object(srv.socket, "SO_PEERCRED", 17, create=True):
            return srv.go_process_identity()

    def test_pid_executable_service_socket_agree(self):
        self.assertEqual(self.process(), 123)

    def test_socket_of_foreign_process_or_user_is_rejected(self):
        for kwargs in ({"peer_pid": 999}, {"peer_uid": 1000}):
            with self.subTest(kwargs=kwargs), self.assertRaises(RuntimeError):
                self.process(**kwargs)

    def test_process_generation_change_and_foreign_arguments_are_rejected(self):
        for kwargs in ({"changed_pid": True}, {"wrong_argv": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(RuntimeError):
                self.process(**kwargs)

    def test_tun_name_without_process_identity_is_not_ownership(self):
        with patch.object(srv, "interface_exists", return_value=True), \
                patch.object(srv, "run_cmd", return_value="tun type tun"), \
                patch.object(srv, "go_process_identity", side_effect=RuntimeError("foreign")):
            self.assertEqual(srv.awg_interface_ownership({"implementation": "go"}), "unknown")

    def test_unit_has_no_shell_full_restore_and_restart_on_clean_exit(self):
        unit = srv.awg_go_unit_text()
        self.assertIn("ExecStart=" + srv.AWG_GO_BINARY + " -f wg0", unit)
        self.assertIn("_go-preflight", unit)
        self.assertIn("ExecStartPost=/usr/bin/python3 -u /opt/vpn-admin/vsrv-admin.py _go-restore", unit)
        self.assertIn("ExecStopPost=/usr/bin/python3 -u /opt/vpn-admin/vsrv-admin.py _go-closed", unit)
        self.assertIn("Restart=always", unit)
        self.assertNotIn("/bin/sh", unit)

    def test_systemctl_timeout_does_not_report_sensitive_output(self):
        with patch.object(srv.subprocess, "run", side_effect=subprocess.TimeoutExpired("systemctl", 60, output="private-secret")):
            with self.assertRaises(RuntimeError) as caught:
                srv.go_systemctl("restart")
            self.assertNotIn("private-secret", str(caught.exception))

    def test_daemon_reload_receives_no_unit_argument(self):
        with patch.object(srv.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="")) as run:
            srv.go_systemctl("daemon-reload")
        self.assertEqual(run.call_args.args[0], ["systemctl", "daemon-reload"])


class LifecycleTests(unittest.TestCase):
    def state(self):
        return dict(backend="awg", implementation="go", wg_bin=srv.AWG_GO_TOOLS,
                    server_private_key="synthetic-private", server_public_key="synthetic-public",
                    awg_params=srv.generate_awg31_params(), listen_port=4387, users=[])

    def test_systemctl_start_waits_without_runtime_lock(self):
        held = []
        observed = []
        @contextmanager
        def lock(**kwargs):
            name = kwargs.get("lock_path", "runtime")
            held.append(name)
            try:
                yield
            finally:
                held.remove(name)
        def systemctl(action, *args):
            if action == "start":
                observed.append(list(held))
                self.assertNotIn("runtime", held)
            return "0" if action == "show" else ""
        with patch.object(srv, "runtime_lock", side_effect=lock), \
                patch.object(srv, "load_state_snapshot", return_value=self.state()), \
                patch.object(srv, "require_go_unit"), patch.object(srv, "interface_exists", return_value=False), \
                patch.object(srv, "cleanup_go_stale_socket"), patch.object(srv.os.path, "lexists", return_value=False), \
                patch.object(srv, "go_systemctl", side_effect=systemctl), \
                patch.object(srv, "close_firewall_guard"), patch.object(srv, "_verify_awg_ready") as verify:
            srv.go_lifecycle("start")
        self.assertEqual(observed, [[srv.AWG_GO_OPERATION_LOCK]])
        verify.assert_called_once()
        self.assertEqual(held, [])

    def test_repeated_start_syncs_running_process_instead_of_closing_guard_forever(self):
        with patch.object(srv, "runtime_lock"), patch.object(srv, "load_state_snapshot", return_value=self.state()), \
                patch.object(srv, "require_go_unit"), patch.object(srv, "interface_exists", return_value=True), \
                patch.object(srv, "awg_interface_ownership", return_value="owned"), \
                patch.object(srv, "go_systemctl", return_value="123") as systemctl, \
                patch.object(srv, "go_process_identity", return_value=123), \
                patch.object(srv, "_sync_awg_runtime_locked") as sync:
            srv.go_lifecycle("start")
        sync.assert_called_once()
        self.assertEqual([c.args[0] for c in systemctl.call_args_list], ["show"])

    def test_stop_does_not_delete_unknown_or_lingering_interface(self):
        for ownership in ("unknown", "owned"):
            with self.subTest(ownership=ownership), patch.object(srv, "runtime_lock"), \
                    patch.object(srv, "load_state_snapshot", return_value=self.state()), \
                    patch.object(srv, "require_go_unit"), patch.object(srv, "interface_exists", return_value=True), \
                    patch.object(srv, "awg_interface_ownership", return_value=ownership), \
                    patch.object(srv, "go_systemctl", side_effect=lambda action, *a: "123" if action == "show" else ""), \
                    patch.object(srv, "go_process_identity", return_value=123), \
                    patch.object(srv, "close_firewall_guard"), patch.object(srv, "cleanup_owned_firewall") as cleanup:
                with self.assertRaises(RuntimeError):
                    srv.go_lifecycle("stop")
                cleanup.assert_not_called()

    def test_service_failure_keeps_guard_closed(self):
        def systemctl(action, *args):
            if action == "start":
                raise RuntimeError("service failed")
            return "0"
        with patch.object(srv, "runtime_lock"), patch.object(srv, "load_state_snapshot", return_value=self.state()), \
                patch.object(srv, "require_go_unit"), patch.object(srv, "interface_exists", return_value=False), \
                patch.object(srv, "cleanup_go_stale_socket"), patch.object(srv.os.path, "lexists", return_value=False), \
                patch.object(srv, "go_systemctl", side_effect=systemctl), \
                patch.object(srv, "close_firewall_guard") as close, patch.object(srv, "_verify_awg_ready") as verify:
            with self.assertRaises(RuntimeError):
                srv.go_lifecycle("start")
        self.assertEqual(close.call_count, 2)
        verify.assert_not_called()

    def restore(self, failure=None):
        state = self.state()
        commands = []
        def run(command, check=True):
            commands.append(command)
            if "setconf" in command and failure == "setconf":
                raise RuntimeError("HeaderProtectionKey=do-not-report")
            return "tun type tun" if command.startswith("ip -d") else ""
        with patch.object(srv, "state_permission_errors", return_value=[]), \
                patch.object(srv, "load_state_snapshot", return_value=state), \
                patch.object(srv.os.path, "lexists", return_value=True), \
                patch.object(srv, "close_firewall_guard") as close, \
                patch.object(srv, "go_process_identity", return_value=123), patch.object(srv, "record_go_socket"), \
                patch.object(srv, "interface_exists", return_value=True), patch.object(srv, "run_cmd", side_effect=run), \
                patch.object(srv, "write_setconf", return_value="/etc/wireguard/wg0.setconf") as write, \
                patch.object(srv, "prepare_internet_policy", return_value=state), \
                patch.object(srv, "public_client_firewall_rules", return_value=[]), \
                patch.object(srv, "_apply_awg_peers") as peers, patch.object(srv, "rebuild_policy_chains"), \
                patch.object(srv, "_verify_awg_before_open", side_effect=RuntimeError("mismatch") if failure == "verify" else None), \
                patch.object(srv, "open_firewall_guard") as opened, patch.object(srv, "_verify_awg_ready"), \
                patch.object(srv, "generate_awg_params") as generate:
            if failure:
                with self.assertRaises(RuntimeError) as caught:
                    srv.go_restore_locked()
                self.assertNotIn("do-not-report", str(caught.exception))
                opened.assert_not_called()
                self.assertGreaterEqual(close.call_count, 2)
            else:
                srv.go_restore_locked()
                opened.assert_called_once()
                peers.assert_called_once_with(state)
                self.assertEqual(write.call_args.args, (state["server_private_key"], "awg", state["awg_params"], 4387))
            generate.assert_not_called()
        self.assertFalse(any("modprobe" in c or "ip link add" in c for c in commands))

    def test_full_restore_reuses_saved_keys_and_profile(self):
        self.restore()

    def test_setconf_error_is_redacted_and_never_opens_guard(self):
        self.restore("setconf")

    def test_failed_readback_never_opens_guard(self):
        self.restore("verify")

    def test_socket_creation_timeout_keeps_guard_closed(self):
        with patch.object(srv, "state_permission_errors", return_value=[]), \
                patch.object(srv, "load_state_snapshot", return_value=self.state()), \
                patch.object(srv.os.path, "lexists", return_value=False), \
                patch.object(srv, "go_process_identity", return_value=123), \
                patch.object(srv.time, "monotonic", side_effect=[0, 16]), \
                patch.object(srv, "close_firewall_guard") as close, patch.object(srv, "open_firewall_guard") as opened:
            with self.assertRaises(RuntimeError):
                srv.go_restore_locked()
            opened.assert_not_called()
            self.assertEqual(close.call_count, 2)

    def test_main_does_not_hold_runtime_lock_while_starting_go_service(self):
        with patch.object(srv.sys, "argv", ["vsrv-admin.py", "start"]), \
                patch.object(srv.os.path, "exists", return_value=True), \
                patch.object(srv, "get_implementation", return_value="go"), \
                patch.object(srv, "cmd_start") as start, patch.object(srv, "runtime_lock") as lock:
            srv.main()
        start.assert_called_once()
        lock.assert_not_called()

    def test_account_revocation_closes_guard_before_committing_database(self):
        for command, row in ((srv.cmd_block, ("synthetic-public", "10.8.0.2", 1)),
                             (srv.cmd_delete, ("synthetic-public", "10.8.0.2"))):
            events = []
            connection = Mock()
            connection.execute.return_value.fetchone.return_value = row
            connection.commit.side_effect = lambda: events.append("commit")
            with self.subTest(command=command.__name__), patch.object(srv, "init_db", return_value=connection), \
                    patch.object(srv, "require_backend", return_value="awg"), \
                    patch.object(srv, "get_implementation", return_value="go"), \
                    patch.object(srv, "load_state_snapshot", side_effect=[self.state(), RuntimeError("damaged state")]), \
                    patch.object(srv, "awg_interface_ownership", return_value="owned"), \
                    patch.object(srv, "close_firewall_guard", side_effect=lambda **kw: events.append("closed")), \
                    patch.object(Path, "exists", return_value=False), patch.object(srv, "_sync_awg_runtime_locked") as sync:
                with self.assertRaises(RuntimeError):
                    command(SimpleNamespace(name="ci-peer", confirm="ci-peer"))
                self.assertEqual(events, ["closed", "commit"])
                sync.assert_not_called()


class StaleSocketTests(unittest.TestCase):
    def cleanup(self, inode=2, alive=False, listening=False):
        record = {"device": 1, "inode": 2, "ctime_ns": 3, "pid": 123, "start": "100"}
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        if not listening:
            connection.connect.side_effect = ConnectionRefusedError()
        def read(path, *args, **kwargs):
            if path == Path(srv.AWG_GO_SOCKET_RECORD):
                return json.dumps(record)
            if alive:
                return "123 (synthetic process) " + " ".join(["0"] * 19 + ["100"])
            raise FileNotFoundError()
        with patch.object(srv.os.path, "lexists", return_value=True), \
                patch.object(srv, "trusted_go_path"), \
                patch.object(Path, "read_text", autospec=True, side_effect=read), \
                patch.object(Path, "stat", return_value=SimpleNamespace(st_size=100)), \
                patch.object(srv.os, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=0,
                                                                          st_dev=1, st_ino=inode, st_ctime_ns=3)), \
                patch.object(srv.socket, "socket", return_value=connection), \
                patch.object(srv.socket, "AF_UNIX", 1, create=True), patch.object(srv.os, "unlink") as unlink:
            if inode != 2 or alive or listening:
                with self.assertRaises(RuntimeError):
                    srv.cleanup_go_stale_socket()
                unlink.assert_not_called()
            else:
                srv.cleanup_go_stale_socket()
                unlink.assert_called_once_with(srv.AWG_GO_SOCKET)

    def test_recorded_dead_socket_can_be_removed_after_sigkill(self):
        self.cleanup()

    def test_replaced_socket_is_not_removed(self):
        self.cleanup(inode=99)

    def test_live_generation_is_not_removed(self):
        self.cleanup(alive=True)

    def test_listening_socket_is_not_removed_even_when_old_process_has_died(self):
        self.cleanup(listening=True)


if __name__ == "__main__":
    unittest.main()
