"""Обновление Go: отказы до остановки, защита снимка и блокировка изменений."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


srv = module("srv_go_update", "vsrv-admin.py")
cli = module("cli_go_update", "vcli-admin.py")


class GoUpdateTests(unittest.TestCase):
    def record(self):
        files = {path: {"sha256": "a" * 64, "mode": 0o600} for path in srv.go_update_paths()}
        return {"schema": 1, "phase": "prepared", "old_sha256": "a" * 64,
                "new_sha256": "b" * 64, "running": True, "components": False,
                "files": files, "backup": "go-update-backup-" + "c" * 32,
                "stage": ".go-update-abcdefgh"}

    def test_bad_version_or_protocol_refuses_before_lock_and_stop(self):
        cases = [(b"GO_UPDATE_SCHEMA = 1\n", "0.0.17"),
                 (b"GO_UPDATE_SCHEMA = 1\n", "0.1.0"),
                 (b"GO_UPDATE_SCHEMA = 2\n", "0.0.18")]
        for data, version in cases:
            with patch.object(srv, "runtime_lock") as lock, patch.object(srv, "stop_go_for_update") as stop:
                with self.assertRaises(RuntimeError):
                    srv.install_go_server_module(data, version)
                lock.assert_not_called()
                stop.assert_not_called()

    def test_corrupt_journal_never_exposes_data(self):
        for change in ({"schema": True}, {"files": {}}, {"backup": "../foreign"},
                       {"stage": "../foreign"}, {"phase": "secret-state"}):
            record = self.record()
            record.update(change)
            with tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "journal.json"
                path.write_text(json.dumps(record))
                with patch.object(srv, "GO_UPDATE_RECORD", str(path)), patch.object(srv, "trusted_go_path"):
                    with self.assertRaises(RuntimeError) as caught:
                        srv.read_go_update_record()
                    self.assertNotIn("secret-state", str(caught.exception))
                    self.assertNotIn("foreign", str(caught.exception))

    def test_pending_update_blocks_mutation_before_lifecycle(self):
        for phase in ("prepared", "committed"):
            with patch.object(srv.os.path, "lexists", return_value=True), \
                    patch.object(srv, "read_go_update_record", return_value={"phase": phase}), \
                    patch.object(srv, "runtime_lock") as state_lock, patch.object(srv, "go_systemctl") as systemctl:
                with self.assertRaises(RuntimeError):
                    srv._go_lifecycle_locked("restart")
                state_lock.assert_not_called()
                systemctl.assert_not_called()

    def test_corrupt_backup_refuses_before_stop_or_restore(self):
        with tempfile.TemporaryDirectory() as temp:
            record = self.record()
            directory = Path(temp) / record["backup"]
            directory.mkdir(mode=0o700)
            for index in range(len(srv.go_update_paths())):
                (directory / str(index)).write_bytes(b"secret-snapshot")
            with patch.object(srv, "REMOTE_DIR", temp), patch.object(srv, "go_update_paths", return_value=list(record["files"])), \
                    patch.object(srv, "trusted_go_path"), \
                    patch.object(srv, "stop_go_for_update") as stop, patch.object(srv, "atomic_root_bytes") as write:
                with self.assertRaises(RuntimeError) as caught:
                    srv.rollback_go_update(record)
                self.assertNotIn("secret-snapshot", str(caught.exception))
                stop.assert_not_called()
                write.assert_not_called()
                self.assertTrue((directory / "0").exists())

    def test_unknown_stage_file_forbids_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            record = self.record()
            directory = Path(temp) / record["stage"]
            directory.mkdir(mode=0o700)
            (directory / "candidate.py").write_bytes(b"candidate")
            foreign = directory / "foreign"
            foreign.write_text("must remain")
            with patch.object(srv, "REMOTE_DIR", temp), patch.object(srv, "trusted_go_path"):
                with self.assertRaises(RuntimeError):
                    srv.cleanup_go_update_stage(record)
                self.assertTrue(foreign.exists())
                self.assertTrue((directory / "candidate.py").exists())

    def test_failed_candidate_check_preserves_current_installation(self):
        with tempfile.TemporaryDirectory() as temp:
            current = Path(temp) / "vsrv-admin.py"
            current.write_bytes(b"old module")
            with patch.object(srv, "REMOTE_DIR", temp), patch.object(srv, "runtime_lock"), \
                    patch.object(srv.os.path, "lexists", return_value=False), \
                    patch.object(srv, "atomic_root_bytes"), patch.object(srv, "trusted_python_path", return_value=sys.executable), \
                    patch.object(srv, "run_bounded_command", side_effect=RuntimeError("bad candidate")), \
                    patch.object(srv, "stop_go_for_update") as stop:
                with self.assertRaises(RuntimeError):
                    srv.install_go_server_module(b"GO_UPDATE_SCHEMA = 1\n", "0.0.18")
                stop.assert_not_called()
                self.assertEqual(current.read_bytes(), b"old module")
                self.assertEqual({entry.name for entry in Path(temp).iterdir()}, {"vsrv-admin.py"})

    def test_equal_version_reinstall_and_components_use_protected_copy(self):
        for flag in ("reinstall", "components"):
            args = SimpleNamespace(**{flag: True})
            with patch.object(cli, "get_remote_version", return_value=cli.__version__), \
                    patch.object(cli, "try_cleanup_stale_temporary_sudo_trust"), patch.object(cli, "copy_server_module") as copy:
                cli.cmd_patch(args)
                copy.assert_called_once_with(args, remote_version=cli.__version__)

    def test_component_copy_uses_existing_installer_without_legacy_fallback(self):
        args = SimpleNamespace(auth="password", user="tester", host="example.invalid", debug=False, components=True)
        with patch.object(cli, "local_server_module_path", return_value=str(ROOT / "vsrv-admin.py")), \
                patch.object(cli, "run_local"), patch.object(cli, "_validate_uploaded_server_module"), \
                patch.object(cli, "get_remote_version", return_value=cli.__version__), \
                patch.object(cli, "exec_remote") as remote, patch.object(cli, "_legacy_atomic_server_install") as legacy:
            cli.copy_server_module(args, remote_version="0.0.18")
            install = [call for call in remote.call_args_list if "_install-module" in call.args[1]]
            self.assertEqual(len(install), 1)
            self.assertIn("--components", install[0].args[1])
            self.assertEqual(install[0].kwargs["timeout"], 600)
            legacy.assert_not_called()
