#!/usr/bin/env python3
"""Профили и отказ init рядом с временной службой проверяются без VPS."""
import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def load(filename, module_name):
    spec = importlib.util.spec_from_file_location(module_name, Path(__file__).resolve().parents[1] / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cli = load("vcli-admin.py", "cli_private_config")
srv = load("vsrv-admin.py", "srv_stabilization")


class TestPrivateConfig(unittest.TestCase):
    def test_unsafe_filename_is_rejected_before_ssh(self):
        for name in ("../user", "a/b", "a\\b", "C:profile", "user\nname", "CON", "NUL.txt", "..", "", "user."):
            with self.subTest(name=name), patch.object(cli, "ensure_remote_version_compatible") as ssh:
                with self.assertRaises(RuntimeError):
                    cli.cmd_config(SimpleNamespace(name=name))
                ssh.assert_not_called()
        self.assertEqual(cli.private_config_target("Дима-1"), "Дима-1.conf")

    def test_success_replaces_entire_file_and_leaves_no_temporary_files(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "user.conf"
            target.write_text("previous-profile")
            cli.save_private_config(str(target), "new-profile")
            self.assertEqual(target.read_text(), "new-profile\n")
            self.assertEqual([p.name for p in Path(directory).iterdir()], ["user.conf"])
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_replace_failure_keeps_previous_profile_and_cleans_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "user.conf"
            target.write_text("previous-profile")
            with patch.object(cli.os, "replace", side_effect=OSError("replacement-failed")):
                with self.assertRaises(OSError):
                    cli.save_private_config(str(target), "new-profile")
            self.assertEqual(target.read_text(), "previous-profile")
            self.assertEqual([p.name for p in Path(directory).iterdir()], ["user.conf"])

    def test_profile_has_private_posix_permissions_before_write(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "user.conf"
            real_fdopen = cli.os.fdopen
            def inspect(fd, *args, **kwargs):
                if os.name != "nt":
                    self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode), 0o600)
                self.assertEqual(os.fstat(fd).st_size, 0)
                return real_fdopen(fd, *args, **kwargs)
            with patch.object(cli.os, "fdopen", side_effect=inspect):
                cli.save_private_config(str(target), "private")

    def test_symlink_is_rejected_without_touching_destination(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(cli.os.path, "islink", return_value=True):
            with patch.object(cli.tempfile, "mkstemp") as create:
                with self.assertRaises(RuntimeError):
                    cli.save_private_config(str(Path(directory) / "user.conf"), "private")
                create.assert_not_called()


class TestStandaloneInstallation(unittest.TestCase):
    def test_init_refuses_standalone_installation_before_any_mutation(self):
        for existing in ("/opt/lanfabric-awg31", "/etc/systemd/system/lanfabric-awg31.service"):
            with self.subTest(existing=existing), \
                 patch.object(srv.os.path, "lexists", side_effect=lambda path: path == existing), \
                 patch.object(srv, "ensure_dirs") as dirs, patch.object(srv, "run_cmd") as commands:
                with self.assertRaisesRegex(RuntimeError, "миграция"):
                    srv.cmd_init(SimpleNamespace())
                dirs.assert_not_called()
                commands.assert_not_called()


if __name__ == "__main__":
    unittest.main()
