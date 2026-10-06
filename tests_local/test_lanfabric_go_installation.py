"""Установка Go: отказы до создания ключей и сохранение чужих ресурсов."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


srv = module("srv_go_install", "vsrv-admin.py")
cli = module("cli_go_install", "vcli-admin.py")


class GoDownloadTests(unittest.TestCase):
    def test_changed_or_truncated_download_never_executes_component(self):
        for data in (b"changed", b""):
            response = io.BytesIO(data)
            response.geturl = lambda: "https://release-assets.githubusercontent.com/component"
            with tempfile.TemporaryDirectory() as temp, patch.object(srv.urllib.request, "urlopen", return_value=response), \
                    patch.object(srv, "run_cmd") as execute:
                with self.assertRaises(RuntimeError):
                    srv.download_go_components(temp)
                self.assertFalse((Path(temp) / "manifest.json").exists())
                execute.assert_not_called()

    def test_unpinned_release_refuses_before_network(self):
        with patch.object(srv, "AWG_GO_RELEASE_SHA256", {}), patch.object(srv.urllib.request, "urlopen") as network:
            with self.assertRaises(RuntimeError):
                srv.download_go_components("unused")
            network.assert_not_called()

    def test_verified_files_and_manifest_are_private(self):
        data = {"amneziawg-go": b"synthetic-go", "awg": b"synthetic-tools"}
        expected = {name: hashlib.sha256(value).hexdigest() for name, value in data.items()}
        urls = []
        def response(url, timeout):
            urls.append(url)
            name = "amneziawg-go" if "amneziawg-go-linux" in url else "awg"
            result = io.BytesIO(data[name])
            result.geturl = lambda: url
            return result
        with tempfile.TemporaryDirectory() as temp, patch.object(srv, "AWG_GO_RELEASE_SHA256", expected), \
                patch.object(srv.urllib.request, "urlopen", side_effect=response), \
                patch.object(srv.os, "fchmod", create=True) as private_mode:
            srv.download_go_components(temp)
            self.assertEqual(json.loads((Path(temp) / "manifest.json").read_text())["sha256"], expected)
            self.assertTrue(all(Path(temp, name).read_bytes() == value for name, value in data.items()))
            self.assertTrue(all(url.startswith("https://github.com/dilukhin/LanFabric/releases/download/awg-go-3.1-r1/") for url in urls))
            self.assertEqual(private_mode.call_args.args[1], 0o600)


class GoInstallTests(unittest.TestCase):
    def test_protocol_and_port_rejected_before_mutations(self):
        for args in (SimpleNamespace(no_amnezia=True), SimpleNamespace(no_amnezia=False, listen_port=0)):
            with patch.object(srv, "runtime_lock") as lock, patch.object(srv, "download_go_components") as download:
                with self.assertRaises(RuntimeError):
                    srv.cmd_init_go(args)
                lock.assert_not_called()
                download.assert_not_called()

    def test_foreign_target_rejected_before_download_or_key_generation(self):
        with patch.object(srv, "runtime_lock"), patch.object(srv.os.path, "lexists", return_value=False), \
                patch.object(srv, "require_go_platform"), patch.object(srv, "check_go_clean_target", side_effect=RuntimeError("чужая цель")), \
                patch.object(srv, "download_go_components") as download, patch.object(srv, "run_cmd") as execute:
            with self.assertRaises(RuntimeError):
                srv.cmd_init_go(SimpleNamespace(no_amnezia=False))
            download.assert_not_called()
            execute.assert_not_called()

    def test_incomplete_creation_cannot_generate_new_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            record = Path(temp) / "go-install.json"
            record.write_text('{"schema": 1, "phase": "creating"}')
            with patch.object(srv, "AWG_GO_INSTALL_RECORD", str(record)), patch.object(srv, "runtime_lock"), \
                    patch.object(srv, "trusted_go_path"), patch.object(srv, "download_go_components") as download, \
                    patch.object(srv, "run_cmd") as execute:
                with self.assertRaises(RuntimeError):
                    srv.cmd_init_go(SimpleNamespace(no_amnezia=False))
                download.assert_not_called()
                execute.assert_not_called()
                self.assertEqual(json.loads(record.read_text())["phase"], "creating")

    def test_corrupted_record_and_boolean_schema_do_not_expose_contents(self):
        with tempfile.TemporaryDirectory() as temp:
            record = Path(temp) / "go-install.json"
            for text in ('{"schema": true, "phase": "complete"}', '{"private": "do-not-report"'):
                record.write_text(text)
                with patch.object(srv, "AWG_GO_INSTALL_RECORD", str(record)), patch.object(srv, "trusted_go_path"):
                    with self.assertRaises(RuntimeError) as caught:
                        srv.read_go_install_record()
                    self.assertNotIn("do-not-report", str(caught.exception))

    def test_repeat_rejects_port_change_before_restart(self):
        with tempfile.TemporaryDirectory() as temp:
            record = Path(temp) / "go-install.json"
            record.write_text('{"schema": 1, "phase": "complete"}')
            snapshot = {"implementation": "go", "listen_port": 4387, "awg_params": srv.generate_awg31_params()}
            with patch.object(srv, "AWG_GO_INSTALL_RECORD", str(record)), patch.object(srv, "runtime_lock"), \
                    patch.object(srv, "trusted_go_path"), patch.object(srv, "load_state_snapshot", return_value=snapshot), \
                    patch.object(srv, "_go_lifecycle_locked") as lifecycle:
                with self.assertRaises(RuntimeError):
                    srv.cmd_init_go(SimpleNamespace(no_amnezia=False, listen_port=4388))
                lifecycle.assert_not_called()

    def test_cli_rejects_wrong_protocol_before_ssh(self):
        with patch.object(cli, "exec_remote") as remote:
            with self.assertRaises(RuntimeError):
                cli.cmd_init(SimpleNamespace(no_amnezia=True, implementation="go"))
            remote.assert_not_called()

    def test_go_dispatch_does_not_wait_for_systemd_under_outer_state_lock(self):
        with patch.object(sys, "argv", ["vsrv-admin.py", "init", "--implementation", "go"]), \
                patch.object(srv.os.path, "exists", return_value=False), patch.object(srv, "cmd_init") as init, \
                patch.object(srv, "runtime_lock") as outer_lock, patch.object(srv, "cancel_awg_boot_before_lock") as cancel:
            srv.main()
            self.assertEqual(init.call_args.args[0].implementation, "go")
            outer_lock.assert_not_called()
            cancel.assert_not_called()

    def test_remove_does_not_use_global_package_or_trust_cleanup(self):
        with patch.object(srv, "get_implementation", return_value="go"), patch.object(srv, "cmd_remove_go") as remove, \
                patch.object(srv, "remove_packages") as packages, patch.object(srv, "run_cmd") as execute:
            srv.cmd_remove(SimpleNamespace(confirm="REMOVE"))
            srv.cmd_purge(SimpleNamespace(confirm="PURGE"))
            self.assertEqual([entry.kwargs for entry in remove.call_args_list], [{"purge": False}, {"purge": True}])
            packages.assert_not_called()
            execute.assert_not_called()

    def test_foreign_purge_failure_does_not_stop_runtime(self):
        with patch.object(srv, "runtime_lock"), patch.object(srv, "load_state_snapshot", return_value={}), \
                patch.object(srv, "require_go_components"), patch.object(srv, "go_purge_files", side_effect=RuntimeError("чужой файл")), \
                patch.object(srv, "_go_lifecycle_locked") as lifecycle:
            with self.assertRaises(RuntimeError):
                srv.cmd_remove_go(purge=True)
            lifecycle.assert_not_called()
