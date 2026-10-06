"""Приватный Python: проверка архива, целостности и отказ до исполнения."""
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("srv_python_runtime", ROOT / "vsrv-admin.py")
srv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(srv)


class PythonRuntimeTests(unittest.TestCase):
    def archive(self, directory, entries):
        result = Path(directory) / "input.tar.gz"
        with tarfile.open(result, "w:gz") as output:
            for name, kind, value in entries:
                member = tarfile.TarInfo(name)
                member.mode = 0o755
                if kind == "file":
                    member.size = len(value)
                    output.addfile(member, io.BytesIO(value))
                else:
                    member.type = kind
                    member.linkname = value
                    output.addfile(member)
        return result

    def save_fixture(self, path, contents, mode=0o600):
        Path(path).write_bytes(contents)
        Path(path).chmod(mode)

    def test_escaping_paths_links_and_special_nodes_never_extract(self):
        cases = [("/etc/foreign", "file", b"x"), ("python/../../foreign", "file", b"x"),
                 ("python/link", tarfile.SYMTYPE, "../../foreign"),
                 ("python/link", tarfile.SYMTYPE, "/etc/foreign"),
                 ("python/node", tarfile.CHRTYPE, ""), ("python/hard", tarfile.LNKTYPE, "python/file")]
        for entry in cases:
            with tempfile.TemporaryDirectory() as temp:
                archive = self.archive(temp, [entry])
                with patch.object(srv, "atomic_root_bytes") as write:
                    with self.assertRaises(RuntimeError):
                        srv.unpack_python_runtime(archive, Path(temp) / "result")
                    write.assert_not_called()

    def test_internal_file_link_is_flattened_and_recorded(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = self.archive(temp, [("python/bin/python3.12", "file", b"synthetic interpreter"),
                                          ("python/bin/python3", tarfile.SYMTYPE, "python3.12")])
            destination = Path(temp) / "result"
            with patch.object(srv, "atomic_root_bytes", side_effect=self.save_fixture), patch.object(srv, "fsync_root_directory"):
                record = srv.unpack_python_runtime(archive, destination)
            self.assertFalse((destination / "bin/python3").is_symlink())
            self.assertEqual((destination / "bin/python3").read_bytes(), b"synthetic interpreter")
            self.assertEqual(record["files"]["bin/python3"]["sha256"], record["files"]["bin/python3.12"]["sha256"])
            self.assertEqual(json.loads((destination / "lanfabric-runtime.json").read_text()), record)

    def test_link_cycle_and_duplicate_file_refuse(self):
        for entries in ([("python/a", tarfile.SYMTYPE, "b"), ("python/b", tarfile.SYMTYPE, "a")],
                        [("python/a", "file", b"a"), ("python/a", "file", b"b")]):
            with tempfile.TemporaryDirectory() as temp:
                archive = self.archive(temp, entries)
                with patch.object(srv, "atomic_root_bytes", side_effect=self.save_fixture):
                    with self.assertRaises(RuntimeError):
                        srv.unpack_python_runtime(archive, Path(temp) / "result")

    def test_changed_download_never_unpacks_or_executes(self):
        with tempfile.TemporaryDirectory() as temp:
            response = io.BytesIO(b"wrong runtime")
            response.geturl = lambda: "https://release-assets.githubusercontent.com/runtime"
            with patch.object(srv, "REMOTE_DIR", temp), patch.object(srv, "PYTHON_RUNTIME_DIR", str(Path(temp) / "runtime")), \
                    patch.object(srv.urllib.request, "urlopen", return_value=response), \
                    patch.object(srv, "unpack_python_runtime") as unpack, patch.object(srv, "run_bounded_command") as execute:
                with self.assertRaises(RuntimeError):
                    srv.install_python_runtime()
                unpack.assert_not_called()
                execute.assert_not_called()
                self.assertEqual(list(Path(temp).iterdir()), [])

    def test_existing_corrupt_runtime_refuses_without_download(self):
        with patch.object(srv.os.path, "lexists", return_value=True), \
                patch.object(srv, "validate_python_runtime", side_effect=RuntimeError("corrupt runtime")), \
                patch.object(srv.urllib.request, "urlopen") as network:
            with self.assertRaises(RuntimeError):
                srv.install_python_runtime()
            network.assert_not_called()

    def test_invalid_port_bootstrap_refuses_before_install(self):
        with patch.object(sys, "version_info", (3, 8)), \
                patch.object(sys, "argv", ["vsrv-admin.py", "init", "--implementation", "go", "--listen-port", "0"]), \
                patch.object(srv, "__file__", srv.REMOTE_DIR + "/vsrv-admin.py"), \
                patch.object(Path, "read_text", return_value='ID=ubuntu\nVERSION_ID="20.04"\n'), \
                patch.object(srv.os, "uname", return_value=SimpleNamespace(machine="x86_64"), create=True), \
                patch.object(srv.os, "geteuid", return_value=0, create=True), \
                patch.object(srv.os.path, "lexists", return_value=False), patch.object(srv, "trusted_go_path"), \
                patch.object(srv, "runtime_lock"), patch.object(srv, "install_python_runtime") as install:
            with self.assertRaises(RuntimeError):
                srv.bootstrap_go_python()
            install.assert_not_called()

    def test_current_python_does_not_download_another_runtime(self):
        with patch.object(sys, "version_info", (3, 10)), patch.object(srv, "install_python_runtime") as install:
            srv.bootstrap_go_python()
            install.assert_not_called()

    def test_private_interpreter_unit_disables_site_and_bytecode(self):
        unit = srv.awg_go_unit_text(srv.PYTHON_RUNTIME_EXECUTABLE)
        self.assertIn(srv.PYTHON_RUNTIME_EXECUTABLE + " -I -B -u", unit)
        self.assertNotIn(" -I -B", srv.awg_go_unit_text("/usr/bin/python3"))
