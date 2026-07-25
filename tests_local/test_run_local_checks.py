#!/usr/bin/env python3
"""Тесты локального runner LanFabric."""

import importlib.util
import io
import os
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch


_RUNNER_PATH = os.path.join(os.path.dirname(__file__), "run_local_checks.py")
_spec = importlib.util.spec_from_file_location("run_local_checks", _RUNNER_PATH)
checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checks)


class TestSubprocessConfiguration(unittest.TestCase):

    def test_run_version_rejects_empty_output(self):
        result = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch.object(checks.subprocess, "run", return_value=result), redirect_stdout(io.StringIO()):
            self.assertEqual(checks.run_module_version(checks.CLI_PATH, "vcli-admin.py"), (False, None))

    def test_run_help_rejects_empty_output(self):
        result = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch.object(checks.subprocess, "run", return_value=result), redirect_stdout(io.StringIO()):
            self.assertFalse(checks.run_help(checks.CLI_PATH))

    def test_run_help_uses_utf8_environment(self):
        result = SimpleNamespace(returncode=0, stdout="usage: test\n", stderr="")
        with (
            patch.object(checks.subprocess, "run", return_value=result) as run_mock,
            redirect_stdout(io.StringIO()),
        ):
            self.assertTrue(checks.run_help(checks.CLI_PATH))

        kwargs = run_mock.call_args.kwargs
        self.assertEqual(kwargs["encoding"], "utf-8")
        self.assertEqual(kwargs["errors"], "replace")
        self.assertEqual(kwargs["env"]["PYTHONUTF8"], "1")
        self.assertEqual(kwargs["env"]["PYTHONIOENCODING"], "utf-8")


class TestResultValidation(unittest.TestCase):

    def test_unexpected_success_fails_result(self):
        result = SimpleNamespace(failures=[], errors=[], unexpectedSuccesses=[object()])
        self.assertFalse(checks.unittest_result_ok(result))

    def test_expected_versions_are_synchronized(self):
        self.assertEqual(checks.expected_module_version("vcli-admin"), "vcli-admin 0.0.17")
        self.assertEqual(checks.expected_module_version("vsrv-admin"), "vsrv-admin 0.0.17")


if __name__ == "__main__":
    unittest.main()
