#!/usr/bin/env python3
"""Регрессии потокового SSH-исполнения LanFabric без реального SSH."""

import contextlib
import importlib.util
import io
import os
import sys
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch


_CLI_PATH = os.path.join(os.path.dirname(__file__), "..", "vcli-admin.py")
_spec = importlib.util.spec_from_file_location("vcli_admin_stream_timeout", _CLI_PATH)
cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cli)


def make_args():
    return SimpleNamespace(debug=False, ssh_tty=False)


class TestExecRemoteStreamingTimeout(unittest.TestCase):

    def test_streaming_prompt_without_newline_times_out(self):
        """Запрос без перевода строки не должен навсегда блокировать readline()."""
        child = [
            sys.executable,
            "-c",
            "import sys,time; sys.stderr.write('PROMPT'); sys.stderr.flush(); time.sleep(5)",
        ]
        started = time.monotonic()
        with patch.object(cli, "build_ssh_cmd", return_value=child):
            with self.assertRaisesRegex(RuntimeError, "не выдавала данных"):
                cli.exec_remote(make_args(), ["true"], stream_output=True, timeout=0.2)
        self.assertLess(time.monotonic() - started, 2.0)

    def test_streaming_timeout_is_idle_timeout_not_total_runtime(self):
        """Регулярный вывод продлевает ожидание даже при общей длительности больше timeout."""
        child = [
            sys.executable,
            "-c",
            (
                "import time; "
                "print('line-1', flush=True); time.sleep(0.3); "
                "print('line-2', flush=True); time.sleep(0.3); "
                "print('line-3', flush=True); time.sleep(0.3)"
            ),
        ]
        stdout = io.StringIO()
        started = time.monotonic()
        with patch.object(cli, "build_ssh_cmd", return_value=child):
            with contextlib.redirect_stdout(stdout):
                result = cli.exec_remote(
                    make_args(), ["true"], stream_output=True, timeout=0.6
                )
        self.assertGreater(time.monotonic() - started, 0.6)
        self.assertEqual(result, "line-1\nline-2\nline-3")
        self.assertEqual(stdout.getvalue().splitlines(), ["line-1", "line-2", "line-3"])


if __name__ == "__main__":
    unittest.main()
