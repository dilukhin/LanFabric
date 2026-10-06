#!/usr/bin/env python3
"""Регрессии SSH без настоящего сервера."""
import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch, Mock

spec = importlib.util.spec_from_file_location(
    "vcli_stabilization", os.path.join(os.path.dirname(__file__), "..", "vcli-admin.py"))
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


def args():
    return SimpleNamespace(debug=False, ssh_tty=False)


class TestSshStreaming(unittest.TestCase):
    def test_prompt_without_newline_has_finite_wait(self):
        child = [sys.executable, "-c",
                 "import sys,time; sys.stderr.write('PROMPT'); sys.stderr.flush(); time.sleep(5)"]
        started = time.monotonic()
        with patch.object(cli, "build_ssh_cmd", return_value=child):
            with self.assertRaisesRegex(RuntimeError, "не выдавала данных"):
                cli.exec_remote(args(), ["true"], timeout=0.2)
        self.assertLess(time.monotonic() - started, 2)

    def test_periodic_output_extends_idle_wait(self):
        child = [sys.executable, "-c",
                 "import time; print('a',flush=True); time.sleep(.3); "
                 "print('b',flush=True); time.sleep(.3); print('c',flush=True); time.sleep(.3)"]
        with patch.object(cli, "build_ssh_cmd", return_value=child), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.exec_remote(args(), ["true"], timeout=0.6), "a\nb\nc")

    def test_exited_parent_with_open_pipe_does_not_wait_forever(self):
        # Потомок может удержать pipe после выхода родителя: poll() != None
        # не отменяет срок ожидания EOF. Модель не создаёт фоновых процессов.
        process = Mock()
        process.poll.return_value = 0
        reader = Mock()
        with patch.object(cli, "build_ssh_cmd", return_value=["ssh"]), \
             patch.object(cli.subprocess, "Popen", return_value=process), \
             patch.object(cli.threading, "Thread", return_value=reader), \
             patch.object(cli.queue, "Queue") as queue_factory:
            queue_factory.return_value.get.side_effect = [cli.queue.Empty, AssertionError("Повтор после срока ожидания")]
            with self.assertRaisesRegex(RuntimeError, "не выдавала данных"):
                cli.exec_remote(args(), ["true"], timeout=.01)
        process.kill.assert_not_called()

    def test_closed_stdout_with_running_process_has_finite_wait(self):
        child = [sys.executable, "-c",
                 "import os,time; os.close(1); os.close(2); time.sleep(5)"]
        started = time.monotonic()
        with patch.object(cli, "build_ssh_cmd", return_value=child):
            with self.assertRaisesRegex(RuntimeError, "не завершилась"):
                cli.exec_remote(args(), ["true"], timeout=.2)
        self.assertLess(time.monotonic() - started, 2)

    def test_interrupt_terminates_local_ssh(self):
        process = Mock()
        process.poll.return_value = None
        with patch.object(cli, "build_ssh_cmd", return_value=["ssh"]), \
             patch.object(cli.subprocess, "Popen", return_value=process), \
             patch.object(cli.threading, "Thread"), \
             patch.object(cli.queue, "Queue") as queue_factory:
            queue_factory.return_value.get.side_effect = KeyboardInterrupt
            with self.assertRaises(KeyboardInterrupt):
                cli.exec_remote(args(), ["true"])
        process.kill.assert_called_once()
        process.wait.assert_called_once()


class TestSshCleanOutput(unittest.TestCase):
    def test_stderr_never_enters_returned_config(self):
        child = [sys.executable, "-c",
                 "import sys; print('[Interface]'); print('warning',file=sys.stderr)"]
        with patch.object(cli, "build_ssh_cmd", return_value=child):
            output = cli.exec_remote(args(), ["config", "user"], stream_output=False)
        self.assertEqual(output, "[Interface]")

    def test_failed_clean_command_does_not_expose_partial_stdout(self):
        secret = "PRIVATE_CONFIG_MUST_NOT_APPEAR"
        child = [sys.executable, "-c",
                 "import sys; print('PRIVATE_CONFIG_MUST_NOT_APPEAR'); sys.exit(1)"]
        with patch.object(cli, "build_ssh_cmd", return_value=child):
            with self.assertRaises(RuntimeError) as caught:
                cli.exec_remote(args(), ["config", "user"], stream_output=False)
        self.assertNotIn(secret, str(caught.exception))


if __name__ == "__main__":
    unittest.main()

