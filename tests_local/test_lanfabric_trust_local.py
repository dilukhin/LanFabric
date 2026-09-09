#!/usr/bin/env python3
"""
Локальные unit/smoke тесты для vcli-admin.py версии 0.0.17.
Без SSH/SCP/sudo/systemd/iptables/WireGuard/AmneziaWG.
Без внешних библиотек, только стандартная библиотека Python.
"""

import unittest
import importlib.util
import sys
import os
import subprocess
import tempfile
import time
import datetime
import re
import hashlib
import platform
import importlib.util
import inspect
from pathlib import Path
from unittest.mock import patch, MagicMock
from types import SimpleNamespace
from contextlib import contextmanager

_SRV_PATH = os.path.join(os.path.dirname(__file__), "..", "vsrv-admin.py")
_srv_spec = importlib.util.spec_from_file_location("vsrv_admin_for_trust_tests", _SRV_PATH)
srv = importlib.util.module_from_spec(_srv_spec)
_srv_spec.loader.exec_module(srv)

# ---------------------------------------------------------------------------
# Импортируем vcli-admin.py через importlib.util (имя файла содержит дефис)
# ---------------------------------------------------------------------------
_CLI_PATH = os.path.join(os.path.dirname(__file__), "..", "vcli-admin.py")
_spec = importlib.util.spec_from_file_location("vcli_admin", _CLI_PATH)
cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cli)

# ---------------------------------------------------------------------------
# Подавляем логи при тестах
# ---------------------------------------------------------------------------
import logging
logging.disable(logging.CRITICAL)


# ---------------------------------------------------------------------------
# Вспомогательные функции-харнессы, извлекающие логику inline-скриптов
# Парсинг использует re.split(r':(?=\w+=)', marker), который корректно
# обрабатывает двоеточия внутри created (ISO-время вида 22:10:19Z).
# ---------------------------------------------------------------------------

def _parse_marker_fields(marker_text):
    """Разбирает поля маркера через re.split, устойчивый к двоеточиям в created."""
    fields = {}
    for part in re.split(r':(?=\w+=)', marker_text)[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k] = v
    return fields


def filter_authorized_keys(lines, marker="", all_lanfabric=False, temp_only=False):
    """Локальная копия логики inline-скрипта remove_authorized_key_by_marker (строки 504-530)."""
    new = []
    removed = 0
    for line in lines:
        if all_lanfabric:
            drop = "lanfabric-temp:" in line or "lanfabric-trust:" in line
        elif temp_only:
            drop = "lanfabric-temp:" in line
        else:
            drop = bool(marker and marker in line)
        if drop:
            removed += 1
        else:
            new.append(line)
    return new, removed


def filter_stale_temp_keys(lines, remove_all=False, now=None):
    """Локальная копия логики inline-скрипта cleanup_stale_lanfabric_temp_keys (строки 539-574)."""
    if now is None:
        now_local = time.time()
    else:
        now_local = now
    new = []
    removed = 0
    for line in lines:
        pos = line.find("lanfabric-temp:")
        if pos < 0:
            new.append(line)
            continue
        marker_text = line[pos:].strip().split()[0]
        fields = _parse_marker_fields(marker_text)
        try:
            created_raw = fields.get("created", "").replace("Z", "+00:00")
            ttl_val = int(fields.get("ttl", "0"))
            expired = ttl_val > 0 and now_local > datetime.datetime.fromisoformat(created_raw).timestamp() + ttl_val
        except Exception:
            expired = True
        if remove_all or expired:
            removed += 1
        else:
            new.append(line)
    return new, removed


# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------

def make_args(**overrides):
    """Создаёт SimpleNamespace-объект, имитирующий args для тестов."""
    defaults = dict(
        host="test-server",
        user="test-user",
        auth="key",
        key="/tmp/fake_key",
        debug=False,
        ssh_tty=False,
        command="status",
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def make_marker(kind="lanfabric-temp", host="s", user="u", client="c1234",
                nonce="n1", ttl=3600, created=None):
    """Собирает маркер с правильным ISO-временем (created содержит двоеточия).

    Парсинг через re.split с упреждающим просмотром (lookahead)
    корректно обрабатывает двоеточия внутри created.
    """
    if created is None:
        created = "2026-06-09T10:00:00Z"
    parts = [kind, f"host={host}", f"user={user}", f"client={client}",
             f"created={created}"]
    if ttl is not None:
        parts.append(f"ttl={ttl}")
    parts.append(f"nonce={nonce}")
    return ":".join(str(p) for p in parts)


def make_lanfabric_key_line(pub="AAAA test-key", kind="lanfabric-temp",
                            host="s", user="u", client="c1234", nonce="n1",
                            ttl=3600, created=None):
    """Генерирует строку authorized_keys с LanFabric-маркером."""
    marker = make_marker(kind, host, user, client, nonce, ttl, created)
    return f"{pub} {marker}\n"


def foreign_key_line(key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI external-key"):
    """Генерирует строку без LanFabric-маркера."""
    return key + " user@machine\n"


# ===================================================================
# A. client_id и marker
# ===================================================================

class TestClientIdAndMarker(unittest.TestCase):

    def test_current_client_id_is_16_hex(self):
        cid = cli.current_client_id()
        self.assertEqual(len(cid), 16)
        int(cid, 16)

    def test_current_client_id_stable(self):
        cid1 = cli.current_client_id()
        cid2 = cli.current_client_id()
        self.assertEqual(cid1, cid2)

    def test_current_client_id_different_inputs(self):
        raw1 = "|".join(["host-a", "user-a", "/home/a"])
        raw2 = "|".join(["host-b", "user-b", "/home/b"])
        h1 = hashlib.sha256(raw1.encode()).hexdigest()[:16]
        h2 = hashlib.sha256(raw2.encode()).hexdigest()[:16]
        self.assertNotEqual(h1, h2)

    def test_lanfabric_temp_marker_contains_all_fields(self):
        args = make_args()
        nonce = "test-nonce-123"
        marker = cli.lanfabric_marker("lanfabric-temp", args, nonce, ttl=3600)
        self.assertIn("lanfabric-temp:", marker)
        self.assertIn("host=test-server", marker)
        self.assertIn("user=test-user", marker)
        self.assertIn("client=", marker)
        self.assertIn("created=", marker)
        self.assertIn("ttl=3600", marker)
        self.assertIn("nonce=test-nonce-123", marker)

    def test_lanfabric_trust_marker_no_ttl(self):
        args = make_args()
        nonce = "trust-nonce"
        marker = cli.lanfabric_marker("lanfabric-trust", args, nonce)
        self.assertIn("lanfabric-trust:", marker)
        self.assertIn("host=test-server", marker)
        self.assertIn("user=test-user", marker)
        self.assertIn("client=", marker)
        self.assertIn("created=", marker)
        self.assertIn("nonce=trust-nonce", marker)
        self.assertNotIn("ttl=", marker)


# ===================================================================
# B. authorized_keys filtering (локально, через файл)
# ===================================================================

class TestAuthorizedKeysFiltering(unittest.TestCase):

    def setUp(self):
        self.foreign = foreign_key_line()
        self.temp_line = make_lanfabric_key_line(
            "ssh-ed25519 AAAAtemp", kind="lanfabric-temp",
            host="s", user="u", client="c1", nonce="temp1", ttl=3600
        )
        self.trust_line = make_lanfabric_key_line(
            "ssh-ed25519 AAAATrust", kind="lanfabric-trust",
            host="s", user="u", client="c1", nonce="trust1", ttl=None
        )

    def test_foreign_key_survives(self):
        lines = [self.foreign, self.temp_line]
        new, removed = filter_authorized_keys(
            lines, marker="lanfabric-temp:host=s", all_lanfabric=False, temp_only=False
        )
        self.assertIn(self.foreign, new)
        self.assertNotIn(self.temp_line, new)
        self.assertEqual(removed, 1)

    def test_remove_by_marker_single_line(self):
        lines = [self.foreign, self.temp_line, self.trust_line]
        target_marker = "lanfabric-temp:host=s:user=u:client=c1"
        new, removed = filter_authorized_keys(lines, marker=target_marker)
        self.assertIn(self.foreign, new)
        self.assertIn(self.trust_line, new)
        self.assertNotIn(self.temp_line, new)
        self.assertEqual(removed, 1)

    def test_temp_only_removes_only_temp(self):
        lines = [self.foreign, self.temp_line, self.trust_line]
        new, removed = filter_authorized_keys(lines, temp_only=True)
        self.assertIn(self.foreign, new)
        self.assertIn(self.trust_line, new)
        self.assertNotIn(self.temp_line, new)
        self.assertEqual(removed, 1)

    def test_all_lanfabric_removes_all_lanfabric(self):
        lines = [self.foreign, self.temp_line, self.trust_line]
        new, removed = filter_authorized_keys(lines, all_lanfabric=True)
        self.assertIn(self.foreign, new)
        self.assertNotIn(self.temp_line, new)
        self.assertNotIn(self.trust_line, new)
        self.assertEqual(removed, 2)

    def test_expired_temp_removed(self):
        base_ts = datetime.datetime.fromisoformat("2026-06-09").timestamp()
        now_past = base_ts + 7200
        expired_line = make_lanfabric_key_line(
            "ssh-ed25519 AAAExpired", kind="lanfabric-temp",
            host="s", user="u", client="c1", nonce="expired", ttl=3600,
            created="2026-06-09"
        )
        lines = [self.foreign, expired_line]
        new, removed = filter_stale_temp_keys(lines, remove_all=False, now=now_past)
        self.assertIn(self.foreign, new)
        self.assertNotIn(expired_line, new)
        self.assertEqual(removed, 1)

    def test_not_expired_temp_preserved(self):
        base_ts = datetime.datetime.fromisoformat("2026-06-09").timestamp()
        now_fresh = base_ts + 600
        valid_line = make_lanfabric_key_line(
            "ssh-ed25519 AAAValid", kind="lanfabric-temp",
            host="s", user="u", client="c1", nonce="valid", ttl=3600,
            created="2026-06-09"
        )
        lines = [self.foreign, valid_line]
        new, removed = filter_stale_temp_keys(
            lines, remove_all=False, now=now_fresh
        )
        self.assertIn(self.foreign, new)
        self.assertIn(valid_line, new)
        self.assertEqual(removed, 0)

    def test_corrupted_temp_marker_removed(self):
        """Повреждённый marker (непарсибельный created) считается небезопасным и удаляется."""
        base_ts = datetime.datetime.fromisoformat("2026-06-09").timestamp()
        corrupted_line = "ssh-ed25519 AAAACorrupted lanfabric-temp:created=BADDATA:ttl=3600:nonce=bad\n"
        lines = [self.foreign, corrupted_line]
        new, removed = filter_stale_temp_keys(lines, remove_all=False, now=base_ts + 1800)
        self.assertIn(self.foreign, new)
        self.assertNotIn(corrupted_line, new)
        self.assertEqual(removed, 1)

    def test_temp_by_marker_via_file_roundtrip(self):
        """Полный roundtrip: запись в файл -> фильтрация -> чтение."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(self.foreign)
            f.write(self.temp_line)
            f.write(self.trust_line)
            tmp = f.name
        try:
            with open(tmp, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new, removed = filter_authorized_keys(lines, all_lanfabric=True)
            self.assertEqual(removed, 2)
            self.assertEqual(len(new), 1)
            self.assertIn(self.foreign, new)
        finally:
            os.unlink(tmp)


# ===================================================================
# C. SSH command construction
# ===================================================================

class TestSshCommandConstruction(unittest.TestCase):

    def test_build_ssh_cmd_auth_key_adds_i(self):
        args = make_args(auth="key", key="~/.ssh/id_test")
        with patch.object(cli.os.path, "isfile", return_value=True):
            cmd = cli.build_ssh_cmd(args)
        self.assertIn("-i", cmd)
        idx = cmd.index("-i")
        self.assertTrue(len(cmd) > idx + 1)

    def test_build_ssh_cmd_auth_password_no_i(self):
        args = make_args(auth="password", key=None)
        cmd = cli.build_ssh_cmd(args)
        self.assertNotIn("-i", cmd)

    def test_build_ssh_cmd_contains_strict_host_key_checking(self):
        """Security risk: StrictHostKeyChecking=no отключает проверку host key."""
        args = make_args(auth="key", key="~/.ssh/id_test")
        with patch.object(cli.os.path, "isfile", return_value=True):
            cmd = cli.build_ssh_cmd(args)
        self.assertTrue(
            any("StrictHostKeyChecking=no" in part for part in cmd),
            "build_ssh_cmd использует StrictHostKeyChecking=no"
        )

    def test_build_ssh_cmd_requires_host(self):
        args = make_args(host=None)
        with self.assertRaises(RuntimeError):
            with patch.object(cli.os.path, "isfile", return_value=True):
                cli.build_ssh_cmd(args)

    def test_build_ssh_cmd_raises_on_missing_key_file(self):
        args = make_args(auth="key", key="/nonexistent/key_file")
        with patch.object(cli.os.path, "isfile", return_value=False):
            with self.assertRaises(RuntimeError):
                cli.build_ssh_cmd(args)


# ===================================================================
# D. temporary password session state (через mock)
# ===================================================================

class TestTemporaryPasswordSession(unittest.TestCase):

    def setUp(self):
        self.args = make_args(auth="password", command="status", host="srv")

    @staticmethod
    def _setup_ssh_side_effect(args, nonce):
        args.auth = "key"
        args.key = "/tmp/fake_temp_key"
        return {"marker": "m:test", "temp_dir": "/tmp/t",
                "original_auth": "password", "original_key": None}

    @staticmethod
    def _cleanup_ssh_side_effect(args, state):
        args.auth = state.get("original_auth")
        args.key = state.get("original_key")

    def test_setup_called_when_needed(self):
        with patch.object(cli, "server_command_needs_password_session", return_value=True):
            with patch.object(cli, "setup_temporary_ssh_trust",
                              side_effect=self._setup_ssh_side_effect) as mock_ssh:
                with patch.object(cli, "setup_temporary_sudo_trust", return_value="/tmp/sudo") as mock_sudo:
                    with patch.object(cli, "cleanup_temporary_sudo_trust"):
                        with patch.object(cli, "cleanup_temporary_ssh_trust",
                                          side_effect=self._cleanup_ssh_side_effect):
                            with cli.temporary_password_session_if_needed(self.args):
                                mock_ssh.assert_called_once()
                                mock_sudo.assert_called_once()

    def test_auth_switched_to_key_inside_context(self):
        with patch.object(cli, "server_command_needs_password_session", return_value=True):
            with patch.object(cli, "setup_temporary_ssh_trust",
                              side_effect=self._setup_ssh_side_effect):
                with patch.object(cli, "setup_temporary_sudo_trust", return_value="/tmp/sudo"):
                    with patch.object(cli, "cleanup_temporary_sudo_trust"):
                        with patch.object(cli, "cleanup_temporary_ssh_trust",
                                          side_effect=self._cleanup_ssh_side_effect):
                            with cli.temporary_password_session_if_needed(self.args):
                                self.assertEqual(self.args.auth, "key")
                                self.assertEqual(self.args.key, "/tmp/fake_temp_key")

    def test_auth_and_key_restored_after_context_exit(self):
        with patch.object(cli, "server_command_needs_password_session", return_value=True):
            with patch.object(cli, "setup_temporary_ssh_trust",
                              side_effect=self._setup_ssh_side_effect):
                with patch.object(cli, "setup_temporary_sudo_trust", return_value="/tmp/sudo"):
                    with patch.object(cli, "cleanup_temporary_sudo_trust"):
                        with patch.object(cli, "cleanup_temporary_ssh_trust",
                                          side_effect=self._cleanup_ssh_side_effect):
                            with cli.temporary_password_session_if_needed(self.args):
                                pass
        self.assertEqual(self.args.auth, "password")
        self.assertIsNone(self.args.key)

    def test_password_session_does_not_call_new_helper_before_server_patch(self):
        with patch.object(cli, "server_command_needs_password_session", return_value=True), \
             patch.object(cli, "setup_temporary_ssh_trust", side_effect=self._setup_ssh_side_effect), \
             patch.object(cli, "setup_temporary_sudo_trust", return_value="/tmp/sudo"), \
             patch.object(cli, "cleanup_stale_temporary_sudo_trust") as cleanup, \
             patch.object(cli, "cleanup_temporary_sudo_trust"), \
             patch.object(cli, "cleanup_temporary_ssh_trust", side_effect=self._cleanup_ssh_side_effect):
            with cli.temporary_password_session_if_needed(self.args):
                cleanup.assert_not_called()

    def test_key_auth_patch_only_cleans_stale_ssh_keys_before_body(self):
        args = make_args(auth="key", command="patch", host="srv")
        with patch.object(cli, "cleanup_stale_lanfabric_temp_keys") as cleanup_keys, \
             patch.object(cli, "cleanup_stale_temporary_sudo_trust") as cleanup_sudo:
            with cli.temporary_password_session_if_needed(args):
                cleanup_keys.assert_called_once_with(args)
                cleanup_sudo.assert_not_called()

    def test_cleanup_called_on_exception(self):
        with patch.object(cli, "server_command_needs_password_session", return_value=True):
            with patch.object(cli, "setup_temporary_ssh_trust",
                              side_effect=self._setup_ssh_side_effect):
                with patch.object(cli, "setup_temporary_sudo_trust", return_value="/tmp/sudo"):
                    with patch.object(cli, "cleanup_temporary_sudo_trust") as mock_cleanup_sudo:
                        with patch.object(cli, "cleanup_temporary_ssh_trust",
                                          side_effect=self._cleanup_ssh_side_effect) as mock_cleanup_ssh:
                            try:
                                with cli.temporary_password_session_if_needed(self.args):
                                    raise RuntimeError("test error")
                            except RuntimeError:
                                pass
        mock_cleanup_sudo.assert_called_once()
        mock_cleanup_ssh.assert_called_once()
        self.assertEqual(self.args.auth, "password")
        self.assertIsNone(self.args.key)


# ===================================================================
# E. sudoers rule
# ===================================================================

class TestSudoersRule(unittest.TestCase):

    def test_contains_vsrv_admin(self):
        rule = cli.sudoers_rule_for_user("donpedro")
        self.assertIn("/usr/bin/python3 /opt/vpn-admin/vsrv-admin.py *", rule)

    def test_no_unrestricted_shell(self):
        rule = cli.sudoers_rule_for_user("donpedro")
        self.assertNotIn("/bin/sh *", rule)
        self.assertNotIn("/bin/bash *", rule)

    def test_sudoers_allowlist_excludes_python3_c(self):
        """Sudoers allowlist не разрешает произвольный python3 -c."""
        rule = cli.sudoers_rule_for_user("donpedro")
        self.assertIn("/usr/bin/python3 /opt/vpn-admin/vsrv-admin.py *", rule)
        self.assertNotIn("python3 -c", rule)

    def test_sudoers_format_structure(self):
        rule = cli.sudoers_rule_for_user("donpedro")
        self.assertTrue(rule.startswith("donpedro ALL=(ALL) NOPASSWD:"))


# ===================================================================
# F. Known defects (expected failures / risk checks)
# ===================================================================

class TestKnownDefects(unittest.TestCase):

    def _add_trust(self, home, line, calls=None):
        def fake_exec(_args, command, **kwargs):
            if calls is not None:
                calls.append(command)
            env = os.environ.copy()
            env["HOME"] = home
            env["USERPROFILE"] = home
            result = subprocess.run(
                [sys.executable, "-c", command[2], *command[3:]],
                env=env, capture_output=True, text=True
            )
            if result.returncode:
                raise RuntimeError(result.stderr or result.stdout)
            return result.stdout

        with patch.object(cli, "ensure_remote_ssh_dir"), \
             patch.object(cli, "exec_remote", side_effect=fake_exec):
            cli.add_authorized_key_line(make_args(), line)

    def test_trust_potential_duplicate(self):
        """RISK: повторный trust с тем же public key и новым nonce
        может создать дубликат в authorized_keys, потому что
        add_authorized_key_line использует grep -Fxq для проверки всей строки,
        а каждая строка содержит уникальный nonce."""
        key_line_1 = "ssh-ed25519 AAAAB3NzaC1test lanfabric-trust:host=s:user=u:client=c1:created=2024-01-01T00-00-00Z:nonce=abc"
        key_line_2 = "ssh-ed25519 AAAAB3NzaC1test lanfabric-trust:host=s:user=u:client=c1:created=2024-01-01T00-01-00Z:nonce=def"
        self.assertEqual(
            key_line_1.split()[0:2], key_line_2.split()[0:2],
            "Один и тот же публичный ключ"
        )
        self.assertNotEqual(
            key_line_1, key_line_2,
            "Строки различаются из-за nonce: grep -Fxq не обнаружит дубликат"
        )

        key = "ssh-ed25519 AAAAB3NzaC1test"
        first = make_lanfabric_key_line(key, kind="lanfabric-trust", nonce="first")
        second = make_lanfabric_key_line(key, kind="lanfabric-trust", nonce="second")
        with tempfile.TemporaryDirectory() as home:
            os.makedirs(os.path.join(home, ".ssh"))
            path = os.path.join(home, ".ssh", "authorized_keys")
            open(path, "w", encoding="utf-8").close()
            calls = []
            self._add_trust(home, first, calls)
            self._add_trust(home, second, calls)
            with open(path, encoding="utf-8") as f:
                content = f.read()
            owned = [line for line in content.splitlines()
                     if "lanfabric-trust:" in line and line.split()[:2] == key.split()]
            self.assertEqual(owned, [second.rstrip("\n")])
            self.assertEqual(len([c for c in calls if c[0] == "python3"]), 2)

    def test_trust_collapses_existing_duplicates_and_preserves_other_lines(self):
        key = "ssh-ed25519 AAAAB3NzaC1test"
        old = make_lanfabric_key_line(key, kind="lanfabric-trust", nonce="old")
        duplicate = make_lanfabric_key_line(key, kind="lanfabric-trust", nonce="duplicate")
        current = make_lanfabric_key_line(key, kind="lanfabric-trust", nonce="current")
        foreign_other = foreign_key_line("ssh-rsa AAAAforeign-other")
        foreign_same = foreign_key_line(key)
        temp_same = make_lanfabric_key_line(key, kind="lanfabric-temp", nonce="temp")
        trust_other = make_lanfabric_key_line(
            "ssh-ed25519 AAAAother-trust", kind="lanfabric-trust", nonce="other"
        )
        original = old + duplicate + foreign_other + foreign_same + temp_same + trust_other
        with tempfile.TemporaryDirectory() as home:
            os.makedirs(os.path.join(home, ".ssh"))
            path = os.path.join(home, ".ssh", "authorized_keys")
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(original)
            self._add_trust(home, current)
            with open(path, encoding="utf-8", newline="") as f:
                content = f.read()
            owned = [line for line in content.splitlines()
                     if "lanfabric-trust:" in line and line.split()[:2] == key.split()]
            self.assertEqual(owned, [current.rstrip("\n")])
            normalized = content.replace("\r\n", "\n")
            self.assertIn(foreign_other, normalized)
            self.assertIn(foreign_same, normalized)
            self.assertIn(temp_same, normalized)
            self.assertIn(trust_other, normalized)
            if os.name == "posix":
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_invalid_trust_line_does_not_change_file(self):
        with tempfile.TemporaryDirectory() as home:
            os.makedirs(os.path.join(home, ".ssh"))
            path = os.path.join(home, ".ssh", "authorized_keys")
            original = "ssh-ed25519 AAAAexisting foreign\n"
            with open(path, "w", encoding="utf-8") as f:
                f.write(original)
            with patch.object(cli, "ensure_remote_ssh_dir") as ensure, \
                 patch.object(cli, "exec_remote") as execute:
                with self.assertRaises(RuntimeError):
                    cli.add_authorized_key_line(make_args(), "ssh-ed25519 AAAAexisting foreign")
            with open(path, encoding="utf-8") as f:
                self.assertEqual(f.read(), original)
            ensure.assert_not_called()
            execute.assert_not_called()

    def test_untrust_two_separate_ssh_calls(self):
        """Обычный untrust сначала отзывает passwordless sudo trust."""
        args = make_args(confirm="", temp=False, all_lanfabric=None)
        calls = []
        with patch.object(cli, "cleanup_stale_lanfabric_temp_keys"), \
             patch.object(cli, "cleanup_permanent_sudo_trust", side_effect=lambda *a, **k: calls.append("sudo")), \
             patch.object(cli, "remove_authorized_key_by_marker", side_effect=lambda *a, **k: calls.append("ssh") or 1):
            cli.cmd_untrust(args)
        self.assertEqual(calls, ["sudo", "ssh"])

        with patch.object(cli, "cleanup_stale_lanfabric_temp_keys"), \
             patch.object(cli, "cleanup_permanent_sudo_trust", side_effect=RuntimeError("sudo failed")), \
             patch.object(cli, "remove_authorized_key_by_marker") as remove_key:
            with self.assertRaises(RuntimeError):
                cli.cmd_untrust(args)
        remove_key.assert_not_called()

    def test_cleanup_stale_sudoers_not_in_sudoers_allowlist(self):
        """Cleanup использует существующий узкий server allowlist."""
        rule = cli.sudoers_rule_for_user("donpedro")
        self.assertNotIn("python3 -c", rule)

        args = make_args(user="donpedro")
        commands = []

        def fake_exec(_args, command, **kwargs):
            commands.append(command)
            return "1\n"

        with patch.object(cli, "exec_remote", side_effect=fake_exec):
            self.assertEqual(cli.cleanup_stale_temporary_sudo_trust(args), 1)
        self.assertEqual(commands[0], ["sudo", "-n", "python3", cli.REMOTE_SCRIPT,
                                       "_cleanup-temp-sudoers", "--user", "donpedro",
                                       "--ttl", "3600"])

    def test_cleanup_stale_sudoers_uses_privileged_internal_helper(self):
        args = make_args(user="donpedro")
        commands = []

        def fake_exec(_args, command, **kwargs):
            commands.append(command)
            return "2\n"

        with patch.object(cli, "exec_remote", side_effect=fake_exec):
            self.assertEqual(cli.cleanup_stale_temporary_sudo_trust(args), 2)
        self.assertEqual(
            commands,
            [["sudo", "-n", "python3", cli.REMOTE_SCRIPT,
              "_cleanup-temp-sudoers", "--user", "donpedro", "--ttl", "3600"]],
        )

    def test_cleanup_stale_sudoers_all_uses_only_internal_all(self):
        args = make_args(user="donpedro")
        with patch.object(cli, "exec_remote", return_value="1\n") as execute:
            self.assertEqual(cli.cleanup_stale_temporary_sudo_trust(args, remove_all_temp=True), 1)
        self.assertEqual(
            execute.call_args.args[1],
            ["sudo", "-n", "python3", cli.REMOTE_SCRIPT,
             "_cleanup-temp-sudoers", "--user", "donpedro", "--all"],
        )

    def test_cleanup_stale_sudoers_does_not_use_client_python_scan(self):
        source = inspect.getsource(cli.cleanup_stale_temporary_sudo_trust)
        self.assertNotIn("os.listdir('/etc/sudoers.d')", source)
        self.assertNotIn("os.listdir(\"/etc/sudoers.d\")", source)
        self.assertNotIn("[\"sudo\", \"python3\", \"-c\"", source)

    def test_patch_runs_new_cleanup_only_after_copy_and_version_check(self):
        args = make_args(command="patch")
        events = []
        with patch.object(cli, "get_remote_version", side_effect=["0.0.16", "0.0.17"]), \
             patch.object(cli, "ensure_sudo_nopasswd", side_effect=lambda a: events.append("sudo")), \
             patch.object(cli, "copy_server_module", side_effect=lambda a: events.append("copy")), \
             patch.object(cli, "cleanup_stale_temporary_sudo_trust", side_effect=lambda a: events.append("cleanup") or 0), \
             patch.object(cli, "add_advice"):
            cli.cmd_patch(args)
        self.assertEqual(events, ["sudo", "copy", "cleanup"])

    def test_key_auth_equal_flow_cleans_sudoers_once(self):
        args = make_args(auth="key", command="status", host="srv")
        with patch.object(cli, "cleanup_stale_lanfabric_temp_keys"), \
             patch.object(cli, "get_remote_version", return_value="0.0.17"), \
             patch.object(cli, "cleanup_stale_temporary_sudo_trust") as cleanup:
            with cli.temporary_password_session_if_needed(args):
                self.assertEqual(cli.ensure_remote_version_compatible(args), "0.0.17")
        cleanup.assert_called_once_with(args)

    def test_key_auth_mismatch_flow_does_not_clean_sudoers(self):
        args = make_args(auth="key", command="status", host="srv")
        with patch.object(cli, "cleanup_stale_lanfabric_temp_keys"), \
             patch.object(cli, "get_remote_version", return_value="0.0.16"), \
             patch.object(cli, "cleanup_stale_temporary_sudo_trust") as cleanup:
            with cli.temporary_password_session_if_needed(args):
                with self.assertRaises(cli.VersionMismatchError):
                    cli.ensure_remote_version_compatible(args)
        cleanup.assert_not_called()

    def test_equal_version_runs_background_cleanup_once(self):
        args = make_args()
        with patch.object(cli, "get_remote_version", return_value="0.0.17"), \
             patch.object(cli, "cleanup_stale_temporary_sudo_trust") as cleanup:
            self.assertEqual(cli.ensure_remote_version_compatible(args), "0.0.17")
        cleanup.assert_called_once_with(args)

    def test_patch_mismatch_does_not_run_background_cleanup(self):
        args = make_args()
        with patch.object(cli, "get_remote_version", return_value="0.0.16"), \
             patch.object(cli, "cleanup_stale_temporary_sudo_trust") as cleanup:
            with self.assertRaises(cli.VersionMismatchError):
                cli.ensure_remote_version_compatible(args)
        cleanup.assert_not_called()

    def test_patch_equal_is_noop_and_cleans_sudoers_once(self):
        args = make_args(command="patch")
        with patch.object(cli, "get_remote_version", return_value="0.0.17"), \
             patch.object(cli, "copy_server_module") as copy, \
             patch.object(cli, "cleanup_stale_temporary_sudo_trust") as cleanup, \
             patch.object(cli, "add_advice"):
            cli.cmd_patch(args)
        copy.assert_not_called()
        cleanup.assert_called_once_with(args)

    def test_internal_cleanup_requires_matching_sudo_user(self):
        with patch.dict(srv.os.environ, {"SUDO_USER": "donpedro"}):
            with patch.object(srv, "_cleanup_temp_sudoers", return_value=1) as cleanup:
                self.assertEqual(
                    srv._run_internal_cleanup_temp_sudoers(["--user", "donpedro", "--all"]),
                    1,
                )
        cleanup.assert_called_once_with("donpedro", 3600, True)

    def test_internal_cleanup_rejects_other_sudo_user(self):
        with patch.dict(srv.os.environ, {"SUDO_USER": "other"}):
            with patch.object(srv, "_cleanup_temp_sudoers") as cleanup:
                with self.assertRaises(RuntimeError):
                    srv._run_internal_cleanup_temp_sudoers(["--user", "donpedro"])
        cleanup.assert_not_called()

    def test_internal_cleanup_requires_sudo_user(self):
        with patch.dict(srv.os.environ, {}, clear=True):
            with patch.object(srv, "_cleanup_temp_sudoers") as cleanup:
                with self.assertRaises(RuntimeError):
                    srv._run_internal_cleanup_temp_sudoers(["--user", "donpedro"])
        cleanup.assert_not_called()

    def test_internal_cleanup_compares_sanitized_users(self):
        with patch.dict(srv.os.environ, {"SUDO_USER": "don/pedro"}):
            with patch.object(srv, "_cleanup_temp_sudoers", return_value=0) as cleanup:
                self.assertEqual(
                    srv._run_internal_cleanup_temp_sudoers(["--user", "don_pedro"]),
                    0,
                )
        cleanup.assert_called_once_with("don_pedro", 3600, False)

    def test_untrust_all_and_temp_are_sudoers_first(self):
        for mode in ("all", "temp"):
            args = make_args(
                confirm="REMOVE-ALL-LANFABRIC-KEYS" if mode == "all" else "",
                temp=mode == "temp",
                all_lanfabric="REMOVE-ALL-LANFABRIC-KEYS" if mode == "all" else None,
            )
            calls = []
            with patch.object(cli, "cleanup_stale_lanfabric_temp_keys", side_effect=lambda *a, **k: calls.append("keys") or 0), \
                 patch.object(cli, "cleanup_stale_temporary_sudo_trust", side_effect=lambda *a, **k: calls.append("temp-sudo") or 0), \
                 patch.object(cli, "cleanup_permanent_sudo_trust", side_effect=lambda *a, **k: calls.append("sudo") or 0), \
                 patch.object(cli, "remove_authorized_key_by_marker", side_effect=lambda *a, **k: calls.append("ssh") or 0):
                cli.cmd_untrust(args)
            expected = ["temp-sudo", "keys"] if mode == "temp" else ["sudo", "ssh"]
            self.assertEqual(calls, expected)


    def test_marker_split_by_colon_no_longer_breaks_timestamp_parsing(self):
        """Исправлено: re.split вместо split(':') —
        created с ISO-временем (22:10:19Z) парсится целиком."""
        marker_text = "lanfabric-temp:host=s:user=u:client=c1:created=2026-06-09T22:10:19Z:ttl=3600:nonce=abc"
        fields = _parse_marker_fields(marker_text)
        self.assertEqual(fields.get("created"), "2026-06-09T22:10:19Z")
        self.assertEqual(fields.get("ttl"), "3600")
        self.assertEqual(fields.get("nonce"), "abc")


# ===================================================================
# G. Marker parsing with ISO-time (created содержит двоеточия)
# ===================================================================

class TestMarkerParsingWithIsoTime(unittest.TestCase):

    def test_temp_marker_with_iso_time_parsed_correctly(self):
        """Marker с ISO-временем (двоеточия в created) не ломается."""
        marker = "lanfabric-temp:host=198.51.100.42:user=donpedro:client=abc123:created=2026-06-09T22:10:19Z:ttl=3600:nonce=n1"
        fields = _parse_marker_fields(marker)
        self.assertEqual(fields.get("created"), "2026-06-09T22:10:19Z")
        self.assertEqual(fields.get("ttl"), "3600")
        self.assertEqual(fields.get("nonce"), "n1")
        self.assertEqual(fields.get("host"), "198.51.100.42")
        self.assertEqual(fields.get("user"), "donpedro")

    def test_expired_temp_marker_with_iso_time_removed(self):
        """Просроченный temp marker удаляется корректно (created в ISO-формате)."""
        created_str = "2026-06-09T10:00:00Z"
        created_ts = datetime.datetime.fromisoformat(created_str.replace("Z", "+00:00")).timestamp()
        now_past = created_ts + 7200  # TTL=3600, now > created + TTL
        foreign = foreign_key_line()
        expired = make_lanfabric_key_line(
            "ssh-ed25519 AAAExpiredIso", kind="lanfabric-temp",
            host="s", user="u", client="c1", nonce="exp-iso", ttl=3600,
            created=created_str
        )
        fresh = make_lanfabric_key_line(
            "ssh-ed25519 AAAFreshIso", kind="lanfabric-temp",
            host="s", user="u", client="c1", nonce="fresh-iso", ttl=3600,
            created="2026-06-09T11:50:00Z"
        )
        lines = [foreign, expired, fresh]
        new, removed = filter_stale_temp_keys(lines, remove_all=False, now=now_past)
        self.assertIn(foreign, new, "Foreign key должен сохраниться")
        self.assertIn(fresh, new, "Свежий temp marker должен сохраниться")
        self.assertNotIn(expired, new, "Просроченный temp marker должен быть удалён")
        self.assertEqual(removed, 1)

    def test_fresh_temp_marker_with_iso_time_preserved(self):
        """Непросроченный temp marker с двоеточиями в created сохраняется."""
        created_str = "2026-06-09T10:30:00Z"
        created_ts = datetime.datetime.fromisoformat(created_str.replace("Z", "+00:00")).timestamp()
        now_fresh = created_ts + 600  # TTL=3600, now < created + TTL (600s < 3600s)
        valid_line = make_lanfabric_key_line(
            "ssh-ed25519 AAAFreshIso", kind="lanfabric-temp",
            host="s", user="u", client="c1", nonce="fresh-iso", ttl=3600,
            created=created_str
        )
        lines = [foreign_key_line(), valid_line]
        new, removed = filter_stale_temp_keys(lines, remove_all=False, now=now_fresh)
        self.assertIn(valid_line, new, "Свежий temp marker не должен удаляться")
        self.assertEqual(removed, 0)

    def test_corrupted_temp_marker_without_iso_removed(self):
        """Повреждённый temp marker удаляется (created содержит непарсибельное значение)."""
        now_val = datetime.datetime.fromisoformat("2026-06-09T11:00:00Z".replace("Z", "+00:00")).timestamp()
        corrupted = "ssh-ed25519 AAAACorrupted lanfabric-temp:host=s:user=u:client=c1:created=bad-time:ttl=3600:nonce=n1\n"
        lines = [foreign_key_line(), corrupted]
        new, removed = filter_stale_temp_keys(lines, remove_all=False, now=now_val)
        self.assertIn(foreign_key_line(), new, "Foreign key должен сохраниться")
        self.assertNotIn(corrupted, new, "Повреждённый marker должен быть удалён")
        self.assertEqual(removed, 1)

    def test_temp_sudoers_marker_parsed_correctly(self):
        """Temporary sudoers marker (# lanfabric-temp-sudo:...) парсится корректно."""
        marker = "lanfabric-temp-sudo:host=198.51.100.42:user=donpedro:client=abc123:created=2026-06-09T22:10:19Z:ttl=3600:nonce=n1"
        fields = _parse_marker_fields(marker)
        self.assertEqual(fields.get("created"), "2026-06-09T22:10:19Z")
        self.assertEqual(fields.get("ttl"), "3600")
        self.assertEqual(fields.get("nonce"), "n1")

    def test_trust_marker_with_iso_time_no_ttl(self):
        """Trust marker (без ttl) с ISO-временем не ломается."""
        marker = "lanfabric-trust:host=198.51.100.42:user=donpedro:client=abc123:created=2026-06-09T22:10:19Z:nonce=n1"
        fields = _parse_marker_fields(marker)
        self.assertEqual(fields.get("created"), "2026-06-09T22:10:19Z")
        self.assertNotIn("ttl", fields)
        self.assertEqual(fields.get("nonce"), "n1")


# ===================================================================
# Version parsing
# ===================================================================

class TestVersionParsing(unittest.TestCase):

    def test_parse_version_equal(self):
        self.assertEqual(cli.parse_version("0.0.15"), (0, 0, 15))

    def test_parse_version_major_minor_patch(self):
        self.assertEqual(cli.parse_version("1.2.3"), (1, 2, 3))

    def test_parse_version_invalid_raises(self):
        with self.assertRaises(RuntimeError):
            cli.parse_version("abc")

    def test_compare_equal(self):
        self.assertEqual(cli.compare_versions("1.0.0", "1.0.0"), "equal")

    def test_compare_patch_mismatch(self):
        self.assertEqual(cli.compare_versions("1.0.1", "1.0.2"), "patch_mismatch")

    def test_compare_incompatible(self):
        self.assertEqual(cli.compare_versions("2.0.0", "1.0.0"), "incompatible")


# ===================================================================
# Additional checks
# ===================================================================

class TestAdditionalChecks(unittest.TestCase):

    def test_version_is_0_0_17(self):
        self.assertEqual(cli.__version__, "0.0.17")

    def test_module_has_required_functions(self):
        for name in ["lanfabric_marker", "current_client_id", "build_ssh_cmd",
                      "sudoers_rule_for_user", "temporary_password_session_if_needed",
                      "setup_temporary_ssh_trust", "cleanup_temporary_ssh_trust",
                      "add_authorized_key_line", "remove_authorized_key_by_marker"]:
            self.assertTrue(hasattr(cli, name),
                            f"Функция {name} отсутствует в vcli-admin.py")

    def test_utc_now_text_format(self):
        text = cli.utc_now_text()
        self.assertTrue(text.endswith("Z"))
        datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))

    def test_sudoers_allows_specific_commands(self):
        rule = cli.sudoers_rule_for_user("donpedro")
        for cmd in ["apt-get", "systemctl", "iptables", "ip", "mkdir", "chmod", "rm"]:
            self.assertIn(cmd, rule)


class TestServerTemporarySudoersCleanup(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = self.directory.name

    def tearDown(self):
        self.directory.cleanup()

    def touch(self, name, age=7200):
        path = os.path.join(self.path, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("SECRET MUST NOT BE READ")
        os.utime(path, (time.time() - age, time.time() - age))
        return path

    def test_stale_exact_file_removed_and_fresh_preserved(self):
        stale = self.touch("lanfabric-temp-donpedro-0123456789ab")
        fresh = self.touch("lanfabric-temp-donpedro-abcdefabcdef", age=10)
        self.assertEqual(srv._cleanup_temp_sudoers("donpedro", 3600, False, self.path), 1)
        self.assertFalse(os.path.exists(stale))
        self.assertTrue(os.path.exists(fresh))

    def test_all_removes_only_exact_files_for_sanitized_user(self):
        target = self.touch("lanfabric-temp-don_pedro-0123456789ab", age=10)
        other = self.touch("lanfabric-temp-other-0123456789ab", age=10)
        self.assertEqual(srv._cleanup_temp_sudoers("don/pedro", 3600, True, self.path), 1)
        self.assertFalse(os.path.exists(target))
        self.assertTrue(os.path.exists(other))

    def test_foreign_permanent_and_invalid_files_survive(self):
        names = [
            "lanfabric-trust-donpedro",
            "vpn-admin",
            "foreign-file",
            "lanfabric-temp-donpedro-not-a-nonce",
            "lanfabric-temp-donpedro-0123456789aG",
        ]
        for name in names:
            self.touch(name)
        self.assertEqual(srv._cleanup_temp_sudoers("donpedro", 3600, True, self.path), 0)
        for name in names:
            self.assertTrue(os.path.exists(os.path.join(self.path, name)))

    def test_cleanup_does_not_read_file_contents(self):
        self.touch("lanfabric-temp-donpedro-0123456789ab")
        with patch.object(srv, "open", side_effect=AssertionError("content read")):
            self.assertEqual(srv._cleanup_temp_sudoers("donpedro", 3600, True, self.path), 1)

    def test_public_help_does_not_advertise_internal_command(self):
        result = subprocess.run(
            [sys.executable, srv.__file__, "help"],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("_cleanup-temp-sudoers", result.stdout + result.stderr)


# ===================================================================
# Запуск
# ===================================================================

if __name__ == "__main__":
    unittest.main()
