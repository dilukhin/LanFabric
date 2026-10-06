"""Регрессии порта и проверки применённых параметров; без настоящего VPN."""
import importlib.util
import base64
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

srv = load("srv_awg31_runtime", "vsrv-admin.py")
cli = load("cli_awg31_runtime", "vcli-admin.py")

class TestSavedPort(unittest.TestCase):
    def test_absent_legacy_port_does_not_create_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "port"
            with patch.object(srv, "LISTEN_PORT_PATH", str(path)):
                self.assertEqual(srv.read_listen_port(), 51820)
            self.assertFalse(path.exists())

    def test_port_persists_and_server_client_exports_agree(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "port"
            public = Path(tmp) / "wg0.public"
            public.write_text("public-key")
            row = dict(privkey="private-key", ip="10.8.0.2", internet=1)
            with patch.object(srv, "LISTEN_PORT_PATH", str(path)), \
                 patch.object(srv, "WG_DIR", tmp), patch.object(srv, "require_backend", return_value="awg"), \
                 patch.object(srv, "read_awg_params_file", return_value=srv.generate_awg31_params()):
                srv.write_listen_port(4387)
                self.assertEqual(srv.read_listen_port(), 4387)
                self.assertIn("ListenPort = 4387", srv.build_setconf("private-key", "awg"))
                self.assertIn("Endpoint = 45.144.232.170:4387", srv.build_client_config(row, "45.144.232.170"))
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_bad_existing_port_is_not_replaced_with_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "port"
            for text in ("", "0", "65536", "-1", "43\n87", "secret-invalid"):
                path.write_text(text)
                with self.subTest(text=text), patch.object(srv, "LISTEN_PORT_PATH", str(path)):
                    with self.assertRaises(RuntimeError) as caught:
                        srv.read_listen_port()
                    self.assertNotIn("secret-invalid", str(caught.exception))
                    self.assertEqual(path.read_text(), text)

    def test_bad_init_options_fail_before_any_mutation(self):
        for args in (SimpleNamespace(no_amnezia=False, listen_port=65536),
                     SimpleNamespace(no_amnezia=True, listen_port=4387, awg_profile="awg31")):
            with self.subTest(args=args), patch.object(srv, "ensure_dirs") as dirs, \
                 patch.object(srv, "disable_awg_autostart") as disable, \
                 patch.object(srv, "run_cmd") as run:
                with self.assertRaises(RuntimeError):
                    srv.cmd_init(args)
                dirs.assert_not_called()
                disable.assert_not_called()
                run.assert_not_called()

    def test_mismatched_saved_profile_fails_before_cleanup(self):
        with patch.object(srv, "read_listen_port", return_value=4387), \
             patch.object(srv.os.path, "exists", return_value=True), \
             patch.object(srv, "read_awg_params_file", return_value=srv.generate_awg_params()), \
             patch.object(srv, "ensure_dirs") as dirs, patch.object(srv, "cleanup_runtime") as cleanup:
            with self.assertRaises(RuntimeError):
                srv.cmd_init(SimpleNamespace(no_amnezia=False, awg_profile="awg31"))
            dirs.assert_not_called()
            cleanup.assert_not_called()

    def test_cli_forwards_explicit_options_as_separate_arguments(self):
        args = SimpleNamespace(no_amnezia=False, listen_port=4387, awg_profile="awg31")
        with patch.object(cli, "ensure_sudo_nopasswd"), patch.object(cli, "copy_server_module"), \
             patch.object(cli, "exec_remote", return_value="") as remote:
            cli.cmd_init(args)
        self.assertEqual(remote.call_args.args[1][-4:], ["--listen-port", "4387", "--awg-profile", "awg31"])

class TestRuntimeProfile(unittest.TestCase):
    def test_zero_header_key_cannot_validate_unsupported_runtime(self):
        params = srv.generate_awg31_params()
        params["HeaderProtectionKey"] = base64.b64encode(bytes(32)).decode("ascii")
        with self.assertRaises(RuntimeError):
            srv.validate_awg_params(params)

    def test_equal_junk_sizes_are_modern_only(self):
        params = srv.generate_awg31_params()
        params["Jmin"] = params["Jmax"] = 50
        self.assertEqual(srv.validate_awg_params(params)["Jmin"], 50)
        legacy = srv.generate_awg_params()
        legacy["Jmin"] = legacy["Jmax"] = 50
        with self.assertRaises(RuntimeError):
            srv.validate_awg_params(legacy)

    def test_readiness_uses_saved_port_and_exact_socket_filter(self):
        state = dict(backend="awg", wg_bin="awg", server_public_key="public", users=[],
                     listen_port=4387, awg_params=srv.generate_awg31_params())
        answers = {
            "ip -d link show wg0": "amneziawg", "ip link show wg0": "wg0: <UP>",
            "awg show wg0 public-key": "public", "ip -4 -o addr show dev wg0": "1: wg0 inet 10.8.0.1/24",
            "awg show wg0 listen-port": "51820", "awg show wg0 peers": "", "awg show wg0 allowed-ips": "",
            "ss -ulnH 'sport = :4387'": "", "sysctl -n net.ipv4.ip_forward": "1",
        }
        with patch.object(srv, "run_cmd", side_effect=lambda c, check=True: answers[c]) as run, \
             patch.object(srv, "awg31_runtime_errors", return_value=[]):
            errors = srv.runtime_readiness_errors(state, check_firewall=False)
        self.assertTrue(any("ListenPort" in e for e in errors))
        self.assertTrue(any("4387/UDP" in e for e in errors))
        self.assertIn("ss -ulnH 'sport = :4387'", [c.args[0] for c in run.call_args_list])

    def test_profile_failure_keeps_guard_closed(self):
        state = dict(backend="awg", wg_bin="awg", server_private_key="private", server_public_key="public",
                     users=[], listen_port=4387, awg_params=srv.generate_awg31_params())
        with patch.object(srv, "awg_interface_ownership", return_value="absent"), \
             patch.object(srv, "close_firewall_guard") as close, patch.object(srv, "write_setconf", return_value="/tmp/config"), \
             patch.object(srv, "prepare_internet_policy", return_value=state), \
             patch.object(srv, "public_client_firewall_rules", return_value=[]), patch.object(srv, "_apply_awg_peers"), \
             patch.object(srv, "rebuild_policy_chains"), patch.object(srv, "run_cmd", return_value=""), \
             patch.object(srv, "runtime_readiness_errors", return_value=["AWG 3.1 несовместим"]), \
             patch.object(srv, "firewall_readiness_errors", return_value=[]), patch.object(srv, "open_firewall_guard") as opened:
            with self.assertRaises(RuntimeError):
                srv._restore_awg_runtime_locked(state)
            opened.assert_not_called()
            self.assertGreaterEqual(close.call_count, 2)

    def test_setconf_failure_sanitizes_secret_and_keeps_guard_closed(self):
        state = dict(backend="awg", server_private_key="private", listen_port=4387,
                     awg_params=srv.generate_awg31_params(), users=[])
        def invoke(command, check=True):
            if command.startswith("awg setconf"):
                raise RuntimeError("HeaderProtectionKey = secret-value")
            return ""
        with patch.object(srv, "awg_interface_ownership", return_value="absent"), \
             patch.object(srv, "close_firewall_guard") as close, patch.object(srv, "write_setconf", return_value="/tmp/config"), \
             patch.object(srv, "run_cmd", side_effect=invoke), patch.object(srv, "open_firewall_guard") as opened:
            with self.assertRaises(RuntimeError) as caught:
                srv._restore_awg_runtime_locked(state)
            self.assertNotIn("secret-value", str(caught.exception))
            self.assertTrue(caught.exception.__suppress_context__)
            opened.assert_not_called()
            self.assertGreaterEqual(close.call_count, 2)

    def test_complete_readback_includes_key_and_typo_in_pinned_tools(self):
        params = srv.generate_awg31_params()
        expected = iter(params[key] for key in srv.AWG_PARAM_KEYS + ("S3", "S4", "HeaderProtectionKey",
            "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
            "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies"))
        commands = []
        def invoke(command, **kwargs):
            commands.append(command)
            value = str(next(expected))
            if command[-1] in ("h1", "h2", "h3", "h4"):
                value += "-" + value
            return SimpleNamespace(returncode=0, stdout=value + "\n", stderr="")
        with patch.object(srv.subprocess, "run", side_effect=invoke):
            self.assertEqual(srv.awg31_runtime_errors(params), [])
        self.assertIn(["awg", "show", "wg0", "max-handshake-attemps"], commands)
        self.assertIn(["awg", "show", "wg0", "header-protection-key"], commands)
        self.assertTrue(all(len(cmd) == 4 for cmd in commands))

    def test_readback_failure_never_reports_output_or_secret(self):
        params = srv.generate_awg31_params()
        for response in (SimpleNamespace(returncode=1, stdout=params["HeaderProtectionKey"], stderr="secret-error"),
                         subprocess.TimeoutExpired("awg", 2, output="secret-output")):
            with self.subTest(response=type(response).__name__):
                kwargs = {"side_effect":response} if isinstance(response, Exception) else {"return_value":response}
                with patch.object(srv.subprocess, "run", **kwargs):
                    result = srv.awg31_runtime_errors(params)
                self.assertTrue(result)
                self.assertNotIn(params["HeaderProtectionKey"], str(result))
                self.assertNotIn("secret-", str(result))

    def test_ignored_parameter_is_failure(self):
        params = srv.generate_awg31_params()
        with patch.object(srv.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="0")):
            self.assertTrue(srv.awg31_runtime_errors(params))

    def test_legacy_readback_needs_no_new_tools(self):
        with patch.object(srv.subprocess, "run") as run:
            self.assertEqual(srv.awg31_runtime_errors(srv.generate_awg_params()), [])
            run.assert_not_called()

    def test_scalar_only_fields_reject_ranges(self):
        for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"):
            params = srv.generate_awg31_params()
            params[key] = "12-13"
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                srv.validate_awg_params(params)

if __name__ == "__main__":
    unittest.main()
