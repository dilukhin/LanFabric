#!/usr/bin/env python3
"""Изолированные проверки выводов инспекции; без SSH, сети и системных изменений.

Запуск: python3 inspection_probes.py /путь/к/снимку/LanFabric
Проверяет наличие наблюдаемого поведения 0.0.17, а не приёмку исправления.
Все файлы создаются в TemporaryDirectory, внешние команды подменяются.
"""
import contextlib
import importlib.util
import io
import json
import logging
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect(source):
    srv = load_module("inspection_srv", source / "vsrv-admin.py")
    cli = load_module("inspection_cli", source / "vcli-admin.py")
    results = {}
    logging.disable(logging.CRITICAL)
    with tempfile.TemporaryDirectory(prefix="lanfabric-inspection-") as temp:
        root = Path(temp)
        # SQLite не должен создавать утерянное состояние при диагностике.
        db = root / "state" / "vpn.db"
        with patch.object(srv, "DB_PATH", str(db)), \
             patch.object(srv, "CONF_DIR", str(db.parent / "configs")), \
             patch.object(srv, "WG_DIR", str(root / "wireguard")):
            old_umask = os.umask(0o022)
            try:
                srv.ensure_dirs()
                conn = srv.init_db()
                conn.close()
            finally:
                os.umask(old_umask)
            results["database_permissions"] = {
                "db": oct(db.stat().st_mode & 0o777),
                "parent": oct(db.parent.stat().st_mode & 0o777),
                "group_other_can_read": bool(db.stat().st_mode & 0o044),
            }

        missing_db = root / "missing-health.db"
        def health_run(command, check=True):
            if command.startswith("ip link show") and check:
                raise RuntimeError("Синтетически отсутствующий интерфейс")
            return ""
        with patch.object(srv, "DB_PATH", str(missing_db)), \
             patch.object(srv, "get_backend", return_value="awg"), \
             patch.object(srv, "get_wg_cmd", return_value="awg"), \
             patch.object(srv, "run_cmd", side_effect=health_run), \
             patch.object(srv.subprocess, "run", return_value=SimpleNamespace(returncode=1)), \
             patch.object(sys, "argv", ["vsrv-admin.py", "health"]), \
             contextlib.redirect_stdout(io.StringIO()):
            exit_code = 0
            try:
                srv.main()
            except SystemExit as e:
                exit_code = e.code
        results["health_on_failed_runtime"] = {
            "exit_code": exit_code, "created_missing_db": missing_db.exists()
        }

        params = root / "missing-awg-params"
        with patch.object(srv, "AWG_PARAMS_PATH", str(params)), \
             patch.object(srv, "REMOTE_DIR", str(root)), \
             patch.object(srv.subprocess, "run", side_effect=AssertionError("Внешние команды запрещены")):
            srv.build_setconf("SYNTHETIC_NOT_A_KEY", "awg")
        results["restore_creates_missing_awg_params"] = params.exists()

        firewall_db = root / "firewall.db"
        with patch.object(srv, "DB_PATH", str(firewall_db)):
            conn = srv.init_db()
            conn.executemany("INSERT INTO users VALUES (?, ?, ?, ?, 0, 0, 0, '')", [
                ("one", "SYNTHETIC_ONE", "NOT_A_KEY", "10.8.0.2"),
                ("two", "SYNTHETIC_TWO", "NOT_A_KEY", "10.8.0.3"),
            ])
            conn.commit()
            conn.close()
            state = {"drop": True, "peers": [], "interface_up": True}
            def simulated_run(command, check=True):
                if command == "awg show wg0 peers":
                    return ""
                if "peer SYNTHETIC_ONE allowed-ips" in command:
                    state["peers"].append("one")
                if "peer SYNTHETIC_TWO allowed-ips" in command:
                    raise RuntimeError("Внедрённый отказ применения второго peer")
                if command.startswith("ip link del"):
                    state["interface_up"] = False
                return ""
            def delete_rule(rule):
                if rule == srv.forward_drop_rule():
                    state["drop"] = False
            def ensure_rule(rule):
                if rule == srv.forward_drop_rule():
                    state["drop"] = True
            with patch.object(srv, "get_wg_cmd", return_value="awg"), \
                 patch.object(srv, "run_cmd", side_effect=simulated_run), \
                 patch.object(srv, "delete_iptables_rule", side_effect=delete_rule), \
                 patch.object(srv, "ensure_iptables_rule", side_effect=ensure_rule), \
                 patch.object(srv.subprocess, "run", side_effect=AssertionError("Внешние команды запрещены")):
                try:
                    srv.cmd_sync()
                except RuntimeError:
                    pass
            results["sync_partial_failure_model"] = state

        args = SimpleNamespace()
        with patch.object(cli, "get_remote_version", side_effect=["0.0.18", "0.0.17"]), \
             patch.object(cli, "ensure_sudo_nopasswd"), \
             patch.object(cli, "copy_server_module") as copy, \
             patch.object(cli, "try_cleanup_stale_temporary_sudo_trust"):
            cli.cmd_patch(args)
        results["patch_downgrade_18_to_17_calls_copy"] = copy.called

        configs = root / "configs"
        configs.mkdir()
        with patch.object(srv, "CONF_DIR", str(configs)), \
             patch.object(srv, "build_client_config", return_value="SYNTHETIC CONTENT\n"):
            written = srv.write_client_config({"name": "../escaped"})
        results["config_name_escapes_directory"] = written.resolve().parent != configs.resolve()

        args = SimpleNamespace(debug=False, ssh_tty=False)
        with patch.object(cli, "build_ssh_cmd", return_value=["ssh", "synthetic"]), \
             patch.object(cli.subprocess, "run", return_value=SimpleNamespace(
                 returncode=0, stdout="SYNTHETIC WARNING\n[Interface]\n")) as proc:
            output = cli.exec_remote(args, ["config", "one"], stream_output=False)
        results["clean_stdout_merges_stderr"] = {
            "merge_enabled": proc.call_args.kwargs["stderr"] == cli.subprocess.STDOUT,
            "warning_returned_as_content": output.startswith("SYNTHETIC WARNING"),
        }
    expected = [
        results["database_permissions"]["group_other_can_read"],
        results["health_on_failed_runtime"] == {"exit_code": 0, "created_missing_db": True},
        results["restore_creates_missing_awg_params"],
        results["sync_partial_failure_model"] == {"drop": False, "peers": ["one"], "interface_up": True},
        results["patch_downgrade_18_to_17_calls_copy"],
        results["config_name_escapes_directory"],
        all(results["clean_stdout_merges_stderr"].values()),
    ]
    print(json.dumps({"runtime": srv.__version__, "python": sys.version.split()[0],
                      "observations_confirmed": sum(expected), "total": len(expected),
                      "results": results}, ensure_ascii=False, indent=2))
    return 0 if all(expected) else 1


if __name__ == "__main__":
    raise SystemExit(inspect(Path(sys.argv[1]).resolve()))
