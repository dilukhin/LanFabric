#!/usr/bin/env python3
"""Изолированное испытание службы в GitHub Actions, не установщик для VPS."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

GO_COMMIT = "b5928efb6ca19f0153958460c3d141f04abc5c2e"
TOOLS_COMMIT = "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"


def run(argv, timeout=90):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("Испытательная команда завершилась ошибкой; вывод с данными состояния скрыт")
    return result.stdout.strip()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    if (os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("GITHUB_REPOSITORY") != "dilukhin/LanFabric"):
        raise RuntimeError("Испытание разрешено только в одноразовой машине GitHub Actions этого репозитория")
    repository = Path(__file__).resolve().parents[1]
    for path in ("/opt/vpn-admin", "/etc/wireguard", "/etc/systemd/system/lanfabric-awg-go.service",
                 "/run/amneziawg/wg0.sock", "/opt/lanfabric-awg31"):
        if os.path.lexists(path):
            raise RuntimeError("Машина уже содержит ресурс VPN; испытание не начато")
    if subprocess.run(["ip", "link", "show", "wg0"], capture_output=True).returncode == 0:
        raise RuntimeError("Интерфейс испытания занят")
    for table, chain in (("filter", "LANFABRIC-GUARD"), ("filter", "LANFABRIC-FWD"), ("nat", "LANFABRIC-NAT")):
        if subprocess.run(["iptables", "-t", table, "-S", chain], capture_output=True).returncode == 0:
            raise RuntimeError("Сетевая цепочка испытания занята")
    root = Path("/opt/vpn-admin")
    for parent in (Path("/opt"), Path("/")):
        info = parent.lstat()
        print(f"Права родителя {parent}: uid={info.st_uid}, mode={info.st_mode & 0o777:o}", flush=True)
    # В одноразовом образе Actions /opt может быть открыт для установки инструментов.
    # Подготовка стенда восстанавливает необходимую границу root, не ослабляя код службы.
    if Path("/opt").is_symlink():
        raise RuntimeError("Родитель испытательной установки является ссылкой")
    os.chown("/opt", 0, 0)
    os.chmod("/opt", 0o755)
    root.mkdir(mode=0o700)
    installed = root / "vsrv-admin.py"
    shutil.copyfile(repository / "vsrv-admin.py", installed)
    installed.chmod(0o600)
    spec = importlib.util.spec_from_file_location("srv_ci", installed)
    srv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(srv)
    old_forward = run(["sysctl", "-n", "net.ipv4.ip_forward"])
    fingerprints = {}
    try:
        print("Подготовка синтетического состояния без публикации ключей", flush=True)
        srv.ensure_dirs()
        binaries = root / "awg-go"
        binaries.mkdir(mode=0o700)
        for source, name in ((repository / "ci-src/go/amneziawg-go", "amneziawg-go"),
                             (repository / "ci-src/tools/src/wg", "awg")):
            shutil.copyfile(source, binaries / name)
            (binaries / name).chmod(0o700)
        srv.write_private_file(srv.BACKEND_PATH, "awg\n")
        srv.write_private_file(srv.IMPLEMENTATION_PATH, "go\n")
        srv.write_private_file(srv.AWG_GO_MANIFEST, json.dumps({
            "schema": 1, "platform": "linux-amd64", "go_commit": GO_COMMIT, "tools_commit": TOOLS_COMMIT,
            "sha256": {name: digest(binaries / name) for name in ("amneziawg-go", "awg")}}) + "\n")
        for name in ("server", "ci-peer"):
            private = run([srv.AWG_GO_TOOLS, "genkey"])
            public = srv.derive_public_key(private, srv.AWG_GO_TOOLS)
            if name == "server":
                srv.write_private_file("/etc/wireguard/wg0.private", private + "\n")
                srv.write_private_file("/etc/wireguard/wg0.public", public + "\n")
            else:
                connection = srv.init_db(create=True)
                connection.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                   (name, public, private, "10.8.0.2", 0, 1, 0, "синтетический участник"))
                connection.commit()
                connection.close()
        srv.write_awg_params_file(srv.generate_awg31_params())
        srv.write_listen_port(4387)
        run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        srv.ensure_state_permissions()
        # Контрольный снимок содержит только хеши; значения не выводятся.
        for path in (srv.DB_PATH, srv.AWG_PARAMS_PATH, "/etc/wireguard/wg0.private", "/etc/wireguard/wg0.public", srv.LISTEN_PORT_PATH):
            fingerprints[path] = digest(path)
        srv.ensure_awg_autostart_unit()
        print("Предварительная проверка до появления TUN", flush=True)
        with srv.runtime_lock():
            srv.go_preflight_locked()
        for action in ("start", "start", "sync", "restart", "stop", "start"):
            print("Штатная команда: " + action, flush=True)
            run(["/usr/bin/python3", str(installed), action])
            if action != "stop":
                run(["/usr/bin/python3", str(installed), "health"])
            elif srv.interface_exists():
                raise RuntimeError("Интерфейс сохранился после остановки")
            if any(digest(path) != expected for path, expected in fingerprints.items()):
                raise RuntimeError("Перезапуск изменил сохранённые ключи, параметры или пользователей")
        print("SIGKILL и автоматическое полное восстановление", flush=True)
        before = srv.go_process_identity()
        run(["systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", srv.AWG_GO_UNIT])
        deadline = time.monotonic() + 45
        restored = False
        while time.monotonic() < deadline:
            time.sleep(0.5)
            try:
                after = srv.go_process_identity()
                state = srv.load_state_snapshot("awg")
                if after != before and not srv.runtime_readiness_errors(state):
                    restored = True
                    break
            except RuntimeError:
                pass
        if not restored:
            raise RuntimeError("Служба не восстановилась после SIGKILL в установленный срок")
        if any(digest(path) != expected for path, expected in fingerprints.items()):
            raise RuntimeError("Аварийное восстановление изменило сохранённое состояние")
        print("PASS: настоящий Go, полный профиль, systemd, повторный start, restart, stop и SIGKILL", flush=True)
    except Exception:
        # Только несекретные свойства службы, без showconf/dump/journal и ключей.
        print(run(["systemctl", "show", srv.AWG_GO_UNIT, "-p", "ActiveState", "-p", "SubState",
                   "-p", "Result", "-p", "ExecMainStatus"]), flush=True)
        raise
    finally:
        subprocess.run(["systemctl", "disable", "--now", srv.AWG_GO_UNIT], capture_output=True, timeout=90)
        run(["sysctl", "-w", "net.ipv4.ip_forward=" + old_forward])


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
