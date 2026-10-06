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
import io
from unittest.mock import patch

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
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("srv_ci", installed)
    srv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(srv)
    old_forward = run(["sysctl", "-n", "net.ipv4.ip_forward"])
    fingerprints = {}
    try:
        print("Чистая установка штатным init с готовыми компонентами", flush=True)
        # До публикации выпуска источник загрузки заменён байтами той же CI-сборки.
        # Проверки SHA-256, доверенных путей и весь установочный путь остаются штатными.
        def component_response(url, timeout):
            prefix = "https://github.com/dilukhin/LanFabric/releases/download/" + srv.AWG_GO_RELEASE + "/"
            if not url.startswith(prefix):
                raise RuntimeError("Неожиданный источник компонента")
            filename = url[len(prefix):]
            if filename not in ("amneziawg-go-linux-amd64", "awg-linux-amd64"):
                raise RuntimeError("Неожиданный компонент")
            response = io.BytesIO((repository / "ci-dist" / filename).read_bytes())
            response.geturl = lambda: url
            return response
        with patch.object(srv.urllib.request, "urlopen", side_effect=component_response), \
                patch.object(sys, "argv", [str(installed), "init", "--implementation", "go", "--listen-port", "4387"]):
            srv.main()
        run(["/usr/bin/python3", str(installed), "add", "ci-peer", "--internet"])
        # Контрольный снимок содержит только хеши; значения не выводятся.
        for path in (srv.DB_PATH, srv.AWG_PARAMS_PATH, "/etc/wireguard/wg0.private", "/etc/wireguard/wg0.public", srv.LISTEN_PORT_PATH):
            fingerprints[path] = digest(path)
        run(["/usr/bin/python3", str(installed), "init", "--implementation", "go"])
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
        print("Удаление службы и повторная установка без смены профилей", flush=True)
        run(["/usr/bin/python3", str(installed), "remove", "REMOVE"])
        if Path(srv.AWG_GO_UNIT_PATH).exists() or srv.interface_exists():
            raise RuntimeError("Служба сохранилась после remove")
        run(["/usr/bin/python3", str(installed), "init", "--implementation", "go"])
        run(["/usr/bin/python3", str(installed), "health"])
        if any(digest(path) != expected for path, expected in fingerprints.items()):
            raise RuntimeError("Повтор установки изменил сохранённое состояние")
        # Чужой файл запрещает purge до остановки текущего VPN.
        foreign = root / "foreign-data"
        foreign.write_text("synthetic foreign resource")
        rejected = subprocess.run(["/usr/bin/python3", str(installed), "purge", "PURGE"], capture_output=True, timeout=90)
        if rejected.returncode == 0 or not foreign.exists():
            raise RuntimeError("Purge не защитил чужой файл")
        run(["/usr/bin/python3", str(installed), "health"])
        foreign.unlink()
        run(["/usr/bin/python3", str(installed), "purge", "PURGE"])
        if root.exists() or Path(srv.WG_DIR).exists() or Path(srv.AWG_GO_UNIT_PATH).exists():
            raise RuntimeError("Собственные данные сохранились после purge")
        print("PASS: чистый init, полный профиль, remove/reinstall/purge, защита чужих файлов и SIGKILL", flush=True)
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
