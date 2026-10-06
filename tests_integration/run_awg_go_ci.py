#!/usr/bin/env python3
"""Изолированное испытание службы в GitHub Actions, не установщик для VPS."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import uuid

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
    prepared = sys.argv[1:] == ["--prepared-ci"] and os.environ.get("CI_PYTHON20_PREPARED") == "1"
    for path in (() if prepared else ("/opt/vpn-admin", "/etc/wireguard", "/etc/systemd/system/lanfabric-awg-go.service",
                 "/run/amneziawg/wg0.sock", "/opt/lanfabric-awg31")):
        if os.path.lexists(path):
            raise RuntimeError("Машина уже содержит ресурс VPN; испытание не начато")
    if not prepared and subprocess.run(["ip", "link", "show", "wg0"], capture_output=True).returncode == 0:
        raise RuntimeError("Интерфейс испытания занят")
    for table, chain in (("filter", "LANFABRIC-GUARD"), ("filter", "LANFABRIC-FWD"), ("nat", "LANFABRIC-NAT")):
        if not prepared and subprocess.run(["iptables", "-t", table, "-S", chain], capture_output=True).returncode == 0:
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
    if not prepared:
        root.mkdir(mode=0o700)
    installed = root / "vsrv-admin.py"
    if not prepared:
        shutil.copyfile(repository / "vsrv-admin.py", installed)
        installed.chmod(0o600)
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("srv_ci", installed)
    srv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(srv)
    old_forward = os.environ.get("CI_FORWARD_BEFORE") if prepared else run(["sysctl", "-n", "net.ipv4.ip_forward"])
    if old_forward not in ("0", "1"):
        raise RuntimeError("Исходное значение forwarding для испытания неизвестно")
    fingerprints = {}
    try:
        print("Чистая установка штатным init с готовыми компонентами", flush=True)
        # Обычная команда получает уже опубликованные файлы по публичным HTTPS URL.
        run(["/usr/bin/python3", str(installed), "init", "--implementation", "go", "--listen-port", "4387"], timeout=540)
        if sys.version_info < (3, 10):
            if not Path(srv.PYTHON_RUNTIME_EXECUTABLE).is_file():
                raise RuntimeError("Штатный init не обеспечил поддержанный Python")
            if not run(["/usr/bin/python3", "--version"]).startswith("Python 3.8."):
                raise RuntimeError("Системный Python изменился")
            env = os.environ.copy()
            env.update(CI_PYTHON20_PREPARED="1", CI_FORWARD_BEFORE=old_forward)
            os.execve(srv.PYTHON_RUNTIME_EXECUTABLE,
                      [srv.PYTHON_RUNTIME_EXECUTABLE, "-I", "-B", str(Path(__file__).resolve()), "--prepared-ci"], env)
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
        os.kill(before, signal.SIGKILL)
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
        print("Успешное обновление, возврат после отказа и повтор после обрыва", flush=True)
        env = os.environ.copy()
        env.update(SUDO_USER="root", SUDO_UID="0")
        def update_module(contents, components=False, expected_success=True):
            staged = Path("/tmp/lanfabric-vsrv-" + uuid.uuid4().hex + ".py")
            staged.write_bytes(contents)
            staged.chmod(0o600)
            command = ["/usr/bin/python3", str(installed), "_install-module", "--source", str(staged),
                       "--sha256", digest(staged), "--version", srv.__version__]
            if components:
                command.append("--components")
            try:
                result = subprocess.run(command, capture_output=True, env=env, timeout=180)
                if (result.returncode == 0) != expected_success:
                    raise RuntimeError("Проверка обновления дала неожиданный результат; вывод состояния скрыт")
            finally:
                staged.unlink()
        good_source = installed.read_bytes() + b"\n# CI: candidate update\n"
        profile_before = run(["/usr/bin/python3", str(installed), "config", "ci-peer", "--endpoint", "198.51.100.42"])
        update_module(good_source)
        if installed.read_bytes() != good_source:
            raise RuntimeError("Успешное обновление не заменило модуль")
        before_repeat = srv.go_process_identity()
        update_module(good_source)
        if srv.go_process_identity() != before_repeat:
            raise RuntimeError("Повтор уже завершённого обновления перезапустил процесс")
        update_module(good_source, components=True)
        # То же настоящее содержимое компонентов, но другой проверенный дескриптор.
        # Верхний регистр hex обозначает тот же исходный Git-объект; это позволяет
        # проверить смену описания без выдуманных исходников/сумм бинарников.
        previous = {"go_commit": srv.AWG_GO_COMMIT, "tools_commit": srv.AWG_GO_TOOLS_COMMIT,
                    "sha256": srv.AWG_GO_RELEASE_SHA256}
        good_source = good_source.replace(('AWG_GO_COMMIT = "' + srv.AWG_GO_COMMIT + '"').encode(),
                                          ('AWG_GO_COMMIT = "' + srv.AWG_GO_COMMIT.upper() + '"').encode(), 1)
        good_source = good_source.replace(b"AWG_GO_PREVIOUS_COMPONENTS = ()", ("AWG_GO_PREVIOUS_COMPONENTS = " + repr((previous,))).encode(), 1)
        update_module(good_source, components=True)
        if json.loads(Path(srv.AWG_GO_MANIFEST).read_text())["go_commit"] != srv.AWG_GO_COMMIT.upper():
            raise RuntimeError("Новый проверенный дескриптор компонентов не был установлен")
        faulty_source = good_source.replace(b"        record_go_socket(pid)\n", b"        record_go_socket(pid)\n        raise RuntimeError('CI controlled restore failure')\n", 1)
        update_module(faulty_source, components=True, expected_success=False)
        if installed.read_bytes() != good_source:
            raise RuntimeError("Отказ не вернул прежний модуль")
        run(["/usr/bin/python3", str(installed), "health"])
        if any(digest(path) != expected for path, expected in fingerprints.items()):
            raise RuntimeError("Возврат изменил сохранённые ключи, параметры или пользователей")
        if run(["/usr/bin/python3", str(installed), "config", "ci-peer", "--endpoint", "198.51.100.42"]) != profile_before:
            raise RuntimeError("Возврат изменил клиентский профиль")
        delayed = good_source.replace(b"def go_restore_locked():\n", b"def go_restore_locked():\n    time.sleep(4)\n", 1)
        staged = Path("/tmp/lanfabric-vsrv-" + uuid.uuid4().hex + ".py")
        staged.write_bytes(delayed)
        process = subprocess.Popen(["/usr/bin/python3", str(installed), "_install-module", "--source", str(staged),
                                    "--sha256", digest(staged), "--version", srv.__version__],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try:
            deadline = time.monotonic() + 30
            interrupted = False
            while time.monotonic() < deadline and process.poll() is None:
                time.sleep(0.05)
                record = srv.read_go_update_record()
                if record["phase"] == "committed" and digest(installed) == digest(staged):
                    process.kill()
                    process.communicate(timeout=15)
                    interrupted = True
                    break
            if not interrupted:
                raise RuntimeError("Не удалось прервать испытательное обновление на записанном этапе")
            rejected = subprocess.run(["/usr/bin/python3", str(installed), "add", "must-not-exist"], capture_output=True, timeout=30)
            if rejected.returncode == 0 or any(digest(path) != expected for path, expected in fingerprints.items()):
                raise RuntimeError("Незавершённое обновление разрешило изменение участников")
            update_module(delayed)
            run(["/usr/bin/python3", str(installed), "health"])
            if run(["/usr/bin/python3", str(installed), "config", "ci-peer", "--endpoint", "198.51.100.42"]) != profile_before:
                raise RuntimeError("Повтор после обрыва изменил клиентский профиль")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=15)
            staged.unlink()
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
        print("PASS: публичная поставка, init, полный профиль, обновление/возврат/обрыв, remove/reinstall/purge и SIGKILL", flush=True)
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
