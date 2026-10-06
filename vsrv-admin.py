#!/usr/bin/env python3
"""
vsrv-admin.py - серверный инструмент управления VPN на базе WireGuard/AmneziaWG.
Управление пирами, маршрутизацией, доступом в интернет и состоянием сервера.
"""
__version__ = "0.0.18"

import sys
import os
import subprocess
import sqlite3
import argparse
import logging
import shlex
import ipaddress
import secrets
import re
import time
import json
import base64
import binascii
import hashlib
import socket
import stat
import struct
import shutil
import tempfile
import urllib.request
try:
    import fcntl
except ImportError:  # локальные unit-тесты могут импортировать серверный модуль на Windows
    fcntl = None
from contextlib import contextmanager
from pathlib import Path

# Константы
DB_PATH = "/opt/vpn-admin/vpn.db"
WG_IF = "wg0"
SERVER_IP = "10.8.0.1"
VPN_NET = "10.8.0.0/24"
CONF_DIR = "/opt/vpn-admin/configs"
WG_DIR = "/etc/wireguard"
WG_BASE_PORT = 51820
LISTEN_PORT_PATH = "/opt/vpn-admin/listen_port"
BACKEND_PATH = "/opt/vpn-admin/backend"
REMOTE_DIR = "/opt/vpn-admin"
SUDOERS_PATH = "/etc/sudoers.d/vpn-admin"
SUDOERS_LANFABRIC_GLOB = "/etc/sudoers.d/lanfabric-*"
AWG_PARAMS_PATH = "/opt/vpn-admin/awg_params"
AWG_PARAM_KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4")
AWG31_EXTRA_KEYS = (
    "S3", "S4", "HeaderProtectionKey", "RekeyAfterTime", "RekeyTimeout",
    "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts",
    "ContentPaddingAddition", "RandomTrailers", "DisableCookies",
)
AWG31_PARAM_KEYS = AWG_PARAM_KEYS + AWG31_EXTRA_KEYS
AWG31_TIMER_KEYS = (
    "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
    "MaxHandshakeAttempts", "ContentPaddingAddition",
)
LOCK_DIR = "/run/lanfabric"
LOCK_PATH = f"{LOCK_DIR}/runtime.lock"
LOCK_TIMEOUT_SECONDS = 20
FW_GUARD_CHAIN = "LANFABRIC-GUARD"
FW_FORWARD_CHAIN = "LANFABRIC-FWD"
FW_NAT_CHAIN = "LANFABRIC-NAT"
NAT_MARK = "lanfabric-client-nat-v1"
FORWARD_MARK = "lanfabric-client-forward-v1"
AWG_AUTOSTART_UNIT = "lanfabric-awg.service"
AWG_AUTOSTART_PATH = f"/etc/systemd/system/{AWG_AUTOSTART_UNIT}"
AWG_AUTOSTART_TIMEOUT_SECONDS = 60
IMPLEMENTATION_PATH = "/opt/vpn-admin/implementation"
AWG_GO_DIR = "/opt/vpn-admin/awg-go"
AWG_GO_BINARY = f"{AWG_GO_DIR}/amneziawg-go"
AWG_GO_TOOLS = f"{AWG_GO_DIR}/awg"
AWG_GO_MANIFEST = f"{AWG_GO_DIR}/manifest.json"
AWG_GO_UNIT = "lanfabric-awg-go.service"
AWG_GO_UNIT_PATH = f"/etc/systemd/system/{AWG_GO_UNIT}"
AWG_GO_SOCKET = f"/run/amneziawg/{WG_IF}.sock"
AWG_GO_SOCKET_RECORD = f"{LOCK_DIR}/go-socket.json"
AWG_GO_OPERATION_LOCK = f"{LOCK_DIR}/go-operation.lock"
AWG_GO_TIMEOUT_SECONDS = 60
AWG_GO_RELEASE = "awg-go-3.1-r1"
AWG_GO_RELEASE_SHA256 = {
    "amneziawg-go": "5e8e2e656d77f9f66102660234fa08d8c2ddb99bf32961db8c02ad19c32e872f",
    "awg": "a31d773ed5be300fafbd5d87689e5fd6541d47e60ecad9c704e6c197fffcfb28",
}
AWG_GO_INSTALL_RECORD = f"{REMOTE_DIR}/go-install.json"

def require_go_platform():
    """Проверяет платформу без установки компиляторов или обновления ОС."""
    values = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip('"')
    if (values.get("ID") != "ubuntu" or values.get("VERSION_ID") not in ("22.04", "24.04")
            or os.uname().machine != "x86_64" or sys.version_info < (3, 10)):
        raise RuntimeError("Поставка Go поддерживает Ubuntu 22.04/24.04 x86_64 с Python 3.10+; для другой ОС нужен отдельный проверенный путь")
    info = os.stat("/dev/net/tun")
    if not stat.S_ISCHR(info.st_mode):
        raise RuntimeError("Для AWG Go требуется доступный символьный /dev/net/tun")
    trusted_python_path()
    if shutil.disk_usage(REMOTE_DIR).free < 128 * 1024 * 1024:
        raise RuntimeError("Для поставки Go требуется не менее 128 MiB свободного места")
    memory = next((int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines()
                   if line.startswith("MemTotal:")), 0)
    if memory < 256 * 1024:
        raise RuntimeError("Для AWG Go требуется не менее 256 MiB памяти")

def check_go_clean_target(port, staging=None):
    """Доказывает чистоту цели; неизвестные файлы, сеть и службы не очищает."""
    for path in (BACKEND_PATH, IMPLEMENTATION_PATH, DB_PATH, AWG_PARAMS_PATH, LISTEN_PORT_PATH,
                 AWG_GO_DIR, AWG_GO_INSTALL_RECORD, AWG_GO_UNIT_PATH, AWG_AUTOSTART_PATH,
                 "/opt/lanfabric-awg31", "/etc/systemd/system/lanfabric-awg31.service", AWG_GO_SOCKET,
                 "/etc/sysctl.d/99-vpn-forward.conf"):
        if os.path.lexists(path):
            raise RuntimeError("Цель Go содержит состояние VPN; init не является миграцией или очисткой")
    trusted_go_path(f"{REMOTE_DIR}/vsrv-admin.py", private=True)
    for entry in Path(REMOTE_DIR).iterdir():
        if entry.name == "vsrv-admin.py" or (staging is not None and entry == Path(staging)):
            continue
        if entry == Path(CONF_DIR) and not entry.is_symlink() and entry.is_dir() and not any(entry.iterdir()):
            continue
        raise RuntimeError("В каталоге установки есть неизвестный ресурс; автоматическая очистка запрещена")
    if os.path.lexists(WG_DIR):
        directory = Path(WG_DIR)
        if directory.is_symlink() or not directory.is_dir() or any(directory.iterdir()):
            raise RuntimeError("Каталог WireGuard занят; чистая установка Go остановлена")
        for parent in (directory, *directory.parents):
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError("Нарушена граница доверия каталога WireGuard")
    if interface_exists():
        raise RuntimeError("Имя интерфейса Go уже занято")
    if run_cmd(f"ss -ulnH 'sport = :{port}'", check=False):
        raise RuntimeError("UDP-порт Go уже занят")
    for entry in json.loads(run_cmd("ip -j -4 route show table all")):
        if entry.get("dst", "default") != "default" and ipaddress.ip_network(VPN_NET).overlaps(
                ipaddress.ip_network(entry["dst"], strict=False)):
            raise RuntimeError("Подсеть Go пересекается с существующим маршрутом")
    if command_succeeds("systemctl is-active --quiet wg-quick@wg0") or command_succeeds("systemctl is-enabled --quiet wg-quick@wg0"):
        raise RuntimeError("Служба wg-quick@wg0 уже используется")
    if command_succeeds("command -v iptables"):
        for table, chain in (("filter", FW_GUARD_CHAIN), ("filter", FW_FORWARD_CHAIN), ("nat", FW_NAT_CHAIN)):
            if _chain_exists(table, chain):
                raise RuntimeError("Имя сетевой цепочки Go занято")
        # Правила должны быть доступны для чтения, а не скрыты ошибкой command -v.
        for table in ("filter", "nat"):
            rules = run_cmd(f"iptables -t {table} -S")
            if any(WG_IF in line or VPN_NET in line or SERVER_IP in line for line in rules.splitlines()):
                raise RuntimeError("Существующие сетевые правила пересекаются с установкой Go")

def download_go_components(directory):
    """Загружает только закреплённые готовые файлы; не исполняет их до проверки."""
    if set(AWG_GO_RELEASE_SHA256) != {"amneziawg-go", "awg"}:
        raise RuntimeError("Поставка Go ещё не закреплена; загрузка запрещена")
    for name, expected in AWG_GO_RELEASE_SHA256.items():
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise RuntimeError("Контрольная сумма поставки Go недопустима")
        url = f"https://github.com/dilukhin/LanFabric/releases/download/{AWG_GO_RELEASE}/{name}-linux-amd64"
        path = Path(directory) / name
        digest = hashlib.sha256()
        deadline = time.monotonic() + 120
        size = 0
        try:
            with urllib.request.urlopen(url, timeout=30) as response, open(path, "xb") as output:
                if not response.geturl().startswith("https://"):
                    raise ValueError
                os.chmod(path, 0o700)
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > 64 * 1024 * 1024 or time.monotonic() >= deadline:
                        raise ValueError
                    output.write(chunk)
                    digest.update(chunk)
                output.flush()
                os.fsync(output.fileno())
            if size == 0 or not secrets.compare_digest(digest.hexdigest(), expected):
                raise ValueError
        except Exception:
            raise RuntimeError("Не удалось получить проверенный компонент Go; состояние VPN не создано. Проверьте доступ к выпуску GitHub") from None
    data = {"schema": 1, "platform": "linux-amd64",
            "go_commit": "b5928efb6ca19f0153958460c3d141f04abc5c2e",
            "tools_commit": "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843",
            "sha256": dict(AWG_GO_RELEASE_SHA256)}
    write_private_file(str(Path(directory) / "manifest.json"), json.dumps(data) + "\n")

def cmd_init_go(args):
    """Только чистая установка либо продолжение уже подготовленной собственной."""
    if args.no_amnezia or getattr(args, "awg_profile", None) not in (None, "awg31", "legacy"):
        raise RuntimeError("AWG Go несовместим с выбранным протоколом или профилем")
    requested_port = getattr(args, "listen_port", None)
    port = validate_listen_port(WG_BASE_PORT if requested_port is None else requested_port)
    with runtime_lock(lock_path=AWG_GO_OPERATION_LOCK):
        with runtime_lock():
            if os.path.lexists(AWG_GO_INSTALL_RECORD):
                trusted_go_path(AWG_GO_INSTALL_RECORD, private=True)
                record = json.loads(Path(AWG_GO_INSTALL_RECORD).read_text())
                if record not in ({"schema": 1, "phase": "prepared"}, {"schema": 1, "phase": "complete"}, {"schema": 1, "phase": "removed"}):
                    raise RuntimeError("Установка Go остановлена во время создания состояния; повторная генерация запрещена, требуется проверка состояния")
                snapshot = load_state_snapshot("awg")
                saved = "awg31" if "HeaderProtectionKey" in snapshot["awg_params"] else "legacy"
                if (snapshot["implementation"] != "go" or (getattr(args, "listen_port", None) is not None and port != snapshot["listen_port"])
                        or getattr(args, "awg_profile", None) not in (None, saved)):
                    raise RuntimeError("Повтор init не может изменить сохранённую установку Go")
                ensure_awg_autostart_unit()
                prepared = True
            else:
                require_go_platform()
                check_go_clean_target(port)
                prepared = False
        if not prepared:
            with tempfile.TemporaryDirectory(prefix=".awg-go-", dir=REMOTE_DIR) as staging:
                download_go_components(staging)
                # Устанавливаются только сетевые зависимости из штатных репозиториев ОС.
                run_bounded_command(["apt-get", "update", "-qq"], timeout=180)
                run_bounded_command(["apt-get", "install", "-y", "iproute2", "iptables-persistent", "netfilter-persistent"], timeout=300)
                with runtime_lock():
                    check_go_clean_target(port, staging=staging)
                    _atomic_write_root_file(AWG_GO_INSTALL_RECORD, '{"schema": 1, "phase": "creating"}\n', mode=0o600)
                    ensure_dirs()
                    os.rename(staging, AWG_GO_DIR)
                    write_private_file(BACKEND_PATH, "awg\n")
                    write_private_file(IMPLEMENTATION_PATH, "go\n")
                    require_go_components()
                    private = run_cmd(f"{AWG_GO_TOOLS} genkey")
                    public = derive_public_key(private, AWG_GO_TOOLS)
                    write_private_file(f"{WG_DIR}/{WG_IF}.private", private + "\n")
                    _atomic_write_root_file(f"{WG_DIR}/{WG_IF}.public", public + "\n", mode=0o644)
                    write_awg_params_file(generate_awg_params(profile=getattr(args, "awg_profile", None) or "awg31"))
                    write_listen_port(port)
                    init_db(create=True).close()
                    ensure_state_permissions()
                    run_bounded_command(["sysctl", "-w", "net.ipv4.ip_forward=1"], timeout=10)
                    forward_path = "/etc/sysctl.d/99-vpn-forward.conf"
                    if os.path.lexists(forward_path):
                        raise RuntimeError("Файл настройки forwarding занят; автоматическая замена запрещена")
                    _atomic_write_root_file(forward_path, "net.ipv4.ip_forward=1\n", mode=0o644)
                    ensure_awg_autostart_unit()
                    _atomic_write_root_file(AWG_GO_INSTALL_RECORD, '{"schema": 1, "phase": "prepared"}\n', mode=0o600)
            # TemporaryDirectory уже перемещён; его очистка не удаляет компоненты.
        _go_lifecycle_locked("start")
        with runtime_lock():
            _atomic_write_root_file(AWG_GO_INSTALL_RECORD, '{"schema": 1, "phase": "complete"}\n', mode=0o600)
    log.info("AWG Go установлен, запущен и проверен")
    add_advice("Создайте участников командой add <имя>; для проверки используйте health")

def run_bounded_command(argv, timeout):
    """Конечное ожидание системных зависимостей без вывода их внутренних данных."""
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    try:
        result = subprocess.run(argv, env=env, capture_output=True, timeout=timeout)
        if result.returncode:
            raise ValueError
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise RuntimeError("Подготовка системной зависимости не завершилась; состояние установки требует проверки") from None

def go_purge_files(snapshot):
    """Возвращает доказанно собственные файлы; неизвестные ресурсы запрещают purge."""
    trusted_go_path(AWG_GO_INSTALL_RECORD, private=True)
    if json.loads(Path(AWG_GO_INSTALL_RECORD).read_text()) not in (
            {"schema": 1, "phase": "complete"}, {"schema": 1, "phase": "removed"}, {"schema": 1, "phase": "prepared"}):
        raise RuntimeError("Для удаления требуется завершённое собственное состояние установки Go")
    allowed = {
        Path(REMOTE_DIR): {"vsrv-admin.py", "vpn.db", "backend", "implementation", "awg_params", "listen_port", "go-install.json", "awg-go", "configs"},
        Path(AWG_GO_DIR): {"amneziawg-go", "awg", "manifest.json"},
        Path(CONF_DIR): {row["name"] + ".conf" for row in snapshot["users"]},
        Path(WG_DIR): {WG_IF + ".private", WG_IF + ".public", WG_IF + ".setconf"},
    }
    files = []
    for directory, names in allowed.items():
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise RuntimeError("Каталог Go не принадлежит приватному состоянию LanFabric")
        for entry in directory.iterdir():
            if entry.name not in names or entry.is_symlink():
                raise RuntimeError("Есть неизвестный ресурс; полное удаление Go запрещено")
            if entry in allowed:
                continue
            trusted_go_path(str(entry), private=entry.name != WG_IF + ".public")
            files.append(entry)
    forward = Path("/etc/sysctl.d/99-vpn-forward.conf")
    if forward.exists():
        trusted_go_path(str(forward))
        if forward.read_text() != "net.ipv4.ip_forward=1\n":
            raise RuntimeError("Настройка forwarding изменена; удаление запрещено")
        files.append(forward)
    return files, list(reversed(list(allowed)))

def cmd_remove_go(purge=False):
    """Удаляет собственную службу; purge удаляет только предварительно проверенные данные."""
    with runtime_lock(lock_path=AWG_GO_OPERATION_LOCK):
        with runtime_lock():
            snapshot = load_state_snapshot("awg")
            require_go_components()
            # Проверить всю область удаления до остановки работающей службы.
            if purge:
                files, directories = go_purge_files(snapshot)
            if os.path.lexists(AWG_GO_UNIT_PATH):
                require_go_unit()
                installed = True
            else:
                if interface_exists() or os.path.lexists(AWG_GO_SOCKET):
                    raise RuntimeError("Служба отсутствует, но runtime остался; принадлежность не подтверждена")
                installed = False
        if installed:
            _go_lifecycle_locked("stop")
        with runtime_lock():
            if installed:
                require_go_unit()
                go_systemctl("disable")
                Path(AWG_GO_UNIT_PATH).unlink()
                go_systemctl("daemon-reload")
            if purge:
                # Повторная сверка под блокировкой перед фактическим удалением.
                files, directories = go_purge_files(load_state_snapshot("awg"))
                for path in files:
                    path.unlink()
                for directory in directories:
                    directory.rmdir()
                if os.path.lexists(AWG_GO_SOCKET_RECORD):
                    trusted_go_path(AWG_GO_SOCKET_RECORD, private=True)
                    Path(AWG_GO_SOCKET_RECORD).unlink()
            else:
                _atomic_write_root_file(AWG_GO_INSTALL_RECORD, '{"schema": 1, "phase": "removed"}\n', mode=0o600)
    log.info("Go удалён вместе с собственными данными" if purge else "Служба Go удалена; ключи, пользователи и проверенные компоненты сохранены")
    if not purge:
        add_advice("Для восстановления службы выполните init --implementation go; сохранённые ключи не меняются")

# Логирование
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SRV] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
for handler in logging.getLogger().handlers:
    handler.flush = sys.stdout.flush
log = logging.getLogger("vsrv")
ADVICE_LINES = []
os.umask(0o077)

def add_advice(*lines):
    """Добавляет рекомендации, которые будут напечатаны в конце вывода."""
    for line in lines:
        if not line:
            continue
        for part in str(line).splitlines():
            part = part.strip()
            if part and part not in ADVICE_LINES:
                ADVICE_LINES.append(part)

def flush_advice():
    """Печатает накопленные рекомендации заметным блоком."""
    if not ADVICE_LINES:
        return
    log.info("*** РЕКОМЕНДАЦИИ ***")
    for line in ADVICE_LINES:
        log.info(line)
    log.info("*** КОНЕЦ РЕКОМЕНДАЦИЙ ***")
    ADVICE_LINES.clear()

def print_intro():
    """Выводит краткую информацию о серверном инструменте."""
    print(f"LanFabric SRV v{__version__} — сервер управления VPN")


def _cleanup_temp_sudoers(user, ttl, remove_all=False, sudoers_dir="/etc/sudoers.d"):
    """Удаляет только принадлежащие LanFabric временные sudoers-файлы."""
    safe_user = re.sub(r"[^A-Za-z0-9_.-]", "_", user)
    pattern = re.compile(r"^lanfabric-temp-" + re.escape(safe_user) + r"-[0-9a-f]{12}$")
    now = time.time()
    removed = 0
    for entry in os.scandir(sudoers_dir):
        if not entry.is_file(follow_symlinks=False) or not pattern.fullmatch(entry.name):
            continue
        try:
            stale = entry.stat(follow_symlinks=False).st_mtime + ttl < now
            if remove_all or stale:
                os.unlink(entry.path)
                removed += 1
        except FileNotFoundError:
            continue
    return removed


def _run_internal_cleanup_temp_sudoers(argv):
    """Проверяет sudo caller и запускает закрытую cleanup-операцию."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--user", required=True)
    parser.add_argument("--ttl", type=int, default=3600)
    parser.add_argument("--all", action="store_true", dest="remove_all")
    args = parser.parse_args(argv)
    if args.ttl < 0:
        parser.error("--ttl не может быть отрицательным")
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user:
        raise RuntimeError("Внутренняя cleanup-операция разрешена только через sudo")
    safe_user = re.sub(r"[^A-Za-z0-9_.-]", "_", args.user)
    safe_sudo_user = re.sub(r"[^A-Za-z0-9_.-]", "_", sudo_user)
    if safe_user != safe_sudo_user:
        raise RuntimeError("Пользователь cleanup не совпадает с SUDO_USER")
    return _cleanup_temp_sudoers(args.user, args.ttl, args.remove_all)

def get_backend():
    path = "/opt/vpn-admin/backend"
    if not os.path.exists(path):
        raise RuntimeError("Backend не определён. Выполните init")
    return open(path).read().strip()

def get_wg_cmd(allow_missing=False):
    try:
        backend = require_backend()
        return backend_tools(backend, get_implementation(backend))
    except Exception:
        if allow_missing:
            return None
        raise

def require_backend():
    """Возвращает сохранённый backend и проверяет его допустимость."""
    backend = get_backend()
    if backend not in ("wg", "awg"):
        raise RuntimeError(f"Неизвестный backend: {backend}")
    return backend

def get_implementation(backend=None):
    """Прежние установки без отдельного файла используют модуль ядра."""
    backend = require_backend() if backend is None else backend
    try:
        value = Path(IMPLEMENTATION_PATH).read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        if os.path.lexists(IMPLEMENTATION_PATH):
            raise RuntimeError("Файл реализации повреждён; выбор по умолчанию запрещён") from None
        return "kernel"
    if value not in ("kernel", "go") or (value == "go" and backend != "awg"):
        raise RuntimeError("Сохранённая реализация VPN недопустима; автоматическая замена запрещена")
    return value

def backend_tools(backend, implementation):
    return AWG_GO_TOOLS if implementation == "go" else ("awg" if backend == "awg" else "wg")

def trusted_go_path(path_text, executable=False, private=False):
    """Go-компоненты и их родители принадлежат root, без ссылок и чужой записи."""
    path = Path(path_text)
    for entry in (path, *path.parents):
        try:
            info = entry.lstat()
        except OSError:
            raise RuntimeError("Обязательный доверенный файл AWG Go отсутствует") from None
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError(f"Нарушены владелец, тип или права пути AWG Go: {entry}")
    if not path.is_file() or (executable and not os.access(path, os.X_OK)):
        raise RuntimeError("Обязательный файл AWG Go имеет неверный тип или недоступен")
    if private and path.stat().st_mode & 0o077:
        raise RuntimeError("Состояние AWG Go доступно другим пользователям")

def require_go_components():
    """Проверяет уже поставленные компоненты; ничего не скачивает и не исполняет."""
    trusted_go_path(IMPLEMENTATION_PATH, private=True)
    trusted_go_path(AWG_GO_MANIFEST, private=True)
    try:
        if Path(AWG_GO_MANIFEST).stat().st_size > 8192:
            raise ValueError
        data = json.loads(Path(AWG_GO_MANIFEST).read_text(encoding="utf-8"))
        if (set(data) != {"schema", "platform", "go_commit", "tools_commit", "sha256"}
                or type(data["schema"]) is not int or data["schema"] != 1
                or data["platform"] != "linux-amd64"
                or data["go_commit"] != "b5928efb6ca19f0153958460c3d141f04abc5c2e"
                or data["tools_commit"] != "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"
                or data["sha256"] != AWG_GO_RELEASE_SHA256):
            raise ValueError
        if os.uname().machine != "x86_64":
            raise ValueError
        for path_text, name in ((AWG_GO_BINARY, "amneziawg-go"), (AWG_GO_TOOLS, "awg")):
            trusted_go_path(path_text, executable=True)
            expected = data["sha256"][name]
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise ValueError
            if Path(path_text).stat().st_size > 64 * 1024 * 1024:
                raise ValueError
            digest = hashlib.sha256()
            with open(path_text, "rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            if not secrets.compare_digest(digest.hexdigest(), expected):
                raise ValueError
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise RuntimeError("Компоненты AWG Go не соответствуют закреплённой поставке; запуск запрещён") from None

def go_systemctl(*arguments):
    """Конечное ожидание systemd без выдачи вывода дочерних процессов."""
    try:
        command = ["systemctl", *arguments]
        if arguments != ("daemon-reload",):
            command.append(AWG_GO_UNIT)
        result = subprocess.run(command,
                                capture_output=True, text=True, timeout=AWG_GO_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("Управление службой AWG Go не завершилось в срок; проверьте status и health перед повтором") from None
    if result.returncode != 0:
        raise RuntimeError("Операция службы AWG Go завершилась ошибкой; проверьте status и health")
    return result.stdout.strip()

def awg_go_unit_text(python_path=None):
    python_path = python_path or "/usr/bin/python3"
    return f"""[Unit]
Description=LanFabric AWG Go
After=systemd-sysctl.service netfilter-persistent.service
Wants=netfilter-persistent.service
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStartPre={python_path} -u {REMOTE_DIR}/vsrv-admin.py _go-preflight
ExecStart={AWG_GO_BINARY} -f {WG_IF}
ExecStartPost={python_path} -u {REMOTE_DIR}/vsrv-admin.py _go-restore
ExecStopPost={python_path} -u {REMOTE_DIR}/vsrv-admin.py _go-closed
Restart=always
RestartSec=3
TimeoutStartSec={AWG_GO_TIMEOUT_SECONDS}s
TimeoutStopSec=30s
KillMode=control-group
UMask=0077
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=WG_PROCESS_FOREGROUND=1 LOG_LEVEL=silent GOMEMLIMIT=256MiB
MemoryMax=512M
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
"""

def require_go_unit():
    """Проверяет файл службы и отсутствие подмены через дополнения systemd."""
    trusted_go_path(AWG_GO_UNIT_PATH)
    if Path(AWG_GO_UNIT_PATH).read_text(encoding="utf-8") != awg_go_unit_text(trusted_python_path()):
        raise RuntimeError("Файл службы AWG Go не соответствует штатному контракту")
    properties = go_systemctl("show", "-p", "FragmentPath", "-p", "DropInPaths")
    values = dict(line.split("=", 1) for line in properties.splitlines() if "=" in line)
    if values.get("FragmentPath") != AWG_GO_UNIT_PATH or values.get("DropInPaths", "missing"):
        raise RuntimeError("Загруженная служба AWG Go имеет посторонние изменения")

def go_process_identity(require_socket=True):
    """Сверяет systemd, /proc и SO_PEERCRED управляющего сокета с одним PID."""
    require_go_unit()
    try:
        pid_text = go_systemctl("show", "-p", "MainPID", "--value")
        if not pid_text.isdecimal() or int(pid_text) <= 1:
            raise ValueError
        pid = int(pid_text)
        proc = Path(f"/proc/{pid}")
        if os.readlink(proc / "exe") != AWG_GO_BINARY:
            raise ValueError
        argv = (proc / "cmdline").read_bytes().split(b"\0")
        if argv != [os.fsencode(AWG_GO_BINARY), b"-f", os.fsencode(WG_IF), b""]:
            raise ValueError
        if not any(line.split(":", 2)[-1].endswith("/" + AWG_GO_UNIT)
                   for line in (proc / "cgroup").read_text().splitlines()):
            raise ValueError
        if require_socket:
            info = os.lstat(AWG_GO_SOCKET)
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                raise ValueError
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(1)
                connection.connect(AWG_GO_SOCKET)
                peer_pid, peer_uid, _ = struct.unpack("3i", connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            if peer_pid != pid or peer_uid != 0:
                raise ValueError
        # PID мог измениться во время чтения /proc или подключения.
        if go_systemctl("show", "-p", "MainPID", "--value") != pid_text:
            raise ValueError
        return pid
    except (OSError, ValueError, AttributeError, struct.error):
        raise RuntimeError("Принадлежность процесса или сокета AWG Go не подтверждена") from None

def go_preflight_locked():
    """Вызывается systemd перед каждым запуском, включая восстановление после аварии."""
    if get_implementation("awg") != "go":
        raise RuntimeError("Служба Go не соответствует сохранённой реализации")
    errors = state_permission_errors()
    if errors:
        raise RuntimeError("Нарушена доверенная граница AWG Go")
    require_go_components()
    require_go_unit()
    snapshot = load_state_snapshot(expected_backend="awg")
    close_firewall_guard(persist=True)
    cleanup_go_stale_socket()
    if interface_exists() or os.path.lexists(AWG_GO_SOCKET):
        raise RuntimeError("Имя интерфейса или сокета AWG Go занято; автоматическая очистка запрещена")
    port = snapshot["listen_port"]
    if run_cmd(f"ss -ulnH 'sport = :{port}'", check=False):
        raise RuntimeError("UDP-порт AWG Go уже занят")
    # Пересечение с посторонними маршрутами не исправляется удалением маршрутов.
    for entry in json.loads(run_cmd("ip -j -4 route show table all")):
        if entry.get("dst", "default") != "default" and ipaddress.ip_network(VPN_NET).overlaps(
                ipaddress.ip_network(entry["dst"], strict=False)):
            raise RuntimeError("Подсеть AWG Go пересекается с существующим маршрутом")
    # Проверка пересылаемого WAN-пути требует уже созданного входного wg0.
    # Она выполняется в go_restore_locked при закрытой защитной цепочке.

def record_go_socket(pid):
    """Запоминает конкретный сокет только после независимого доказательства владения."""
    info = os.lstat(AWG_GO_SOCKET)
    _atomic_write_root_file(AWG_GO_SOCKET_RECORD, json.dumps({
        "device": info.st_dev, "inode": info.st_ino, "ctime_ns": info.st_ctime_ns,
        "pid": pid, "start": Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19],
    }) + "\n", mode=0o600)

def cleanup_go_stale_socket():
    """После SIGKILL удаляет только подтверждённый мёртвый сокет прежнего процесса."""
    if not os.path.lexists(AWG_GO_SOCKET):
        return
    trusted_go_path(AWG_GO_SOCKET_RECORD, private=True)
    try:
        if Path(AWG_GO_SOCKET_RECORD).stat().st_size > 2048:
            raise ValueError
        record = json.loads(Path(AWG_GO_SOCKET_RECORD).read_text())
        if set(record) != {"device", "inode", "ctime_ns", "pid", "start"}:
            raise ValueError
        if any(type(record[key]) is not int or record[key] < 0 for key in ("device", "inode", "ctime_ns", "pid")):
            raise ValueError
        info = os.lstat(AWG_GO_SOCKET)
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077
                or (info.st_dev, info.st_ino, info.st_ctime_ns) != (record["device"], record["inode"], record["ctime_ns"])):
            raise ValueError
        try:
            start = Path(f"/proc/{record['pid']}/stat").read_text().rsplit(")", 1)[1].split()[19]
        except FileNotFoundError:
            start = None
        if start == record["start"]:
            raise ValueError
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(1)
            try:
                connection.connect(AWG_GO_SOCKET)
            except ConnectionRefusedError:
                pass
            else:
                raise ValueError
        latest = os.lstat(AWG_GO_SOCKET)
        if (latest.st_dev, latest.st_ino, latest.st_ctime_ns) != (info.st_dev, info.st_ino, info.st_ctime_ns):
            raise ValueError
        os.unlink(AWG_GO_SOCKET)
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError):
        raise RuntimeError("Оставшийся сокет Go не доказан как собственный и мёртвый; очистка запрещена") from None

def go_restore_locked():
    """Полная конфигурация применяется после каждого нового процесса, без новых ключей."""
    errors = state_permission_errors()
    if errors:
        raise RuntimeError("Нарушена доверенная граница AWG Go")
    snapshot = load_state_snapshot(expected_backend="awg")
    if snapshot["implementation"] != "go":
        raise RuntimeError("Восстановление Go запрещено для другой реализации")
    close_firewall_guard(persist=True)
    try:
        deadline = time.monotonic() + 15
        while not os.path.lexists(AWG_GO_SOCKET) or not interface_exists():
            # Процесс уже должен быть собственным, хотя его сокет ещё создаётся.
            go_process_identity(require_socket=False)
            if time.monotonic() >= deadline:
                raise RuntimeError("AWG Go не создал интерфейс и сокет за 15 секунд")
            time.sleep(0.05)
        pid = go_process_identity()
        record_go_socket(pid)
        if not interface_exists() or "tun" not in run_cmd(f"ip -d link show {WG_IF}", check=False).lower():
            raise RuntimeError("AWG Go не создал ожидаемый TUN-интерфейс")
        path = write_setconf(snapshot["server_private_key"], "awg", snapshot["awg_params"], snapshot["listen_port"])
        try:
            run_cmd(f"{snapshot['wg_bin']} setconf {WG_IF} {shlex.quote(str(path))}")
        except (RuntimeError, OSError):
            raise RuntimeError("Не удалось применить полный профиль AWG Go; ответ с секретными полями скрыт") from None
        run_cmd(f"ip link set down dev {WG_IF}")
        run_cmd(f"ip -4 addr flush dev {WG_IF}")
        run_cmd(f"ip addr add {SERVER_IP}/24 dev {WG_IF}")
        run_cmd(f"ip link set dev {WG_IF} mtu 1280")
        snapshot = prepare_internet_policy(snapshot)
        public_client_firewall_rules()
        _apply_awg_peers(snapshot)
        rebuild_policy_chains(snapshot)
        run_cmd(f"ip link set up dev {WG_IF}")
        _verify_awg_before_open(snapshot)
        if go_process_identity() != pid:
            raise RuntimeError("Процесс AWG Go изменился во время восстановления")
        open_firewall_guard()
        _verify_awg_ready(snapshot)
        run_cmd("netfilter-persistent save")
    except Exception:
        close_firewall_guard(persist=True)
        raise

def go_lifecycle(action):
    """Блокировка операции не используется службой; systemctl ждёт вне runtime_lock."""
    with runtime_lock(lock_path=AWG_GO_OPERATION_LOCK):
        _go_lifecycle_locked(action)

def _go_lifecycle_locked(action):
    """Операция под уже захваченной блокировкой Go."""
    with runtime_lock():
        snapshot = load_state_snapshot(expected_backend="awg")
        if snapshot["implementation"] != "go":
            raise RuntimeError("Сохранённая реализация изменилась; операция остановлена")
        require_go_unit()
        if interface_exists() and awg_interface_ownership(snapshot) != "owned":
            raise RuntimeError("Принадлежность интерфейса Go не подтверждена; остановка запрещена")
        # Работающий процесс также нельзя останавливать по одному имени службы.
        pid = go_systemctl("show", "-p", "MainPID", "--value")
        if pid != "0":
            go_process_identity()
            if action == "start":
                _sync_awg_runtime_locked(snapshot)
                return
        else:
            cleanup_go_stale_socket()
            if os.path.lexists(AWG_GO_SOCKET) or interface_exists():
                raise RuntimeError("Без процесса Go остался интерфейс или сокет; очистка запрещена")
        close_firewall_guard(persist=True)
    try:
        go_systemctl(action)
    except Exception:
        with runtime_lock():
            close_firewall_guard(persist=True)
        raise
    with runtime_lock():
        if action == "stop":
            if go_systemctl("show", "-p", "MainPID", "--value") != "0" or interface_exists() or os.path.lexists(AWG_GO_SOCKET):
                raise RuntimeError("Остановка Go не подтверждена; защитная цепочка сохранена")
            cleanup_owned_firewall()
            run_cmd("netfilter-persistent save")
        else:
            snapshot = load_state_snapshot(expected_backend="awg")
            _verify_awg_ready(snapshot)

def run_cmd(cmd, check=True):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Ошибка выполнения '{cmd}': {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout.strip()

@contextmanager
def runtime_lock(timeout=LOCK_TIMEOUT_SECONDS, lock_path=None):
    """Сериализует все изменения желаемого и фактического состояния LanFabric."""
    if fcntl is None:
        raise RuntimeError("Межпроцессная блокировка LanFabric поддерживается только на POSIX-сервере")
    Path(LOCK_DIR).mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(lock_path or LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
    deadline = time.monotonic() + timeout
    acquired = False
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"Не удалось получить блокировку LanFabric за {timeout} секунд")
                time.sleep(0.1)
        yield
    finally:
        if acquired:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

def command_succeeds(cmd):
    """Проверяет только код возврата команды без зависимости от stdout."""
    return subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0

def derive_public_key(private_key, wg_bin):
    """Вычисляет public key через stdin, не помещая private key в shell/diagnostics."""
    try:
        result = subprocess.run(
            [wg_bin, "pubkey"],
            input=str(private_key).strip() + "\n",
            capture_output=True,
            text=True,
        )
    except OSError as e:
        raise RuntimeError(f"Не удалось запустить {wg_bin} pubkey: {e}")
    if result.returncode != 0:
        raise RuntimeError(
            f"Не удалось вычислить публичный ключ через {wg_bin}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    public_key = result.stdout.strip()
    if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", public_key):
        raise RuntimeError(f"{wg_bin} вернул публичный ключ некорректного формата")
    return public_key

def generate_awg_params(profile="legacy"):
    """Генерирует явно выбранный профиль без изменения сохранённого состояния."""
    if profile == "awg31":
        return generate_awg31_params()
    if profile != "legacy":
        raise RuntimeError("Неизвестный профиль AmneziaWG; допустимы legacy и awg31")
    s1 = 15 + secrets.randbelow(136)
    s2 = 15 + secrets.randbelow(136)
    while s1 + 56 == s2:
        s2 = 15 + secrets.randbelow(136)

    headers = set()
    while len(headers) < 4:
        headers.add(5 + secrets.randbelow(2147483643))

    h1, h2, h3, h4 = list(headers)
    return {
        "Jc": 7,
        "Jmin": 40,
        "Jmax": 90,
        "S1": s1,
        "S2": s2,
        "H1": h1,
        "H2": h2,
        "H3": h3,
        "H4": h4,
    }

def generate_awg31_params():
    """Создаёт полный профиль AWG 3.1 по официальному профилю клиента 5.0.3.0."""
    return {
        "Jc": 4 + secrets.randbelow(3), "Jmin": 10, "Jmax": 50,
        "S1": 12, "S2": 12, "S3": 12, "S4": 12,
        "H1": 1, "H2": 2, "H3": 3, "H4": 4,
        "HeaderProtectionKey": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        "RekeyAfterTime": "100-120", "RekeyTimeout": "3-7",
        "RejectAfterTime": "150-180", "KeepaliveTimeout": "5-15",
        "MaxHandshakeAttempts": "15-20", "ContentPaddingAddition": "10-100",
        "RandomTrailers": "on", "DisableCookies": "on",
    }

def _validate_awg_number(value, key, maximum, minimum=0):
    """Проверяет целое или диапазон, не включая исходное значение в ошибку."""
    text = str(value)
    match = re.fullmatch(r"([0-9]{1,10})(?:-([0-9]{1,10}))?", text)
    if not match:
        raise RuntimeError(f"Некорректный параметр AmneziaWG {key}: ожидается число или диапазон")
    lower = int(match.group(1))
    upper = int(match.group(2)) if match.group(2) is not None else lower
    if not minimum <= lower <= upper <= maximum:
        raise RuntimeError(f"Некорректный диапазон параметра AmneziaWG {key}")
    normalized = lower if match.group(2) is None else f"{lower}-{upper}"
    return normalized, lower, upper

def validate_awg_params(params):
    """Строго проверяет прежний или полный современный профиль без потери полей."""
    unsupported = set(params) - set(AWG31_PARAM_KEYS)
    if unsupported:
        raise RuntimeError("В профиле AmneziaWG есть неподдерживаемые поля; I1-I5 пока не поддерживаются")
    modern = any(key in params for key in AWG31_EXTRA_KEYS)
    required = AWG31_PARAM_KEYS if modern else AWG_PARAM_KEYS
    missing = [key for key in required if key not in params]
    if missing:
        raise RuntimeError("В параметрах AmneziaWG отсутствуют поля: " + ", ".join(missing))

    values = {}
    bounds = {}
    for key in required:
        if key == "HeaderProtectionKey":
            try:
                value = params[key]
                if not isinstance(value, str):
                    raise ValueError
                decoded = base64.b64decode(value, validate=True)
                if len(decoded) != 32 or not any(decoded) or base64.b64encode(decoded).decode("ascii") != value:
                    raise ValueError
            except (ValueError, TypeError, binascii.Error):
                raise RuntimeError("Некорректный HeaderProtectionKey: требуется ключ из 32 байт в base64") from None
            values[key] = value
        elif key in ("RandomTrailers", "DisableCookies"):
            value = str(params[key]).lower()
            if value not in ("on", "off"):
                raise RuntimeError(f"Некорректный параметр AmneziaWG {key}: ожидается on или off")
            values[key] = value
        else:
            maximum = 4294967295 if key.startswith("H") else 65535
            minimum = 1 if key == "Jc" else 0
            value, lower, upper = _validate_awg_number(params[key], key, maximum, minimum)
            if not isinstance(value, int) and key not in AWG31_TIMER_KEYS and not key.startswith("H"):
                raise RuntimeError(f"Параметр AmneziaWG {key} должен быть целым числом")
            if not modern and not isinstance(value, int):
                raise RuntimeError(f"Диапазон {key} требует полного профиля AWG 3.1")
            values[key] = value
            bounds[key] = (lower, upper)

    if (bounds["Jmin"][1] > bounds["Jmax"][0] or
            (not modern and bounds["Jmin"][1] == bounds["Jmax"][0])):
        raise RuntimeError("Некорректные параметры AmneziaWG Jmin/Jmax")
    if modern:
        if any(bounds[key][0] < 12 for key in ("S1", "S2", "S3", "S4")):
            raise RuntimeError("Параметры S1-S4 с HeaderProtectionKey должны быть не меньше 12")
    else:
        if not 1 <= values["Jc"] <= 128:
            raise RuntimeError("Некорректный параметр AmneziaWG Jc: ожидается 1..128")
        if values["Jmax"] > 1280:
            raise RuntimeError("Некорректные параметры AmneziaWG Jmin/Jmax: ожидается Jmax <= 1280")
        if values["S1"] > 1132 or values["S2"] > 1188:
            raise RuntimeError("Некорректные параметры AmneziaWG S1/S2")
        if values["S1"] + 56 == values["S2"]:
            raise RuntimeError("Некорректные параметры AmneziaWG: S1 + 56 не должно совпадать с S2")
        if any(not 5 <= values[key] <= 2147483647 for key in ("H1", "H2", "H3", "H4")):
            raise RuntimeError("Параметры AmneziaWG H1-H4 должны быть в диапазоне 5..2147483647")

    headers = [bounds[key] for key in ("H1", "H2", "H3", "H4")]
    for i, (lower, upper) in enumerate(headers):
        if any(lower <= other_upper and other_lower <= upper for other_lower, other_upper in headers[:i]):
            raise RuntimeError("Параметры AmneziaWG H1-H4 не должны пересекаться")
    return values

def read_awg_params_file():
    """Читает профиль без создания состояния и без вывода его содержимого."""
    params = {}
    with open(AWG_PARAMS_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise RuntimeError("Некорректная строка параметров AmneziaWG")
            key, value = line.split("=", 1)
            key = key.strip()
            if key in params:
                raise RuntimeError("Повторяющееся поле параметров AmneziaWG")
            params[key] = value.strip()
    return validate_awg_params(params)

def write_awg_params_file(params):
    """Сохраняет все проверенные поля с правами 0600."""
    params = validate_awg_params(params)
    Path(REMOTE_DIR).mkdir(parents=True, exist_ok=True)
    write_private_file(AWG_PARAMS_PATH, format_awg_params(params) + "\n")

def get_or_create_awg_params(profile="legacy"):
    """Создаёт профиль только при отсутствии файла и явно заданном формате."""
    if profile not in ("legacy", "awg31"):
        raise RuntimeError("Неизвестный профиль AmneziaWG; допустимы legacy и awg31")
    if os.path.exists(AWG_PARAMS_PATH):
        params = read_awg_params_file()
        actual = "awg31" if "HeaderProtectionKey" in params else "legacy"
        if profile != actual:
            raise RuntimeError("Сохранённый профиль AmneziaWG отличается от выбранного; автоматическая замена запрещена")
        return params

    params = generate_awg_params(profile=profile)
    write_awg_params_file(params)
    log.info(f"Параметры AmneziaWG созданы: {AWG_PARAMS_PATH}")
    return params

def format_awg_params(params):
    """Формирует полный проверенный блок параметров для .conf."""
    params = validate_awg_params(params)
    keys = AWG31_PARAM_KEYS if "HeaderProtectionKey" in params else AWG_PARAM_KEYS
    return "\n".join(f"{key} = {params[key]}" for key in keys)

def validate_listen_port(value):
    """Проверяет порт без включения исходного значения в ошибку."""
    if not re.fullmatch(r"[0-9]{1,5}", str(value)) or not 1 <= int(value) <= 65535:
        raise RuntimeError("ListenPort должен быть целым числом 1..65535")
    return int(value)

def read_listen_port():
    """Отсутствие файла означает прежний порт; повреждение не исправляется."""
    try:
        value = Path(LISTEN_PORT_PATH).read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return WG_BASE_PORT
    return validate_listen_port(value)

def write_listen_port(value):
    write_private_file(LISTEN_PORT_PATH, str(validate_listen_port(value)) + "\n")

def build_setconf(priv, backend, awg_params=None, listen_port=None):
    """Формирует конфиг для wg/awg setconf без неявного создания состояния."""
    port = read_listen_port() if listen_port is None else validate_listen_port(listen_port)
    conf = f"""[Interface]
PrivateKey = {priv}
ListenPort = {port}
"""
    if backend == "awg":
        params = read_awg_params_file() if awg_params is None else validate_awg_params(awg_params)
        conf += format_awg_params(params) + "\n"
    return conf

def write_private_file(path, content):
    """Записывает файл с приватными данными с правами 0600."""
    fd = os.open(os.fspath(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        file_obj = os.fdopen(fd, "w", encoding="utf-8")
        fd = None
        with file_obj:
            file_obj.write(content)
    finally:
        if fd is not None:
            os.close(fd)

def write_setconf(priv, backend, awg_params=None, listen_port=None):
    """Сохраняет производный конфиг для wg/awg setconf."""
    setconf_path = Path(f"/etc/wireguard/{WG_IF}.setconf")
    write_private_file(setconf_path, build_setconf(priv, backend, awg_params=awg_params, listen_port=listen_port))
    return setconf_path

def ensure_awg_setconf():
    """Пересобирает setconf только из уже существующих проверенных данных."""
    priv, _ = read_server_key_material("awg")
    params = read_awg_params_file()
    return write_setconf(priv, "awg", awg_params=params)

def read_server_key_material(backend):
    """Строго читает и сверяет серверную пару ключей, не выводя приватный ключ."""
    priv_path = Path(f"/etc/wireguard/{WG_IF}.private")
    pub_path = Path(f"/etc/wireguard/{WG_IF}.public")
    if not priv_path.is_file():
        raise RuntimeError(f"Приватный ключ сервера отсутствует: {priv_path}")
    if not pub_path.is_file():
        raise RuntimeError(f"Публичный ключ сервера отсутствует: {pub_path}")
    priv = priv_path.read_text(encoding="utf-8").strip()
    pub = pub_path.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", priv or ""):
        raise RuntimeError("Приватный ключ сервера имеет некорректный формат")
    if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", pub or ""):
        raise RuntimeError("Публичный ключ сервера имеет некорректный формат")
    wg_bin = backend_tools(backend, get_implementation(backend))
    if derive_public_key(priv, wg_bin) != pub:
        raise RuntimeError("Сохранённые приватный и публичный ключи сервера не соответствуют друг другу")
    return priv, pub

def validate_user_rows(rows, wg_bin):
    """Проверяет записи пользователей и соответствие их пар ключей."""
    network = ipaddress.ip_network(VPN_NET)
    seen_ips = set()
    seen_pubkeys = set()
    for row in rows:
        name = str(row["name"] or "")
        pubkey = str(row["pubkey"] or "")
        privkey = str(row["privkey"] or "")
        ip_text = str(row["ip"] or "")
        if not name:
            raise RuntimeError("В БД обнаружена учётная запись без имени")
        if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", pubkey):
            raise RuntimeError(f"Некорректный публичный ключ пользователя {name}")
        if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", privkey):
            raise RuntimeError(f"Некорректный приватный ключ пользователя {name}")
        if derive_public_key(privkey, wg_bin) != pubkey:
            raise RuntimeError(f"Пара ключей пользователя {name} не соответствует друг другу")
        try:
            address = ipaddress.ip_address(ip_text)
        except ValueError:
            raise RuntimeError(f"Некорректный IP пользователя {name}: {ip_text}")
        if address not in network or ip_text == SERVER_IP or address == network.network_address or address == network.broadcast_address:
            raise RuntimeError(f"IP пользователя {name} находится вне допустимого пула: {ip_text}")
        if ip_text in seen_ips:
            raise RuntimeError(f"В БД повторяется IP: {ip_text}")
        if pubkey in seen_pubkeys:
            raise RuntimeError(f"В БД повторяется публичный ключ пользователя {name}")
        seen_ips.add(ip_text)
        seen_pubkeys.add(pubkey)
        for field in ("admin", "internet", "blocked"):
            if int(row[field]) not in (0, 1):
                raise RuntimeError(f"Некорректный флаг {field} у пользователя {name}")

def load_state_snapshot(expected_backend=None):
    """Строго читает сохранённое состояние без создания или исправления данных."""
    if sys.version_info < (3, 10):
        raise RuntimeError("Для восстановления LanFabric требуется Python 3.10+")
    backend = require_backend()
    if expected_backend is not None and backend != expected_backend:
        raise RuntimeError(f"Ожидался backend {expected_backend}, сохранён backend {backend}")
    implementation = get_implementation(backend)
    wg_bin = backend_tools(backend, implementation)
    if implementation == "go":
        require_go_components()
        if not os.path.exists("/dev/net/tun"):
            raise RuntimeError("Устройство TUN отсутствует; переключение на модуль ядра запрещено")
    else:
        if not run_cmd(f"command -v {wg_bin}", check=False):
            raise RuntimeError(f"Бинарник backend не найден: {wg_bin}")
        module = "amneziawg" if backend == "awg" else "wireguard"
        if not command_succeeds(f"modprobe -n {module}"):
            raise RuntimeError(f"Модуль ядра backend недоступен: {module}")
    priv, pub = read_server_key_material(backend)
    awg_params = read_awg_params_file() if backend == "awg" else None
    listen_port = read_listen_port()
    conn = init_db(read_only=True)
    try:
        quick_check = conn.execute("PRAGMA quick_check").fetchone()[0]
        if str(quick_check).lower() != "ok":
            raise RuntimeError(f"Проверка SQLite завершилась ошибкой: {quick_check}")
        rows = [dict(row) for row in conn.execute(
            "SELECT name, pubkey, privkey, ip, admin, internet, blocked, comment FROM users ORDER BY ip"
        ).fetchall()]
    finally:
        conn.close()
    validate_user_rows(rows, wg_bin)
    return {"backend": backend, "implementation": implementation, "wg_bin": wg_bin, "server_private_key": priv, "server_public_key": pub, "awg_params": awg_params, "listen_port": listen_port, "users": rows}

def ensure_iptables_rule(rule):
    """Добавляет правило iptables, если оно ещё не существует."""
    check_rule = rule.replace(" -A ", " -C ", 1)
    res = subprocess.run(check_rule, shell=True, capture_output=True, text=True)
    if res.returncode != 0:
        run_cmd(rule)

def delete_iptables_rule(rule):
    """Удаляет одно точное правило iptables, если оно существует."""
    delete_rule = rule.replace(" -A ", " -D ", 1)
    run_cmd(f"{delete_rule} 2>/dev/null || true", check=False)

def get_wan_interface(ip):
    """Проверяет однозначный физический выход для пересылаемого IPv4 клиента."""
    if ipaddress.ip_address(ip) not in ipaddress.ip_network(VPN_NET):
        raise RuntimeError("IP клиента вне VPN-сети; определение WAN прекращено")
    rules = [line.split() for line in run_cmd("ip -4 rule show").splitlines()]
    if rules != [["0:", "from", "all", "lookup", "local"],
                 ["32766:", "from", "all", "lookup", "main"],
                 ["32767:", "from", "all", "lookup", "default"]]:
        raise RuntimeError("Дополнительные IPv4 policy rules: выход клиента неоднозначен")

    defaults = run_cmd("ip -4 route show table main default").splitlines()
    if len(defaults) != 1:
        raise RuntimeError("Нужен ровно один маршрут IPv4 по умолчанию для клиентов")
    parts = defaults[0].split()
    if (parts[:2] != ["default", "via"] or parts.count("via") != 1 or parts.count("dev") != 1 or
            parts.index("via") + 1 >= len(parts) or parts.index("dev") + 1 >= len(parts)):
        raise RuntimeError("Неоднозначный IPv4 маршрут по умолчанию для NAT")
    gateway = parts[parts.index("via") + 1]
    interface = parts[parts.index("dev") + 1]
    if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", interface) or interface in (WG_IF, "lo"):
        raise RuntimeError("Внешний IPv4-интерфейс для NAT отсутствует или является туннелем")
    try:
        ipaddress.IPv4Address(gateway)
        links = json.loads(run_cmd(f"ip -d -j link show dev {interface}"))
    except (ValueError, IndexError) as e:
        raise RuntimeError(f"Не удалось проверить внешний интерфейс NAT: {e}") from e
    if (not isinstance(links, list) or len(links) != 1 or not isinstance(links[0], dict) or
            links[0].get("ifname") != interface or
            links[0].get("link_type") != "ether" or links[0].get("linkinfo") or
            not isinstance(links[0].get("flags"), list) or
            "UP" not in links[0].get("flags", [])):
        raise RuntimeError("Интерфейс NAT не подтверждён как активный физический Ethernet")

    for probe in ("1.1.1.1", "8.8.8.8"):
        if run_cmd(f"ip -4 route show table main match {probe}/32").splitlines() != defaults:
            raise RuntimeError("Для контрольного адреса есть особый маршрут; выбор WAN неоднозначен")
        route = run_cmd(f"ip -4 route get {probe} from {ip} iif {WG_IF}").splitlines()
        tokens = route[0].split() if route else []
        if (not tokens or tokens[0] != probe or tokens.count("dev") != 1 or
                tokens.count("via") != 1 or tokens.index("dev") + 1 >= len(tokens) or
                tokens.index("via") + 1 >= len(tokens) or
                tokens[tokens.index("dev") + 1] != interface or
                tokens[tokens.index("via") + 1] != gateway):
            raise RuntimeError("Пересылаемый трафик клиента идёт не по проверенному WAN-маршруту")
    return interface

def _iptables_prefix(table):
    return "iptables" if table == "filter" else f"iptables -t {table}"

def _chain_exists(table, chain):
    return subprocess.run(
        f"{_iptables_prefix(table)} -S {chain}",
        shell=True, capture_output=True, text=True
    ).returncode == 0

def _ensure_chain(table, chain):
    if not _chain_exists(table, chain):
        run_cmd(f"{_iptables_prefix(table)} -N {chain}")

def _delete_rule_all(table, chain, spec, limit=64):
    """Удаляет все точные копии правила с конечным пределом повторов."""
    prefix = _iptables_prefix(table)
    for _ in range(limit):
        check = subprocess.run(
            f"{prefix} -C {chain} {spec}",
            shell=True, capture_output=True, text=True
        )
        if check.returncode != 0:
            return
        run_cmd(f"{prefix} -D {chain} {spec}")
    raise RuntimeError(f"Слишком много повторов правила iptables: {table}/{chain} {spec}")

def _chain_rule_lines(table, chain):
    output = run_cmd(f"{_iptables_prefix(table)} -S {chain}", check=False)
    return [line for line in output.splitlines() if line.startswith("-A ")]

def _remove_legacy_firewall_rules():
    """Удаляет только узнаваемые правила LanFabric 0.0.17 для выделенной VPN-подсети."""
    _delete_rule_all("filter", "FORWARD", f"-i {WG_IF} -o {WG_IF} -j ACCEPT")
    _delete_rule_all("filter", "FORWARD", f"-i {WG_IF} -j DROP")
    _delete_rule_all("nat", "POSTROUTING", f"-s {VPN_NET} -j MASQUERADE")

    network = ipaddress.ip_network(VPN_NET)
    for line in run_cmd("iptables -S FORWARD", check=False).splitlines():
        match = re.fullmatch(r"-A FORWARD -s (\d+\.\d+\.\d+\.\d+)/32 -j ACCEPT", line)
        if match:
            try:
                address = ipaddress.ip_address(match.group(1))
            except ValueError:
                continue
            if address in network:
                _delete_rule_all("filter", "FORWARD", f"-s {address}/32 -j ACCEPT")

    for line in run_cmd("iptables -t nat -S POSTROUTING", check=False).splitlines():
        match = re.fullmatch(r"-A POSTROUTING -s (\d+\.\d+\.\d+\.\d+)/32 -o eth0 -j MASQUERADE", line)
        if match:
            try:
                address = ipaddress.ip_address(match.group(1))
            except ValueError:
                continue
            if address in network:
                _delete_rule_all("nat", "POSTROUTING", f"-s {address}/32 -o eth0 -j MASQUERADE")

def close_firewall_guard(persist=True):
    """Закрывает трафик wg0 до любых изменений runtime и ставит свой hook первым."""
    _ensure_chain("filter", FW_GUARD_CHAIN)
    _ensure_chain("filter", FW_FORWARD_CHAIN)
    _ensure_chain("nat", FW_NAT_CHAIN)

    run_cmd(f"iptables -I {FW_GUARD_CHAIN} 1 -j DROP")
    hook = f"-A FORWARD -i {WG_IF} -j {FW_GUARD_CHAIN}"
    current_rules = _chain_rule_lines("filter", "FORWARD")
    if not current_rules or current_rules[0] != hook:
        run_cmd(f"iptables -I FORWARD 1 -i {WG_IF} -j {FW_GUARD_CHAIN}")
        current_rules = _chain_rule_lines("filter", "FORWARD")

    duplicate_positions = [
        index + 1 for index, rule in enumerate(current_rules)
        if rule == hook and index != 0
    ]
    for position in reversed(duplicate_positions):
        run_cmd(f"iptables -D FORWARD {position}")

    if persist:
        run_cmd("netfilter-persistent save")

def public_client_firewall_rules():
    """Проверяет внешние клиентские правила; возвращает только доказанно свои."""
    owned = []
    network = ipaddress.ip_network(VPN_NET)
    for table, chain, target, marker in (
        ("filter", "FORWARD", "ACCEPT", FORWARD_MARK),
        ("nat", "POSTROUTING", "MASQUERADE", NAT_MARK),
    ):
        for line in run_cmd(f"{_iptables_prefix(table)} -S {chain}").splitlines():
            parts = shlex.split(line)
            if parts[:2] != ["-A", chain] or "-s" not in parts or "-j" not in parts:
                continue
            source_index = parts.index("-s") + 1
            target_index = parts.index("-j") + 1
            if source_index >= len(parts) or target_index >= len(parts):
                raise RuntimeError("Не удалось разобрать клиентское правило; нужна отдельная миграция")
            if parts[target_index] not in (target, "SNAT" if table == "nat" else target):
                continue
            try:
                source = ipaddress.ip_network(parts[source_index], strict=False)
            except ValueError:
                raise RuntimeError("Не удалось проверить источник клиентского правила; нужна отдельная миграция")
            if source.version != network.version or not source.overlaps(network):
                continue
            address = source.network_address
            expected = ["-A", chain, "-s", parts[source_index]]
            if table == "nat":
                if len(parts) < 6 or parts[4] != "-o" or not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", parts[5]):
                    raise RuntimeError("NAT без доказанной принадлежности LanFabric; нужна отдельная миграция")
                expected += ["-o", parts[5]]
            expected += ["-m", "comment", "--comment", marker, "-j", target]
            if source.prefixlen != 32 or address not in network or parts != expected:
                raise RuntimeError("Правило VPN без доказанной принадлежности LanFabric; нужна отдельная миграция")
            owned.append((table, chain, shlex.join(parts[2:])))
    return owned

def _remove_owned_public_client_rules():
    """Удаляет и перепроверяет только маркированные правила прежней ветки NAT."""
    for table, chain, spec in public_client_firewall_rules():
        _delete_rule_all(table, chain, spec)
    if public_client_firewall_rules():
        raise RuntimeError("Маркированные правила остались после удаления; очистка не подтверждена")

def prepare_internet_policy(snapshot):
    """Выбирает WAN для активных клиентов до замены участников и правил."""
    interfaces = {}
    for row in _active_users(snapshot):
        if int(row["internet"]):
            interfaces[row["ip"]] = get_wan_interface(row["ip"])
    if len(set(interfaces.values())) > 1:
        raise RuntimeError("Активные клиенты используют разные WAN-интерфейсы; применение остановлено")
    if "wan_interfaces" in snapshot and snapshot["wan_interfaces"] != interfaces:
        raise RuntimeError("WAN изменился во время применения; защитный запрет трафика должен остаться закрытым")
    return dict(snapshot, wan_interfaces=interfaces)

def rebuild_policy_chains(snapshot):
    """Пересобирает принадлежащие LanFabric цепочки при закрытом guard."""
    snapshot = prepare_internet_policy(snapshot)
    _remove_owned_public_client_rules()
    _ensure_chain("filter", FW_FORWARD_CHAIN)
    _ensure_chain("nat", FW_NAT_CHAIN)
    run_cmd(f"iptables -F {FW_FORWARD_CHAIN}")
    run_cmd(f"iptables -t nat -F {FW_NAT_CHAIN}")

    run_cmd(f"iptables -A {FW_FORWARD_CHAIN} -o {WG_IF} -j ACCEPT")
    for row in _active_users(snapshot):
        if int(row["internet"]):
            run_cmd(f"iptables -A {FW_FORWARD_CHAIN} -s {row['ip']}/32 -j ACCEPT")
            interface = snapshot["wan_interfaces"][row["ip"]]
            run_cmd(f"iptables -t nat -A {FW_NAT_CHAIN} -s {row['ip']}/32 -o {interface} -j MASQUERADE")
    run_cmd(f"iptables -A {FW_FORWARD_CHAIN} -j DROP")

    _delete_rule_all("nat", "POSTROUTING", f"-s {VPN_NET} -j {FW_NAT_CHAIN}")
    run_cmd(f"iptables -t nat -I POSTROUTING 1 -s {VPN_NET} -j {FW_NAT_CHAIN}")

def open_firewall_guard():
    """Переводит guard из DROP в проверенную рабочую policy без открытого промежутка."""
    _delete_rule_all("filter", FW_GUARD_CHAIN, f"-j {FW_FORWARD_CHAIN}")
    run_cmd(f"iptables -A {FW_GUARD_CHAIN} -j {FW_FORWARD_CHAIN}")
    _delete_rule_all("filter", FW_GUARD_CHAIN, "-j DROP")

def cleanup_owned_firewall(allow_missing=False):
    """Удаляет только собственные цепочки и доказанно свои клиентские правила."""
    if allow_missing and not command_succeeds("command -v iptables"):
        if interface_exists():
            raise RuntimeError("Есть интерфейс VPN, но нет iptables для проверки правил; установка остановлена")
        return
    _remove_owned_public_client_rules()
    _delete_rule_all("filter", "FORWARD", f"-i {WG_IF} -j {FW_GUARD_CHAIN}")
    _delete_rule_all("nat", "POSTROUTING", f"-s {VPN_NET} -j {FW_NAT_CHAIN}")

    if _chain_exists("filter", FW_GUARD_CHAIN):
        run_cmd(f"iptables -F {FW_GUARD_CHAIN}")
    if _chain_exists("filter", FW_FORWARD_CHAIN):
        run_cmd(f"iptables -F {FW_FORWARD_CHAIN}")
    if _chain_exists("nat", FW_NAT_CHAIN):
        run_cmd(f"iptables -t nat -F {FW_NAT_CHAIN}")

    if _chain_exists("filter", FW_GUARD_CHAIN):
        run_cmd(f"iptables -X {FW_GUARD_CHAIN}")
    if _chain_exists("filter", FW_FORWARD_CHAIN):
        run_cmd(f"iptables -X {FW_FORWARD_CHAIN}")
    if _chain_exists("nat", FW_NAT_CHAIN):
        run_cmd(f"iptables -t nat -X {FW_NAT_CHAIN}")


def ensure_legacy_base_firewall_rules():
    """Сохраняет прежний firewall-контракт только для backend wg."""
    delete_iptables_rule(f"iptables -A FORWARD -i {WG_IF} -j DROP")
    ensure_iptables_rule(f"iptables -A FORWARD -i {WG_IF} -o {WG_IF} -j ACCEPT")
    ensure_iptables_rule(f"iptables -A FORWARD -i {WG_IF} -j DROP")

def ensure_legacy_client_internet_rules(ip):
    """Сохраняет прежний internet-контракт только для backend wg."""
    delete_iptables_rule(f"iptables -A FORWARD -i {WG_IF} -j DROP")
    ensure_iptables_rule(f"iptables -A FORWARD -s {ip} -j ACCEPT")
    ensure_iptables_rule(f"iptables -t nat -A POSTROUTING -s {ip} -o eth0 -j MASQUERADE")
    ensure_iptables_rule(f"iptables -A FORWARD -i {WG_IF} -j DROP")

def load_runtime_identity(expected_backend=None):
    """Читает минимум данных для безопасной остановки/проверки владения интерфейсом."""
    backend = require_backend()
    if expected_backend is not None and backend != expected_backend:
        raise RuntimeError(f"Ожидался backend {expected_backend}, сохранён backend {backend}")
    _, pub = read_server_key_material(backend)
    implementation = get_implementation(backend)
    return {"backend": backend, "implementation": implementation,
            "wg_bin": backend_tools(backend, implementation), "server_public_key": pub}

def interface_exists():
    return subprocess.run(
        f"ip link show {WG_IF}", shell=True, capture_output=True, text=True
    ).returncode == 0

def awg_interface_ownership(identity):
    """Возвращает absent/owned/unknown для wg0."""
    if not interface_exists():
        return "absent"
    detail = run_cmd(f"ip -d link show {WG_IF}", check=False)
    if identity.get("implementation", "kernel") == "go":
        try:
            go_process_identity()
        except RuntimeError:
            return "unknown"
        if "tun" not in detail.lower():
            return "unknown"
        actual_pub = run_cmd(f"{identity['wg_bin']} show {WG_IF} public-key", check=False).strip()
        return "owned" if actual_pub == identity["server_public_key"] else "unknown"
    if "amneziawg" not in detail.lower():
        return "unknown"
    actual_pub = run_cmd(f"awg show {WG_IF} public-key", check=False).strip()
    return "owned" if actual_pub == identity["server_public_key"] else "unknown"

def _apply_awg_peers(snapshot):
    wg_bin = snapshot.get("wg_bin", "awg")
    current = run_cmd(f"{wg_bin} show {WG_IF} peers", check=False)
    for peer in current.splitlines():
        if peer:
            run_cmd(f"{wg_bin} set {WG_IF} peer {peer} remove")
    for row in _active_users(snapshot):
        run_cmd(
            f"{wg_bin} set {WG_IF} peer {row['pubkey']} "
            f"allowed-ips {row['ip']}/32 persistent-keepalive 25"
        )

def firewall_readiness_errors(snapshot, guard_open=True):
    """Проверяет точную принадлежащую LanFabric firewall policy."""
    errors = []
    try:
        snapshot = prepare_internet_policy(snapshot)
        if public_client_firewall_rules():
            errors.append("Вне собственных цепочек остались маркированные правила клиентов")
    except RuntimeError as e:
        errors.append(str(e))
        return errors
    forward_rules = _chain_rule_lines("filter", "FORWARD")
    hook = f"-A FORWARD -i {WG_IF} -j {FW_GUARD_CHAIN}"
    if not forward_rules or forward_rules[0] != hook:
        errors.append("Hook LanFabric не является первым правилом FORWARD для wg0")
    if forward_rules.count(hook) != 1:
        errors.append("Hook LanFabric присутствует в FORWARD не ровно один раз")

    guard_rules = _chain_rule_lines("filter", FW_GUARD_CHAIN)
    if guard_open:
        expected_guard = [f"-A {FW_GUARD_CHAIN} -j {FW_FORWARD_CHAIN}"]
        if guard_rules != expected_guard:
            errors.append("Защитный guard LanFabric не находится в рабочем состоянии")
    elif not guard_rules or guard_rules[0] != f"-A {FW_GUARD_CHAIN} -j DROP":
        errors.append("Защитный guard LanFabric не закрыт во время применения")

    expected_forward = [f"-A {FW_FORWARD_CHAIN} -o {WG_IF} -j ACCEPT"]
    for row in _active_users(snapshot):
        if int(row["internet"]):
            expected_forward.append(f"-A {FW_FORWARD_CHAIN} -s {row['ip']}/32 -j ACCEPT")
    expected_forward.append(f"-A {FW_FORWARD_CHAIN} -j DROP")
    if _chain_rule_lines("filter", FW_FORWARD_CHAIN) != expected_forward:
        errors.append("Цепочка FORWARD LanFabric не совпадает с политиками БД")

    expected_nat = []
    for row in _active_users(snapshot):
        if int(row["internet"]):
            interface = snapshot["wan_interfaces"][row["ip"]]
            expected_nat.append(f"-A {FW_NAT_CHAIN} -s {row['ip']}/32 -o {interface} -j MASQUERADE")
    if _chain_rule_lines("nat", FW_NAT_CHAIN) != expected_nat:
        errors.append("Цепочка NAT LanFabric не совпадает с политиками БД")

    nat_rules = _chain_rule_lines("nat", "POSTROUTING")
    nat_hook = f"-A POSTROUTING -s {VPN_NET} -j {FW_NAT_CHAIN}"
    if not nat_rules or nat_rules[0] != nat_hook or nat_rules.count(nat_hook) != 1:
        errors.append("Переход в цепочку NAT LanFabric должен быть первым и единственным")
    return errors

def _verify_awg_before_open(snapshot):
    errors = runtime_readiness_errors(snapshot, check_firewall=False)
    errors.extend(firewall_readiness_errors(snapshot, guard_open=False))
    if errors:
        raise RuntimeError("Runtime не готов к открытию guard: " + "; ".join(errors))

def _verify_awg_ready(snapshot):
    errors = runtime_readiness_errors(snapshot, check_firewall=False)
    errors.extend(firewall_readiness_errors(snapshot, guard_open=True))
    if errors:
        raise RuntimeError("Runtime AWG не прошёл финальную проверку: " + "; ".join(errors))

def _restore_awg_runtime_locked(snapshot):
    """Fail-closed восстановление AWG из одного проверенного снимка."""
    if snapshot.get("implementation", "kernel") == "go":
        raise RuntimeError("Запуск Go выполняется службой вне блокировки состояния; используйте start")
    ownership = awg_interface_ownership(snapshot)
    if ownership == "unknown":
        raise RuntimeError(f"Интерфейс {WG_IF} существует, но его принадлежность LanFabric не подтверждена")

    close_firewall_guard(persist=True)
    created = ownership == "absent"
    try:
        run_cmd("modprobe amneziawg")
        setconf_path = str(write_setconf(
            snapshot["server_private_key"], "awg", awg_params=snapshot["awg_params"],
            listen_port=snapshot.get("listen_port", WG_BASE_PORT)
        ))
        if created:
            run_cmd(f"ip link add {WG_IF} type amneziawg")
        else:
            run_cmd(f"ip link set down dev {WG_IF}")
        try:
            run_cmd(f"awg setconf {WG_IF} {setconf_path}")
        except (RuntimeError, OSError):
            # tools может включить отвергнутую строку с HPK в stderr.
            raise RuntimeError("Не удалось применить конфигурацию AWG; проверьте совместимость tools и модуля") from None
        run_cmd(f"ip -4 addr flush dev {WG_IF}")
        run_cmd(f"ip addr add {SERVER_IP}/24 dev {WG_IF}")
        snapshot = prepare_internet_policy(snapshot)
        public_client_firewall_rules()
        _apply_awg_peers(snapshot)
        rebuild_policy_chains(snapshot)
        run_cmd(f"ip link set up dev {WG_IF}")
        _verify_awg_before_open(snapshot)
        open_firewall_guard()
        _verify_awg_ready(snapshot)
        run_cmd("netfilter-persistent save")
    except Exception as original:
        try:
            if awg_interface_ownership(snapshot) == "owned":
                run_cmd(f"ip link set down dev {WG_IF}", check=False)
            close_firewall_guard(persist=True)
        except Exception as cleanup_error:
            log.error(f"Аварийная стабилизация также завершилась ошибкой: {cleanup_error}")
        raise original

def _sync_awg_runtime_locked(snapshot):
    """Безопасно применяет peers/policy к уже работающему собственному AWG runtime."""
    if awg_interface_ownership(snapshot) != "owned":
        raise RuntimeError("sync разрешён только для подтверждённого runtime LanFabric")
    close_firewall_guard(persist=True)
    try:
        snapshot = prepare_internet_policy(snapshot)
        public_client_firewall_rules()
        _apply_awg_peers(snapshot)
        rebuild_policy_chains(snapshot)
        _verify_awg_before_open(snapshot)
        open_firewall_guard()
        _verify_awg_ready(snapshot)
        run_cmd("netfilter-persistent save")
    except Exception as original:
        try:
            close_firewall_guard(persist=True)
        except Exception as cleanup_error:
            log.error(f"Не удалось сохранить закрытый guard после ошибки sync: {cleanup_error}")
        raise original

def _stop_awg_runtime_locked():
    identity = load_runtime_identity(expected_backend="awg")
    if identity.get("implementation", "kernel") == "go":
        raise RuntimeError("Остановка Go выполняется службой вне блокировки состояния; используйте stop")
    ownership = awg_interface_ownership(identity)
    if ownership == "unknown":
        raise RuntimeError(f"Интерфейс {WG_IF} существует, но его принадлежность LanFabric не подтверждена")
    if ownership == "owned":
        close_firewall_guard(persist=True)
        run_cmd(f"ip link set down dev {WG_IF}", check=False)
        run_cmd(f"ip link del {WG_IF}")
        if interface_exists():
            close_firewall_guard(persist=True)
            raise RuntimeError(f"Не удалось подтвердить удаление интерфейса {WG_IF}; защитный guard сохранён")
    cleanup_owned_firewall()
    run_cmd("netfilter-persistent save")

def cmd_stop():
    """Останавливает VPN runtime без удаления пакетов и данных."""
    backend = require_backend()
    log.info(f"Остановка VPN runtime. Backend: {backend}")
    if get_implementation(backend) == "go":
        go_lifecycle("stop")
        log.info("AWG Go остановлен; ключи и пользователи сохранены")
        return
    if backend == "wg":
        run_cmd(f"systemctl stop wg-quick@{WG_IF} 2>/dev/null || true", check=False)
        _remove_legacy_firewall_rules()
        run_cmd("netfilter-persistent save 2>/dev/null || true", check=False)
    else:
        _stop_awg_runtime_locked()
    log.info("VPN runtime остановлен")
    add_advice("Для повторного запуска выполните start, для проверки состояния — status или health")

def cmd_start():
    """Запускает VPN runtime по сохранённому backend без полного init."""
    backend = require_backend()
    log.info(f"Запуск VPN runtime. Backend: {backend}")
    if get_implementation(backend) == "go":
        go_lifecycle("start")
        log.info("AWG Go запущен и проверен")
        return
    if backend == "wg":
        run_cmd(f"systemctl enable wg-quick@{WG_IF}")
        run_cmd(f"systemctl restart wg-quick@{WG_IF}")
        cmd_sync()
    else:
        snapshot = load_state_snapshot(expected_backend="awg")
        _restore_awg_runtime_locked(snapshot)
    log.info("VPN runtime запущен")
    add_advice("Выполните status или health. Для подключения клиента скачайте конфиг командой config <имя>")

def cmd_restart():
    """Перезапускает VPN runtime без полного init под общей внешней блокировкой."""
    log.info("Перезапуск VPN runtime")
    if get_implementation() == "go":
        go_lifecycle("restart")
        log.info("AWG Go перезапущен и проверен без изменения ключей")
        return
    cmd_stop()
    cmd_start()

def cleanup_runtime():
    """Останавливает подтверждённый runtime и удаляет только принадлежащее LanFabric состояние."""
    backend = require_backend()
    if backend == "awg":
        _stop_awg_runtime_locked()
    else:
        run_cmd(f"systemctl disable --now wg-quick@{WG_IF} 2>/dev/null || true", check=False)
        if interface_exists():
            run_cmd(f"ip link del {WG_IF} 2>/dev/null || true", check=False)
        _remove_legacy_firewall_rules()
        run_cmd("netfilter-persistent save 2>/dev/null || true", check=False)
        run_cmd("modprobe -r wireguard 2>/dev/null || true", check=False)
    if backend == "awg":
        run_cmd("modprobe -r amneziawg 2>/dev/null || true", check=False)

def _atomic_write_root_file(path, content, mode=0o644):
    """Атомарно записывает root-owned служебный файл."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.parent / f".{target.name}.new-{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", closefd=True) as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        os.chown(tmp, 0, 0)
        os.chmod(tmp, mode)
        os.replace(tmp, target)
        dir_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass

def trusted_python_path():
    """Возвращает реальный доверенный путь текущего Python 3.10+."""
    if sys.version_info < (3, 10):
        raise RuntimeError("Для root-службы требуется Python 3.10+")
    path = Path(os.path.realpath(sys.executable))
    if not path.is_file():
        raise RuntimeError(f"Интерпретатор Python не найден: {path}")
    for parent in [path, *path.parents]:
        st = parent.stat()
        if st.st_uid != 0:
            raise RuntimeError(f"Путь Python не принадлежит root: {parent}")
        if st.st_mode & 0o022:
            raise RuntimeError(f"Путь Python доступен для записи группе или остальным: {parent}")
        if str(parent) == "/":
            break
    return str(path)

def awg_autostart_unit_text(python_path=None):
    """Возвращает узкий boot-only systemd contract для AWG."""
    python_path = python_path or "/usr/bin/python3"
    return f"""[Unit]
Description=LanFabric AWG boot restore
After=systemd-sysctl.service netfilter-persistent.service
Wants=netfilter-persistent.service

[Service]
Type=oneshot
ExecStart={python_path} -u {REMOTE_DIR}/vsrv-admin.py _boot-awg
TimeoutStartSec={AWG_AUTOSTART_TIMEOUT_SECONDS}s
Restart=no
UMask=0077
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
"""

def state_permission_errors():
    """Проверяет доверенную цепочку root entrypoint без исправления состояния."""
    errors = []
    for path_text in (
        "/", "/opt", REMOTE_DIR,
        "/etc", "/etc/systemd", "/etc/systemd/system", WG_DIR,
    ):
        path = Path(path_text)
        try:
            st = path.stat()
        except OSError as e:
            errors.append(f"Не удалось проверить права {path}: {e}")
            continue
        if st.st_uid != 0:
            errors.append(f"Каталог {path} не принадлежит root")
        if st.st_mode & 0o022:
            errors.append(f"Каталог {path} доступен для записи группе или остальным")

    for path_text in (
        f"{REMOTE_DIR}/vsrv-admin.py", DB_PATH, BACKEND_PATH,
        AWG_PARAMS_PATH, f"{WG_DIR}/{WG_IF}.private", LISTEN_PORT_PATH,
    ):
        path = Path(path_text)
        if path_text == LISTEN_PORT_PATH and not path.exists():
            continue  # прежнее состояние без файла порта поддерживается
        try:
            st = path.stat()
        except OSError as e:
            errors.append(f"Не удалось проверить защищённый файл {path}: {e}")
            continue
        if st.st_uid != 0:
            errors.append(f"Файл {path} не принадлежит root")
        if st.st_mode & 0o077:
            errors.append(f"Файл {path} доступен группе или остальным")

    try:
        trusted_python_path()
    except Exception as e:
        errors.append(str(e))
    if os.path.lexists(IMPLEMENTATION_PATH):
        try:
            trusted_go_path(IMPLEMENTATION_PATH, private=True)
        except RuntimeError as e:
            errors.append(str(e))
    return errors

def ensure_awg_autostart_unit():
    """Устанавливает и разрешает boot-only unit без запуска/перезапуска VPN."""
    snapshot = load_state_snapshot(expected_backend="awg")
    ensure_state_permissions()
    errors = state_permission_errors()
    if errors:
        raise RuntimeError("Нельзя включить AWG autostart: " + "; ".join(errors))
    python_path = trusted_python_path()
    if snapshot.get("implementation", "kernel") == "go":
        if os.path.lexists(AWG_AUTOSTART_PATH):
            raise RuntimeError("Сохранилась служба AWG ядра; для смены реализации нужна отдельная миграция")
        if os.path.lexists(AWG_GO_UNIT_PATH):
            require_go_unit()
        else:
            _atomic_write_root_file(AWG_GO_UNIT_PATH, awg_go_unit_text(python_path), mode=0o644)
            go_systemctl("daemon-reload")
        go_systemctl("enable")
        if go_systemctl("is-enabled") != "enabled":
            raise RuntimeError("Автозапуск AWG Go не включён")
        return
    _atomic_write_root_file(
        AWG_AUTOSTART_PATH,
        awg_autostart_unit_text(python_path=python_path),
        mode=0o644,
    )
    run_cmd("systemctl daemon-reload")
    run_cmd(f"systemctl enable {AWG_AUTOSTART_UNIT}")
    enabled = run_cmd(f"systemctl is-enabled {AWG_AUTOSTART_UNIT}", check=False).strip()
    if enabled != "enabled":
        raise RuntimeError(f"AWG autostart не включён после установки unit: {enabled or 'unknown'}")

def cancel_awg_boot_before_lock():
    """Останавливает незавершённую boot-задачу ДО захвата runtime lock."""
    run_cmd(f"systemctl stop {AWG_AUTOSTART_UNIT} 2>/dev/null || true", check=False)

def disable_awg_autostart(remove_unit=False):
    """Отключает будущий boot restore; текущий wg0 отдельно не останавливает."""
    if os.path.exists(BACKEND_PATH) and get_implementation() == "go":
        if remove_unit:
            raise RuntimeError("Удаление службы Go требует отдельного этапа установки и удаления по #28")
        require_go_unit()
        go_systemctl("disable")
        return
    run_cmd(f"systemctl disable {AWG_AUTOSTART_UNIT} 2>/dev/null || true", check=False)
    if remove_unit:
        run_cmd(f"rm -f {AWG_AUTOSTART_PATH}", check=False)
        run_cmd("systemctl daemon-reload")
        run_cmd(f"systemctl reset-failed {AWG_AUTOSTART_UNIT} 2>/dev/null || true", check=False)

def awg_autostart_state():
    is_go = get_implementation("awg") == "go"
    unit = AWG_GO_UNIT if is_go else AWG_AUTOSTART_UNIT
    unit_path = AWG_GO_UNIT_PATH if is_go else AWG_AUTOSTART_PATH
    installed = os.path.isfile(unit_path)
    enabled = run_cmd(f"systemctl is-enabled {unit}", check=False).strip()
    result = run_cmd(
        f"systemctl show {unit} -p Result --value 2>/dev/null",
        check=False
    ).strip()
    return {
        "installed": installed,
        "enabled": enabled == "enabled",
        "enabled_raw": enabled or "not-found",
        "last_result": result or "unknown",
    }

def cmd_autostart(args):
    """Явно управляет persistent AWG autostart, не меняя текущий runtime."""
    if args.autostart_action == "enable":
        ensure_awg_autostart_unit()
        log.info("AWG autostart установлен и разрешён. Текущий runtime не перезапускался.")
    elif args.autostart_action == "disable":
        disable_awg_autostart(remove_unit=False)
        log.info("AWG autostart отключён. Текущий runtime не останавливался.")
    else:
        state = awg_autostart_state()
        log.info(f"AWG autostart unit установлен: {'ДА' if state['installed'] else 'НЕТ'}")
        log.info(f"AWG autostart enabled: {'ДА' if state['enabled'] else 'НЕТ'} ({state['enabled_raw']})")
        log.info(f"Результат последней systemd-попытки: {state['last_result']}")
        try:
            snapshot = load_state_snapshot(expected_backend="awg")
            errors = runtime_readiness_errors(snapshot, check_firewall=True)
            log.info(f"Фактический AWG runtime готов: {'ДА' if not errors else 'НЕТ'}")
        except Exception as e:
            log.warning(f"Фактический AWG runtime готов: НЕТ ({e})")

def cmd_boot_awg():
    """Внутренняя точка входа systemd: только строгий restore, без init/fallback."""
    errors = state_permission_errors()
    if errors:
        raise RuntimeError("Нарушена доверенная граница AWG autostart: " + "; ".join(errors))
    snapshot = load_state_snapshot(expected_backend="awg")
    _restore_awg_runtime_locked(snapshot)
    log.info("AWG runtime автоматически восстановлен после загрузки")

def remove_packages(purge=False):
    """Удаляет установленные VPN-пакеты."""
    action = "purge" if purge else "remove"
    log.info(f"Удаление VPN-пакетов через apt-get {action}")

    packages = [
        "wireguard",
        "wireguard-tools",
        "amneziawg",
        "amneziawg-tools",
        "amneziawg-dkms",
    ]

    run_cmd(
        "DEBIAN_FRONTEND=noninteractive apt-get "
        f"{action} -y " + " ".join(packages) + " 2>/dev/null || true",
        check=False
    )

    if purge:
        run_cmd("DEBIAN_FRONTEND=noninteractive apt-get autoremove -y 2>/dev/null || true", check=False)
        run_cmd("DEBIAN_FRONTEND=noninteractive apt-get autoclean -y 2>/dev/null || true", check=False)


def cleanup_amnezia_repo():
    """Удаляет подключённый PPA AmneziaWG."""
    log.info("Удаление источников пакетов AmneziaWG")
    run_cmd("rm -f /etc/apt/sources.list.d/amnezia-ubuntu-ppa*.list 2>/dev/null || true", check=False)
    run_cmd("rm -f /etc/apt/trusted.gpg.d/amnezia*.gpg 2>/dev/null || true", check=False)
    run_cmd("apt-get update -qq 2>/dev/null || true", check=False)


def cmd_remove(args):
    """Удаление VPN runtime и пакетов без удаления данных LanFabric."""
    if args.confirm != "REMOVE":
        raise RuntimeError("Для подтверждения удаления укажите: REMOVE")
    if get_implementation() == "go":
        return cmd_remove_go(purge=False)

    log.info("Начало remove: удаление runtime и пакетов, данные сохраняются")

    disable_awg_autostart(remove_unit=True)
    cleanup_runtime()
    remove_packages(purge=False)

    log.info("Remove завершён. Данные /opt/vpn-admin и /etc/wireguard сохранены.")
    add_advice("Для повторного развёртывания выполните init. Для полного удаления используйте purge PURGE")


def cmd_purge(args):
    """Полное удаление LanFabric с сервера."""
    if args.confirm != "PURGE":
        raise RuntimeError("Для подтверждения полного удаления укажите: PURGE")
    if get_implementation() == "go":
        return cmd_remove_go(purge=True)

    log.info("Начало purge: полное удаление LanFabric с сервера")

    disable_awg_autostart(remove_unit=True)
    cleanup_runtime()
    remove_packages(purge=True)
    cleanup_amnezia_repo()

    log.info("Удаление конфигураций и данных LanFabric")
    run_cmd("rm -rf /etc/wireguard 2>/dev/null || true", check=False)
    run_cmd(f"rm -f {SUDOERS_PATH} 2>/dev/null || true", check=False)
    run_cmd(f"rm -f {SUDOERS_LANFABRIC_GLOB} 2>/dev/null || true", check=False)
    run_cmd("rm -f /etc/sysctl.d/99-vpn-forward.conf 2>/dev/null || true", check=False)

    log.info("Удаление каталога LanFabric. Серверный модуль будет удалён вместе с каталогом.")
    run_cmd(f"rm -rf {REMOTE_DIR} 2>/dev/null || true", check=False)
    print("Purge завершён. LanFabric полностью удалён с сервера.")
    add_advice("Для новой установки заново выполните init с клиента")

def validate_db_schema(conn):
    """Проверяет обязательную схему БД без её изменения."""
    expected = ["name", "pubkey", "privkey", "ip", "admin", "internet", "blocked", "comment"]
    rows = conn.execute("PRAGMA table_info(users)").fetchall()
    actual = [row[1] for row in rows]
    if actual != expected:
        raise RuntimeError("Некорректная схема БД users: " f"ожидались поля {', '.join(expected)}, получено {', '.join(actual) or 'нет таблицы'}")

def init_db(create=False, read_only=False):
    """Открывает БД. Создание разрешено только явному init-пути."""
    if read_only and create:
        raise RuntimeError("Нельзя одновременно создавать БД и открывать её только для чтения")
    if not os.path.exists(DB_PATH) and not create:
        raise RuntimeError(f"База данных отсутствует: {DB_PATH}. Автоматическое создание запрещено")
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True) if read_only else sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    if create:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                name TEXT PRIMARY KEY,
                pubkey TEXT NOT NULL,
                privkey TEXT NOT NULL,
                ip TEXT NOT NULL UNIQUE,
                admin INTEGER DEFAULT 0,
                internet INTEGER DEFAULT 0,
                blocked INTEGER DEFAULT 0,
                comment TEXT DEFAULT ''
            )
        """)
        conn.commit()
    try:
        validate_db_schema(conn)
    except Exception:
        conn.close()
        raise
    return conn

def allocate_ip(conn):
    """Находит первый свободный IP в подсети начиная с 10.8.0.2."""
    used = set()
    for row in conn.execute("SELECT ip FROM users WHERE ip IS NOT NULL"):
        try:
            used.add(int(ipaddress.IPv4Address(row[0])))
        except ValueError:
            continue
    base = int(ipaddress.IPv4Address("10.8.0.2"))
    last = int(ipaddress.IPv4Address("10.8.0.254"))
    for num in range(base, last + 1):
        if num not in used:
            return str(ipaddress.IPv4Address(num))
    raise RuntimeError("Свободные IP-адреса в пуле отсутствуют")

def ensure_dirs():
    """Создаёт необходимые директории."""
    conf_dir = Path(CONF_DIR)
    conf_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    conf_dir.chmod(0o700)
    wg_dir = Path(WG_DIR)
    wg_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    wg_dir.chmod(0o700)

def ensure_state_permissions():
    """Закрепляет root-only границу кода и состояния перед запуском root-службы."""
    for directory in (Path(REMOTE_DIR), Path(CONF_DIR), Path(WG_DIR)):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chown(directory, 0, 0)
        directory.chmod(0o700)

    protected_files = [
        Path(REMOTE_DIR) / "vsrv-admin.py",
        Path(DB_PATH),
        Path(BACKEND_PATH),
        Path(AWG_PARAMS_PATH),
        Path(LISTEN_PORT_PATH),
        Path(IMPLEMENTATION_PATH),
        Path(WG_DIR) / f"{WG_IF}.private",
        Path(WG_DIR) / f"{WG_IF}.setconf",
    ]
    for path in protected_files:
        if path.exists():
            os.chown(path, 0, 0)
            path.chmod(0o600)

    public_key = Path(WG_DIR) / f"{WG_IF}.public"
    if public_key.exists():
        os.chown(public_key, 0, 0)
        public_key.chmod(0o644)

    for cfg in Path(CONF_DIR).glob("*.conf"):
        if cfg.is_file():
            os.chown(cfg, 0, 0)
            cfg.chmod(0o600)

def cmd_init(args):
    """Инициализация сервера, установка пакетов, настройка интерфейса."""
    if getattr(args, "implementation", None) == "go":
        return cmd_init_go(args)
    if os.path.lexists(IMPLEMENTATION_PATH) and get_implementation("awg") == "go":
        raise RuntimeError("init поверх AWG Go запрещён: обновление должно сохранить ключи и пользователей по #28")
    # Временная установка AWG 3.1 имеет отдельные ключи, сеть и службу.
    # init не является её миграцией и не должен создавать второй VPN рядом.
    if os.path.lexists("/opt/lanfabric-awg31") or os.path.lexists("/etc/systemd/system/lanfabric-awg31.service"):
        raise RuntimeError(
            "Обнаружена отдельная установка AWG 3.1. init остановлен до изменений. "
            "Для сохранения профилей нужна согласованная миграция по задаче #28."
        )
    # Проверить выбор и существующее состояние до очистки ключей/БД/runtime.
    requested_port = getattr(args, "listen_port", None)
    listen_port = read_listen_port() if requested_port is None else validate_listen_port(requested_port)
    profile = getattr(args, "awg_profile", None)
    if args.no_amnezia and profile is not None:
        raise RuntimeError("--awg-profile несовместим с --no-amnezia")
    awg_params = None
    if not args.no_amnezia:
        if profile not in (None, "legacy", "awg31"):
            raise RuntimeError("Неизвестный профиль AmneziaWG")
        if os.path.exists(AWG_PARAMS_PATH):
            awg_params = read_awg_params_file()
            saved_profile = "awg31" if "HeaderProtectionKey" in awg_params else "legacy"
            if profile is not None and profile != saved_profile:
                raise RuntimeError("Сохранённый профиль отличается от выбранного; автоматическая замена запрещена")
        else:
            awg_params = validate_awg_params(generate_awg_params(profile=profile or "legacy"))
    log.info("Начало инициализации сервера")
    ensure_dirs()
    ensure_state_permissions()

    # --- Очистка предыдущего состояния ---
    log.info("Очистка предыдущего состояния VPN (если есть)")
    disable_awg_autostart(remove_unit=True)

    if os.path.exists(BACKEND_PATH):
        cleanup_runtime()
    elif interface_exists():
        raise RuntimeError(
            f"Интерфейс {WG_IF} существует без сохранённого backend; "
            "его принадлежность LanFabric не подтверждена, init остановлен"
        )
    else:
        cleanup_owned_firewall(allow_missing=True)
        run_cmd("netfilter-persistent save 2>/dev/null || true", check=False)

    run_cmd("rm -f /etc/wireguard/wg0.conf", check=False)
    run_cmd("rm -f /etc/wireguard/wg0.private /etc/wireguard/wg0.public", check=False)
    run_cmd("rm -f /opt/vpn-admin/backend", check=False)
    init_db(create=True).close()
    ensure_state_permissions()

    # --- Установка пакетов ---
    log.info("Обновление списка пакетов")
    run_cmd("apt-get update -qq")

    backend = None

    if args.no_amnezia:
        log.info("Установка стандартного WireGuard")
        run_cmd("DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard")
        backend = "wg"
    else:
        log.info("Попытка установки AmneziaWG")
        try:
            run_cmd("apt-get install -y software-properties-common gnupg2")
            run_cmd("add-apt-repository -y ppa:amnezia/ppa")
            run_cmd("apt-get update -qq")
            run_cmd(
                "DEBIAN_FRONTEND=noninteractive apt-get "
                "-o Dpkg::Options::=--force-confdef "
                "-o Dpkg::Options::=--force-confold install -y amneziawg"
            )
            backend = "awg"
        except RuntimeError as e:
            run_cmd("rm -f /etc/apt/sources.list.d/amnezia-ubuntu-ppa*.list || true", check=False)
            run_cmd("apt-get update -qq", check=False)
            raise RuntimeError(
                f"AmneziaWG недоступен ({e}). Перезапустите с --no-amnezia"
            )

    # Общие зависимости
    run_cmd("DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent")

    log.info(f"Выбран backend: {backend}")

    with open("/opt/vpn-admin/backend", "w") as f:
        f.write(backend)

    # --- Загрузка модуля ---
    if backend == "awg":
        log.info("Загрузка модуля AmneziaWG")
        run_cmd("command -v awg")
        try:
            run_cmd("modprobe amneziawg")
        except RuntimeError as e:
            raise RuntimeError(
                f"Не удалось загрузить модуль AmneziaWG: {e}. "
                "Проверьте установку amneziawg или перезапустите init с --no-amnezia"
            )
        wg_bin = "awg"
    else:
        log.info("Загрузка модуля WireGuard")
        run_cmd("command -v wg")
        try:
            run_cmd("modprobe wireguard")
        except RuntimeError as e:
            raise RuntimeError(
                f"Не удалось загрузить модуль WireGuard: {e}"
            )
        wg_bin = "wg"

    # --- Включение IP forward ---
    current = run_cmd("sysctl -n net.ipv4.ip_forward", check=False)
    if current.strip() != "1":
        log.info("Включение IPv4 forward")
        run_cmd("sysctl -w net.ipv4.ip_forward=1")

    conf_path = "/etc/sysctl.d/99-vpn-forward.conf"
    if not os.path.exists(conf_path):
        with open(conf_path, "w") as f:
            f.write("net.ipv4.ip_forward=1\n")

    # --- Генерация ключей ---
    log.info("Генерация ключей сервера")

    priv_path = "/etc/wireguard/wg0.private"
    pub_path = "/etc/wireguard/wg0.public"

    priv = run_cmd(f"{wg_bin} genkey")
    write_private_file(priv_path, priv)

    server_pub = derive_public_key(priv, wg_bin)
    with open(pub_path, "w") as f:
        f.write(server_pub)

    # --- Конфигурация ---
    log.info("Создание конфигурации интерфейса")

    conf = f"""[Interface]
PrivateKey = {priv}
Address = {SERVER_IP}/24
ListenPort = {listen_port}
PostUp = iptables -A FORWARD -i {WG_IF} -o {WG_IF} -j ACCEPT; iptables -A FORWARD -i {WG_IF} -j DROP
PostDown = iptables -D FORWARD -i {WG_IF} -o {WG_IF} -j ACCEPT; iptables -D FORWARD -i {WG_IF} -j DROP || true
"""
    write_private_file(f"/etc/wireguard/{WG_IF}.conf", conf)

    write_listen_port(listen_port)
    if backend == "awg":
        write_awg_params_file(awg_params)
    write_setconf(priv, backend, awg_params=awg_params, listen_port=listen_port)

    # --- Поднятие интерфейса ---
    log.info("Запуск интерфейса")

    if backend == "wg":
        run_cmd("systemctl enable wg-quick@wg0")
        run_cmd("systemctl restart wg-quick@wg0")
    else:
        snapshot = load_state_snapshot(expected_backend="awg")
        _restore_awg_runtime_locked(snapshot)

    # --- Проверка ---
    run_cmd("ip link show wg0")
    run_cmd(f"{wg_bin} show {WG_IF} public-key")

    # --- Сохранение правил ---
    run_cmd("netfilter-persistent save")
    ensure_state_permissions()
    if backend == "awg":
        ensure_awg_autostart_unit()

    log.info("Инициализация завершена. Интерфейс поднят, правила сохранены.")
    add_advice("Выполните add <имя> для создания пользователя или health для проверки системы")

def cmd_status():
    """Быстрая немутирующая проверка фактического состояния."""
    try:
        backend = require_backend()
    except Exception as e:
        log.warning(f"Backend: ошибка ({e})")
        log.info("Состояние VPN: BROKEN")
        add_advice("Выполните health для подробной диагностики")
        return
    log.info(f"Backend: {backend}")
    try:
        log.info(f"Реализация: {get_implementation(backend)}")
    except RuntimeError:
        log.warning("Сохранённая реализация недостоверна")
    snapshot = None
    snapshot_error = None
    try:
        snapshot = load_state_snapshot(expected_backend=backend)
    except Exception as e:
        snapshot_error = str(e)
    iface_exists = subprocess.run(f"ip link show {WG_IF}", shell=True, capture_output=True, text=True).returncode == 0
    if not iface_exists:
        state = "STOPPED" if snapshot_error is None else "BROKEN"
    elif snapshot_error is not None:
        state = "BROKEN"
    elif backend == "wg":
        svc = run_cmd(f"systemctl is-active wg-quick@{WG_IF}", check=False).strip()
        state = "RUNNING" if svc == "active" and not runtime_readiness_errors(snapshot, check_firewall=False) else "BROKEN"
    else:
        state = "RUNNING" if not runtime_readiness_errors(snapshot, check_firewall=True) else "BROKEN"
    iface = run_cmd(f"ip -brief link show {WG_IF} || echo 'не найден'", check=False)
    log.info("Состояние интерфейса: " + iface)
    if snapshot_error:
        log.warning("Сохранённое состояние некорректно: " + snapshot_error)
    log.info(f"Состояние VPN: {state}")
    if backend == "awg":
        auto = awg_autostart_state()
        log.info(
            "AWG autostart: "
            f"installed={'yes' if auto['installed'] else 'no'}, "
            f"enabled={'yes' if auto['enabled'] else 'no'}, "
            f"last_result={auto['last_result']}"
        )
    if state == "RUNNING":
        add_advice("Можно скачивать клиентские конфиги командой config <имя> или выполнить health для полной проверки")
    elif state == "STOPPED":
        add_advice("Выполните start для запуска VPN runtime")
    else:
        add_advice("Выполните health для подробной диагностики; автоматическое создание потерянных данных запрещено")
    if snapshot is not None:
        total = len(snapshot["users"])
        active = sum(1 for row in snapshot["users"] if not int(row["blocked"]))
        log.info(f"Учётные записи: всего {total}, активных {active}")

def _active_users(snapshot):
    return [row for row in snapshot["users"] if not int(row["blocked"])]

def _expected_peer_map(snapshot):
    return {row["pubkey"]: f"{row['ip']}/32" for row in _active_users(snapshot)}

def awg31_runtime_errors(params, wg_bin="awg"):
    """Сверяет применённые поля; секретные ответы никогда не включаются в ошибки."""
    if not params or "HeaderProtectionKey" not in params:
        return []
    fields = {key: key.lower() for key in AWG_PARAM_KEYS + ("S3", "S4")}
    fields.update({
        "HeaderProtectionKey": "header-protection-key",
        "ContentPaddingAddition": "content-padding-addition",
        "RekeyAfterTime": "rekey-after-time", "RekeyTimeout": "rekey-timeout",
        "RejectAfterTime": "reject-after-time", "KeepaliveTimeout": "keepalive-timeout",
        # В закреплённом upstream tools v3.1.20260812 поле действительно содержит эту опечатку.
        "MaxHandshakeAttempts": "max-handshake-attemps",
        "RandomTrailers": "random-trailers", "DisableCookies": "disable-cookies",
    })
    for key, field in fields.items():
        try:
            result = subprocess.run([wg_bin, "show", WG_IF, field], capture_output=True,
                                    text=True, timeout=2)
            if result.returncode != 0:
                return [f"AWG 3.1: невозможно прочитать поле {key}"]
            actual = result.stdout.strip()
            if key == "HeaderProtectionKey":
                matches = secrets.compare_digest(actual, str(params[key]))
            elif key in ("RandomTrailers", "DisableCookies"):
                matches = actual == params[key]
            else:
                maximum = 4294967295 if key.startswith("H") else 65535
                _, lower, upper = _validate_awg_number(actual, key, maximum)
                _, expected_lower, expected_upper = _validate_awg_number(params[key], key, maximum)
                matches = (lower, upper) == (expected_lower, expected_upper)
            if not matches:
                return [f"AWG 3.1: применённое поле {key} не совпадает с сохранённым"]
        except (OSError, ValueError, TypeError, RuntimeError, subprocess.TimeoutExpired):
            return [f"AWG 3.1: не удалось проверить поле {key}"]
    return []

def runtime_readiness_errors(snapshot, check_firewall=True):
    """Возвращает нарушения обязательных runtime-инвариантов без изменения системы."""
    errors = []
    backend = snapshot["backend"]
    wg_bin = snapshot["wg_bin"]
    detail = run_cmd(f"ip -d link show {WG_IF}", check=False)
    link_state = run_cmd(f"ip link show {WG_IF}", check=False)
    if not detail or not link_state:
        return [f"Интерфейс {WG_IF} отсутствует"]
    flags_match = re.search(r"<([^>]*)>", link_state)
    flags = set(flags_match.group(1).split(",")) if flags_match else set()
    if "UP" not in flags:
        errors.append(f"Интерфейс {WG_IF} не находится в административном состоянии UP")
    is_go = snapshot.get("implementation", "kernel") == "go"
    if is_go:
        if "tun" not in detail.lower():
            errors.append("Интерфейс AWG Go не имеет тип TUN")
        if not re.search(r"\bmtu 1280\b", link_state):
            errors.append("MTU AWG Go отличается от 1280")
        try:
            go_process_identity()
        except RuntimeError:
            errors.append("Принадлежность процесса или сокета AWG Go не подтверждена")
    elif backend == "awg" and "amneziawg" not in detail.lower():
        errors.append(f"Интерфейс {WG_IF} не имеет тип amneziawg")
    actual_pub = run_cmd(f"{wg_bin} show {WG_IF} public-key", check=False).strip()
    if actual_pub != snapshot["server_public_key"]:
        errors.append("Публичный ключ runtime не совпадает с сохранённым ключом сервера")
    addresses = []
    for line in run_cmd(f"ip -4 -o addr show dev {WG_IF}", check=False).splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "inet":
            addresses.append(parts[3])
    expected_address = f"{SERVER_IP}/24"
    if addresses != [expected_address]:
        errors.append(f"IPv4-адрес интерфейса {WG_IF}: ожидался только {expected_address}, получено {', '.join(addresses) or 'нет'}")
    port = snapshot.get("listen_port", WG_BASE_PORT)
    listen_port = run_cmd(f"{wg_bin} show {WG_IF} listen-port", check=False).strip()
    if listen_port != str(port):
        errors.append(f"ListenPort: ожидался {port}, получено {listen_port or 'нет'}")
    if backend == "awg":
        if is_go:
            errors.extend(awg31_runtime_errors(snapshot.get("awg_params"), wg_bin=wg_bin))
        else:
            errors.extend(awg31_runtime_errors(snapshot.get("awg_params")))
    actual_peers = set(filter(None, run_cmd(f"{wg_bin} show {WG_IF} peers", check=False).splitlines()))
    expected_peers = set(_expected_peer_map(snapshot))
    if actual_peers != expected_peers:
        errors.append("Состав peers runtime не совпадает с активными пользователями БД")
    allowed = {}
    for line in run_cmd(f"{wg_bin} show {WG_IF} allowed-ips", check=False).splitlines():
        parts = line.split()
        if parts:
            allowed[parts[0]] = " ".join(parts[1:])
    if allowed != _expected_peer_map(snapshot):
        errors.append("AllowedIPs peers не совпадают с адресами активных пользователей БД")
    if not run_cmd(f"ss -ulnH 'sport = :{port}'", check=False):
        errors.append(f"Порт {port}/UDP не слушается")
    if run_cmd("sysctl -n net.ipv4.ip_forward", check=False).strip() != "1":
        errors.append("IPv4 forward выключен (net.ipv4.ip_forward != 1)")
    if backend == "wg":
        svc = run_cmd(f"systemctl is-active wg-quick@{WG_IF}", check=False).strip()
        if svc != "active":
            errors.append(f"Сервис wg-quick@{WG_IF} не активен (сейчас: {svc or 'unknown'})")
    if check_firewall:
        if backend == "awg":
            errors.extend(firewall_readiness_errors(snapshot, guard_open=True))
        else:
            if subprocess.run(f"iptables -C FORWARD -i {WG_IF} -o {WG_IF} -j ACCEPT", shell=True, capture_output=True, text=True).returncode != 0:
                errors.append("Базовое правило ACCEPT между VPN-клиентами отсутствует")
            if subprocess.run(f"iptables -C FORWARD -i {WG_IF} -j DROP", shell=True, capture_output=True, text=True).returncode != 0:
                errors.append("Базовое правило DROP для трафика из VPN отсутствует")
    return errors

def cmd_health():
    """Строгая немутирующая диагностика; при нарушении инвариантов код выхода ненулевой."""
    log.info("=== Глубокая диагностика ===")
    try:
        snapshot = load_state_snapshot()
    except Exception as e:
        log.warning(f"- Сохранённое состояние некорректно: {e}")
        add_advice("Восстановите обязательные данные из резервной копии или выполните отдельный согласованный init")
        raise RuntimeError("Health завершён с ошибкой: сохранённое состояние недостоверно")
    errors = runtime_readiness_errors(snapshot, check_firewall=True)
    if errors:
        log.warning("Обнаружены проблемы:")
        for err in errors:
            log.warning(f"- {err}")
        add_advice("Исправьте указанное нарушение и повторите health; диагностика сама состояние не изменяет")
        raise RuntimeError(f"Health завершён с ошибкой: нарушений {len(errors)}")
    log.info(f"Backend: {snapshot['backend']}")
    log.info(f"Реализация: {snapshot.get('implementation', 'kernel')}")
    log.info(f"База данных: пользователей {len(snapshot['users'])}")
    log.info("Система работает штатно, обязательные runtime-инварианты подтверждены")

def cmd_sync():
    """Пересборка состояния из одного согласованного снимка БД."""
    log.info("Синхронизация состояния интерфейса и правил")
    snapshot = load_state_snapshot()
    if snapshot["backend"] == "awg":
        _sync_awg_runtime_locked(snapshot)
    else:
        wg_bin = snapshot["wg_bin"]
        current_peers = run_cmd(f"{wg_bin} show {WG_IF} peers")
        for peer in current_peers.splitlines():
            if peer:
                run_cmd(f"{wg_bin} set {WG_IF} peer {peer} remove")
        _remove_legacy_firewall_rules()
        ensure_legacy_base_firewall_rules()
        for row in _active_users(snapshot):
            run_cmd(f"{wg_bin} set {WG_IF} peer {row['pubkey']} allowed-ips {row['ip']}/32 persistent-keepalive 25")
            if int(row["internet"]):
                ensure_legacy_client_internet_rules(row["ip"])
        run_cmd("netfilter-persistent save")
    log.info("Синхронизация завершена")
    add_advice("Выполните health для проверки правил или config <имя> для скачивания клиентского конфига")

def build_client_config(row, endpoint=None):
    """Формирует клиентский конфиг из данных БД."""
    with open(f"{WG_DIR}/{WG_IF}.public") as public_file:
        server_pub = public_file.read().strip()
    server_ip = str(endpoint).strip() if endpoint else run_cmd("hostname -I | awk '{print $1}'").strip()
    allowed_ips = "0.0.0.0/0" if row["internet"] else VPN_NET
    backend = require_backend()
    listen_port = read_listen_port()
    awg_params = ""
    if backend == "awg":
        awg_params = "\n" + format_awg_params(read_awg_params_file())

    return f"""[Interface]
PrivateKey = {row["privkey"]}
Address = {row["ip"]}/32
DNS = 8.8.8.8{awg_params}

[Peer]
PublicKey = {server_pub}
Endpoint = {server_ip}:{listen_port}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""

def write_client_config(row):
    """Сохраняет клиентский конфиг на сервере."""
    cfg_path = Path(f"{CONF_DIR}/{row['name']}.conf")
    cfg_path.write_text(build_client_config(row))
    cfg_path.chmod(0o600)
    return cfg_path

def cmd_backend():
    """Выводит сохранённый backend в stdout без логов."""
    backend = require_backend()
    sys.stdout.write(backend + "\n")

def cmd_config(args):
    """Выводит клиентский конфиг в stdout для безопасного скачивания через sudo."""
    conn = init_db(read_only=True)
    row = conn.execute("SELECT * FROM users WHERE name=?", (args.name,)).fetchone()
    if not row:
        raise RuntimeError(f"Учётная запись '{args.name}' не найдена")

    sys.stdout.write(build_client_config(row, args.endpoint))

def cmd_add(args):
    """Добавление учётной записи."""
    conn = init_db()
    if conn.execute("SELECT 1 FROM users WHERE name=?", (args.name,)).fetchone():
        raise RuntimeError(f"Учётная запись '{args.name}' уже существует")
        
    ip = allocate_ip(conn)
    admin_val = 1 if args.admin else 0
    internet_val = 1 if (args.admin or args.internet) else 0
    blocked_val = 1 if args.block else 0
    backend = require_backend()
    if backend == "awg" and internet_val and not blocked_val:
        get_wan_interface(ip)
        public_client_firewall_rules()
    wg_bin = get_wg_cmd()
    priv = run_cmd(f"{wg_bin} genkey")
    pub = derive_public_key(priv, wg_bin)
    
    conn.execute(
        "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (args.name, pub, priv, ip, admin_val, internet_val, blocked_val, args.comment or "")
    )
    conn.commit()
    
    row = conn.execute("SELECT * FROM users WHERE name=?", (args.name,)).fetchone()
    cfg_path = write_client_config(row)

    if backend == "awg":
        try:
            _sync_awg_runtime_locked(load_state_snapshot(expected_backend="awg"))
        except Exception as e:
            raise RuntimeError(
                f"Учётная запись '{args.name}' сохранена, но применение не завершено: {e}. "
                "Не включайте клиент; проверьте list/health и устраните причину перед повторным sync"
            ) from e
    elif not blocked_val:
        run_cmd(f"{wg_bin} set {WG_IF} peer {pub} allowed-ips {ip}/32 persistent-keepalive 25")
        if internet_val:
            ensure_legacy_client_internet_rules(ip)
            run_cmd("netfilter-persistent save")
    
    log.info(f"Учётная запись '{args.name}' создана. IP: {ip}, Админ: {bool(admin_val)}, Интернет: {bool(internet_val)}")
    log.info(f"Конфиг сохранён: {cfg_path}")
    if internet_val:
        add_advice("Скачайте конфиг командой config и импортируйте его в клиент. Интернет-трафик будет направлен через VPN")
    else:
        add_advice("Скачайте конфиг командой config. По умолчанию будет доступна только VPN-сеть")

def cmd_edit(args):
    """Редактирование учётной записи."""
    conn = init_db()
    user = conn.execute("SELECT * FROM users WHERE name=?", (args.name,)).fetchone()
    if not user:
        raise RuntimeError(f"Учётная запись '{args.name}' не найдена")
        
    updates = []
    params = []
    if args.admin is not None:
        updates.append("admin=?")
        params.append(1 if args.admin else 0)
    if args.internet is not None:
        updates.append("internet=?")
        params.append(1 if args.internet else 0)
    if args.comment is not None:
        updates.append("comment=?")
        params.append(args.comment)
        
    if not updates:
        raise RuntimeError("Не указаны параметры для изменения")
        
    params.append(args.name)
    conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE name=?", params)
    conn.commit()
    log.info("Параметры учётной записи обновлены")
    add_advice("Выполните sync для применения сетевых правил. Если менялся интернет-доступ, заново скачайте config <имя>")

def cmd_block(args):
    """Блокировка учётки с fail-closed применением для AWG."""
    conn = init_db()
    user = conn.execute("SELECT pubkey, ip, internet FROM users WHERE name=?", (args.name,)).fetchone()
    if not user:
        raise RuntimeError(f"Учётная запись '{args.name}' не найдена")
    pub, ip, internet = user
    backend = require_backend()
    if backend == "awg" and get_implementation(backend) == "go":
        snapshot = load_state_snapshot(expected_backend="awg")
        if awg_interface_ownership(snapshot) != "owned":
            raise RuntimeError("Блокировка Go требует подтверждённого собственного интерфейса; БД не изменена")
        close_firewall_guard(persist=True)
    conn.execute("UPDATE users SET blocked=1 WHERE name=?", (args.name,))
    conn.commit()

    if backend == "awg":
        _sync_awg_runtime_locked(load_state_snapshot(expected_backend="awg"))
    else:
        run_cmd(f"wg set {WG_IF} peer {pub} remove")
        if internet:
            run_cmd(f"iptables -D FORWARD -s {ip} -j ACCEPT || true")
            run_cmd(f"iptables -t nat -D POSTROUTING -s {ip} -o eth0 -j MASQUERADE || true")
            run_cmd("netfilter-persistent save")
    log.info(f"Учётная запись '{args.name}' заблокирована. Соединение разорвано.")
    add_advice("Выполните list для проверки статуса или health для проверки runtime")

def cmd_delete(args):
    """Удаление учётки с подтверждением и безопасным применением для AWG."""
    if args.confirm != args.name:
        raise RuntimeError("Подтверждение удаления не совпадает с именем учётной записи")
    conn = init_db()
    user = conn.execute("SELECT pubkey, ip FROM users WHERE name=?", (args.name,)).fetchone()
    if not user:
        raise RuntimeError(f"Учётная запись '{args.name}' не найдена")
    pub, ip = user
    backend = require_backend()
    if backend == "awg" and get_implementation(backend) == "go":
        snapshot = load_state_snapshot(expected_backend="awg")
        if awg_interface_ownership(snapshot) != "owned":
            raise RuntimeError("Удаление участника Go требует подтверждённого собственного интерфейса; БД не изменена")
        close_firewall_guard(persist=True)
    conn.execute("DELETE FROM users WHERE name=?", (args.name,))
    conn.commit()

    cfg = Path(f"{CONF_DIR}/{args.name}.conf")
    if cfg.exists():
        cfg.unlink()

    if backend == "awg":
        _sync_awg_runtime_locked(load_state_snapshot(expected_backend="awg"))
    else:
        run_cmd(f"wg set {WG_IF} peer {pub} remove || true")
        run_cmd(f"iptables -D FORWARD -s {ip} -j ACCEPT || true")
        run_cmd(f"iptables -t nat -D POSTROUTING -s {ip} -o eth0 -j MASQUERADE || true")
        run_cmd("netfilter-persistent save")
    log.info(f"Учётная запись '{args.name}' полностью удалена.")
    add_advice("Выполните list для проверки списка пользователей")

def cmd_list():
    """Список учётных записей."""
    conn = init_db(read_only=True)
    rows = conn.execute("SELECT name, ip, admin, internet, blocked, comment FROM users ORDER BY ip").fetchall()
    if not rows:
        log.info("Список учётных записей пуст")
        return
    log.info(f"{'ИМЯ':<15} {'IP':<12} {'АДМИН':<6} {'ИНЕТ':<6} {'СТАТУС':<10} {'КОММЕНТАРИЙ'}")
    log.info("-" * 70)
    for r in rows:
        status = "БЛОК" if r[4] else "АКТИВ"
        log.info(f"{r[0]:<15} {r[1]:<12} {'ДА' if r[2] else 'НЕТ':<6} {'ДА' if r[3] else 'НЕТ':<6} {status:<10} {r[5]}")

def _run_internal_install_module(argv):
    """Атомарно заменяет root-owned server module из строго проверенного /tmp staged-файла."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--source", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)

    sudo_uid = os.environ.get("SUDO_UID")
    if not os.environ.get("SUDO_USER") or not sudo_uid:
        raise RuntimeError("Внутренняя установка модуля разрешена только через sudo")
    if not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
        raise RuntimeError("Некорректный ожидаемый SHA-256")
    if not re.fullmatch(r"\d+\.\d+\.\d+", args.version):
        raise RuntimeError("Некорректная ожидаемая версия")

    source = Path(args.source)
    if source.parent != Path("/tmp") or not re.fullmatch(r"lanfabric-vsrv-[0-9a-f]{32}\.py", source.name):
        raise RuntimeError("Недопустимый путь staged server module")
    st = source.lstat()
    if not source.is_file() or source.is_symlink():
        raise RuntimeError("Staged server module должен быть обычным файлом")
    if st.st_uid != int(sudo_uid):
        raise RuntimeError("Staged server module не принадлежит вызвавшему sudo пользователю")

    data = source.read_bytes()
    import hashlib
    if hashlib.sha256(data).hexdigest() != args.sha256:
        raise RuntimeError("SHA-256 staged server module не совпадает")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise RuntimeError(f"Server module не является UTF-8: {e}")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match or match.group(1) != args.version:
        raise RuntimeError("Версия staged server module не совпадает")
    compile(text, str(source), "exec")

    target = Path(REMOTE_DIR) / "vsrv-admin.py"
    Path(REMOTE_DIR).mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chown(REMOTE_DIR, 0, 0)
    os.chmod(REMOTE_DIR, 0o700)

    tmp = Path(REMOTE_DIR) / f".vsrv-admin.py.new-{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    try:
        with os.fdopen(fd, "wb", closefd=True) as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chown(tmp, 0, 0)
        os.chmod(tmp, 0o700)
        os.replace(tmp, target)
        dir_fd = os.open(REMOTE_DIR, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass

    print("OK")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "_cleanup-temp-sudoers":
        print(_run_internal_cleanup_temp_sudoers(sys.argv[2:]))
        return

    if len(sys.argv) > 1 and sys.argv[1] == "_install-module":
        try:
            _run_internal_install_module(sys.argv[2:])
        except Exception as e:
            log.error(str(e))
            sys.exit(1)
        return

    if len(sys.argv) > 1 and sys.argv[1] == "_boot-awg":
        try:
            with runtime_lock():
                cmd_boot_awg()
        except Exception as e:
            log.error(str(e))
            sys.exit(1)
        return

    if len(sys.argv) > 1 and sys.argv[1] in ("_go-preflight", "_go-restore", "_go-closed"):
        try:
            if os.geteuid() != 0 or len(sys.argv) != 2:
                raise RuntimeError("Внутренняя операция Go требует root и не принимает аргументы")
            with runtime_lock():
                if sys.argv[1] == "_go-preflight":
                    go_preflight_locked()
                elif sys.argv[1] == "_go-restore":
                    go_restore_locked()
                else:
                    # После аварии состав процесса уже может быть недостоверен.
                    # Только закрываем свою цепочку; не удаляем интерфейс/сокет.
                    close_firewall_guard(persist=True)
        except Exception:
            log.error("Внутренняя операция AWG Go завершилась ошибкой; защитная цепочка не открыта")
            sys.exit(1)
        return
    
    if len(sys.argv) == 1:
        print_intro()
        print("Краткая справка: vsrv-admin.py {init|backend|start|stop|restart|autostart|status|health|sync|add|edit|block|delete|list|config|remove|purge|help} [--version]")
        sys.exit(0)
        
    if "--version" not in sys.argv and (len(sys.argv) < 2 or sys.argv[1] not in ("config", "backend")):
        print_intro()
        
    parser = argparse.ArgumentParser(description="Серверное управление VPN-сетью", add_help=False)
    subparsers = parser.add_subparsers(dest="command")

    p_init = subparsers.add_parser("init", help="Инициализация сервера и установка пакетов")
    p_init.add_argument("--implementation", choices=["kernel", "go"], default=None, help="Явный выбор реализации AWG; Go устанавливается только на чистой цели")
    p_init.add_argument("--no-amnezia", action="store_true", help="Использовать стандартный WireGuard вместо AmneziaWG")
    p_init.add_argument("--listen-port", type=int, default=None, help="UDP-порт 1..65535; при отсутствии сохраняется прежний")
    p_init.add_argument("--awg-profile", choices=["legacy", "awg31"], default=None, help="Профиль AWG; существующий не заменяется, новый по умолчанию legacy")
    subparsers.add_parser("backend", help="Вывести сохранённый backend")
    subparsers.add_parser("start", help="Запуск VPN runtime без полного init")
    subparsers.add_parser("stop", help="Остановка VPN runtime без удаления данных")
    subparsers.add_parser("restart", help="Перезапуск VPN runtime без полного init")
    p_autostart = subparsers.add_parser("autostart", help="Управление автозапуском AWG после загрузки")
    p_autostart.add_argument("autostart_action", choices=["enable", "disable", "status"], help="Включить, отключить или проверить AWG autostart")
    subparsers.add_parser("status", help="Быстрая проверка состояния")
    subparsers.add_parser("health", help="Глубокая диагностика системы")
    subparsers.add_parser("sync", help="Пересборка состояния из базы данных")
    
    p_remove = subparsers.add_parser("remove", help="Удаление VPN runtime и пакетов без удаления данных")
    p_remove.add_argument("confirm", help="Для подтверждения введите REMOVE")

    p_purge = subparsers.add_parser("purge", help="Полное удаление LanFabric с сервера")
    p_purge.add_argument("confirm", help="Для подтверждения введите PURGE")
    
    p_add = subparsers.add_parser("add", help="Создание учётной записи")
    p_add.add_argument("name", help="Имя пользователя")
    p_add.add_argument("--admin", action="store_true", help="Назначить администратора")
    p_add.add_argument("--internet", action="store_true", help="Разрешить доступ в интернет")
    p_add.add_argument("--comment", default="", help="Комментарий к учётке")
    p_add.add_argument("--block", action="store_true", help="Создать сразу заблокированным")
    
    p_edit = subparsers.add_parser("edit", help="Редактирование параметров учётки")
    p_edit.add_argument("name")
    p_edit.add_argument("--admin", type=lambda x: x.lower() in ("true","1","yes"), default=None)
    p_edit.add_argument("--internet", type=lambda x: x.lower() in ("true","1","yes"), default=None)
    p_edit.add_argument("--comment", default=None)
    
    p_block = subparsers.add_parser("block", help="Блокировка учётки")
    p_block.add_argument("name")
    
    p_del = subparsers.add_parser("delete", help="Удаление учётки")
    p_del.add_argument("name", help="Имя учётки")
    p_del.add_argument("confirm", help="Введите имя учётки для подтверждения удаления")
    
    p_cfg = subparsers.add_parser("config", help="Вывод клиентского .conf в stdout")
    p_cfg.add_argument("name", help="Имя учётной записи")
    p_cfg.add_argument("--endpoint", default=None, help="Публичный IP или DNS-имя сервера для Endpoint")

    subparsers.add_parser("list", help="Вывод списка учётных записей")
    subparsers.add_parser("help", help="Подробная справка")
    parser.add_argument("--version", action="version", version=f"vsrv-admin {__version__}")
    
    args = parser.parse_args()
    if args.command == "help" or not args.command:
        parser.print_help(sys.stderr)
        sys.exit(0)
        
    try:
        mutating_commands = {
            "init", "start", "stop", "restart", "sync", "autostart",
            "add", "edit", "block", "delete", "remove", "purge",
        }

        def dispatch():
            if args.command == "init":
                cmd_init(args)
            elif args.command == "backend":
                cmd_backend()
            elif args.command == "start":
                cmd_start()
            elif args.command == "stop":
                cmd_stop()
            elif args.command == "restart":
                cmd_restart()
            elif args.command == "autostart":
                cmd_autostart(args)
            elif args.command == "status":
                cmd_status()
            elif args.command == "health":
                cmd_health()
            elif args.command == "sync":
                cmd_sync()
            elif args.command == "add":
                cmd_add(args)
            elif args.command == "edit":
                cmd_edit(args)
            elif args.command == "block":
                cmd_block(args)
            elif args.command == "delete":
                cmd_delete(args)
            elif args.command == "list":
                cmd_list()
            elif args.command == "config":
                cmd_config(args)
            elif args.command == "remove":
                cmd_remove(args)
            elif args.command == "purge":
                cmd_purge(args)

        cancel_boot_commands = {"init", "remove", "purge"}
        if args.command == "autostart" and args.autostart_action == "disable":
            cancel_boot_commands.add("autostart")

        go_command = (args.command in {"start", "stop", "restart", "init", "remove", "purge", "autostart"}
                      and os.path.exists(BACKEND_PATH) and get_implementation() == "go")
        if args.command in cancel_boot_commands and not go_command and not (args.command == "init" and args.implementation == "go"):
            cancel_awg_boot_before_lock()

        needs_lock = (
            args.command in mutating_commands
            and not (args.command == "autostart" and args.autostart_action == "status")
            and not (go_command and args.command in {"start", "stop", "restart", "remove", "purge"})
        )
        if args.command == "init" and args.implementation == "go":
            needs_lock = False
        if needs_lock:
            with runtime_lock():
                dispatch()
        else:
            dispatch()
        flush_advice()
    except Exception as e:
        log.error(str(e))
        flush_advice()
        sys.exit(1)

if __name__ == "__main__":
    main()
