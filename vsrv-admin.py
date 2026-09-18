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
BACKEND_PATH = "/opt/vpn-admin/backend"
REMOTE_DIR = "/opt/vpn-admin"
SUDOERS_PATH = "/etc/sudoers.d/vpn-admin"
SUDOERS_LANFABRIC_GLOB = "/etc/sudoers.d/lanfabric-*"
AWG_PARAMS_PATH = "/opt/vpn-admin/awg_params"
AWG_PARAM_KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4")
LOCK_DIR = "/run/lanfabric"
LOCK_PATH = f"{LOCK_DIR}/runtime.lock"
LOCK_TIMEOUT_SECONDS = 20
FW_GUARD_CHAIN = "LANFABRIC-GUARD"
FW_FORWARD_CHAIN = "LANFABRIC-FWD"
FW_NAT_CHAIN = "LANFABRIC-NAT"
AWG_AUTOSTART_UNIT = "lanfabric-awg.service"
AWG_AUTOSTART_PATH = f"/etc/systemd/system/{AWG_AUTOSTART_UNIT}"
AWG_AUTOSTART_TIMEOUT_SECONDS = 60

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
        return "awg" if backend == "awg" else "wg"
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

def run_cmd(cmd, check=True):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Ошибка выполнения '{cmd}': {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout.strip()

@contextmanager
def runtime_lock(timeout=LOCK_TIMEOUT_SECONDS):
    """Сериализует все изменения желаемого и фактического состояния LanFabric."""
    if fcntl is None:
        raise RuntimeError("Межпроцессная блокировка LanFabric поддерживается только на POSIX-сервере")
    Path(LOCK_DIR).mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
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

def generate_awg_params():
    """Генерирует параметры маскировки AmneziaWG для сервера и клиентов."""
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

def validate_awg_params(params):
    """Проверяет параметры AmneziaWG перед применением."""
    missing = [key for key in AWG_PARAM_KEYS if key not in params]
    if missing:
        raise RuntimeError("В параметрах AmneziaWG отсутствуют поля: " + ", ".join(missing))

    try:
        values = {key: int(params[key]) for key in AWG_PARAM_KEYS}
    except (TypeError, ValueError) as e:
        raise RuntimeError(f"Параметры AmneziaWG должны быть целыми числами: {e}")

    if not 1 <= values["Jc"] <= 128:
        raise RuntimeError("Некорректный параметр AmneziaWG Jc: ожидается 1..128")
    if not 0 <= values["Jmin"] < values["Jmax"] <= 1280:
        raise RuntimeError("Некорректные параметры AmneziaWG Jmin/Jmax: ожидается 0 <= Jmin < Jmax <= 1280")
    if not 0 <= values["S1"] <= 1132:
        raise RuntimeError("Некорректный параметр AmneziaWG S1: ожидается 0..1132")
    if not 0 <= values["S2"] <= 1188:
        raise RuntimeError("Некорректный параметр AmneziaWG S2: ожидается 0..1188")
    if values["S1"] + 56 == values["S2"]:
        raise RuntimeError("Некорректные параметры AmneziaWG: S1 + 56 не должно совпадать с S2")

    headers = [values["H1"], values["H2"], values["H3"], values["H4"]]
    if len(set(headers)) != 4:
        raise RuntimeError("Параметры AmneziaWG H1-H4 должны быть уникальными")
    if any(value < 5 or value > 2147483647 for value in headers):
        raise RuntimeError("Параметры AmneziaWG H1-H4 должны быть в диапазоне 5..2147483647")

    return values

def read_awg_params_file():
    """Читает параметры AmneziaWG из файла."""
    params = {}
    with open(AWG_PARAMS_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise RuntimeError(f"Некорректная строка параметров AmneziaWG: {line}")
            key, value = line.split("=", 1)
            params[key.strip()] = value.strip()
    return validate_awg_params(params)

def write_awg_params_file(params):
    """Сохраняет параметры AmneziaWG."""
    params = validate_awg_params(params)
    Path(REMOTE_DIR).mkdir(parents=True, exist_ok=True)
    text = "\n".join(f"{key} = {params[key]}" for key in AWG_PARAM_KEYS) + "\n"
    Path(AWG_PARAMS_PATH).write_text(text, encoding="utf-8")
    os.chmod(AWG_PARAMS_PATH, 0o600)

def get_or_create_awg_params():
    """Возвращает сохранённые параметры AmneziaWG или создаёт новые."""
    if os.path.exists(AWG_PARAMS_PATH):
        return read_awg_params_file()

    params = generate_awg_params()
    write_awg_params_file(params)
    log.info(f"Параметры AmneziaWG созданы: {AWG_PARAMS_PATH}")
    return params

def format_awg_params(params):
    """Формирует блок параметров AmneziaWG для .conf."""
    params = validate_awg_params(params)
    return "\n".join(f"{key} = {params[key]}" for key in AWG_PARAM_KEYS)

def build_setconf(priv, backend, awg_params=None):
    """Формирует конфиг для wg/awg setconf без неявного создания состояния."""
    conf = f"""[Interface]
PrivateKey = {priv}
ListenPort = {WG_BASE_PORT}
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

def write_setconf(priv, backend, awg_params=None):
    """Сохраняет производный конфиг для wg/awg setconf."""
    setconf_path = Path(f"/etc/wireguard/{WG_IF}.setconf")
    write_private_file(setconf_path, build_setconf(priv, backend, awg_params=awg_params))
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
    wg_bin = "awg" if backend == "awg" else "wg"
    try:
        result = subprocess.run([wg_bin, "pubkey"], input=priv + "\n", capture_output=True, text=True)
    except OSError as e:
        raise RuntimeError(f"Не удалось запустить {wg_bin} для проверки ключа: {e}")
    if result.returncode != 0:
        raise RuntimeError(f"Не удалось проверить пару ключей сервера через {wg_bin}: {result.stderr.strip() or result.stdout.strip()}")
    if result.stdout.strip() != pub:
        raise RuntimeError("Сохранённые приватный и публичный ключи сервера не соответствуют друг другу")
    return priv, pub

def validate_user_rows(rows):
    """Проверяет записи пользователей перед восстановлением runtime."""
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
    if sys.version_info < (3, 12):
        raise RuntimeError("Для восстановления LanFabric требуется Python 3.12+")
    backend = require_backend()
    if expected_backend is not None and backend != expected_backend:
        raise RuntimeError(f"Ожидался backend {expected_backend}, сохранён backend {backend}")
    wg_bin = "awg" if backend == "awg" else "wg"
    if not run_cmd(f"command -v {wg_bin}", check=False):
        raise RuntimeError(f"Бинарник backend не найден: {wg_bin}")
    priv, pub = read_server_key_material(backend)
    awg_params = read_awg_params_file() if backend == "awg" else None
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
    validate_user_rows(rows)
    return {"backend": backend, "wg_bin": wg_bin, "server_private_key": priv, "server_public_key": pub, "awg_params": awg_params, "users": rows}

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

def rebuild_policy_chains(snapshot):
    """Пересобирает принадлежащие LanFabric цепочки при закрытом guard."""
    _ensure_chain("filter", FW_FORWARD_CHAIN)
    _ensure_chain("nat", FW_NAT_CHAIN)
    run_cmd(f"iptables -F {FW_FORWARD_CHAIN}")
    run_cmd(f"iptables -t nat -F {FW_NAT_CHAIN}")

    run_cmd(f"iptables -A {FW_FORWARD_CHAIN} -o {WG_IF} -j ACCEPT")
    for row in _active_users(snapshot):
        if int(row["internet"]):
            run_cmd(f"iptables -A {FW_FORWARD_CHAIN} -s {row['ip']}/32 -j ACCEPT")
            run_cmd(f"iptables -t nat -A {FW_NAT_CHAIN} -s {row['ip']}/32 -o eth0 -j MASQUERADE")
    run_cmd(f"iptables -A {FW_FORWARD_CHAIN} -j DROP")

    _delete_rule_all("nat", "POSTROUTING", f"-s {VPN_NET} -j {FW_NAT_CHAIN}")
    run_cmd(f"iptables -t nat -I POSTROUTING 1 -s {VPN_NET} -j {FW_NAT_CHAIN}")
    _remove_legacy_firewall_rules()

def open_firewall_guard():
    """Переводит guard из DROP в проверенную рабочую policy без открытого промежутка."""
    _delete_rule_all("filter", FW_GUARD_CHAIN, f"-j {FW_FORWARD_CHAIN}")
    run_cmd(f"iptables -A {FW_GUARD_CHAIN} -j {FW_FORWARD_CHAIN}")
    _delete_rule_all("filter", FW_GUARD_CHAIN, "-j DROP")

def cleanup_owned_firewall():
    """Удаляет только hook/цепочки новой схемы LanFabric и узнаваемые legacy-правила."""
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

    _remove_legacy_firewall_rules()

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
    return {"backend": backend, "wg_bin": "awg" if backend == "awg" else "wg", "server_public_key": pub}

def interface_exists():
    return subprocess.run(
        f"ip link show {WG_IF}", shell=True, capture_output=True, text=True
    ).returncode == 0

def awg_interface_ownership(identity):
    """Возвращает absent/owned/unknown для wg0."""
    if not interface_exists():
        return "absent"
    detail = run_cmd(f"ip -d link show {WG_IF}", check=False)
    if "amneziawg" not in detail.lower():
        return "unknown"
    actual_pub = run_cmd(f"awg show {WG_IF} public-key", check=False).strip()
    return "owned" if actual_pub == identity["server_public_key"] else "unknown"

def _apply_awg_peers(snapshot):
    current = run_cmd(f"awg show {WG_IF} peers", check=False)
    for peer in current.splitlines():
        if peer:
            run_cmd(f"awg set {WG_IF} peer {peer} remove")
    for row in _active_users(snapshot):
        run_cmd(
            f"awg set {WG_IF} peer {row['pubkey']} "
            f"allowed-ips {row['ip']}/32 persistent-keepalive 25"
        )

def firewall_readiness_errors(snapshot, guard_open=True):
    """Проверяет точную принадлежащую LanFabric firewall policy."""
    errors = []
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
            expected_nat.append(f"-A {FW_NAT_CHAIN} -s {row['ip']}/32 -o eth0 -j MASQUERADE")
    if _chain_rule_lines("nat", FW_NAT_CHAIN) != expected_nat:
        errors.append("Цепочка NAT LanFabric не совпадает с политиками БД")

    nat_rules = _chain_rule_lines("nat", "POSTROUTING")
    nat_hook = f"-A POSTROUTING -s {VPN_NET} -j {FW_NAT_CHAIN}"
    if nat_hook not in nat_rules:
        errors.append("Hook NAT LanFabric отсутствует")
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
    ownership = awg_interface_ownership(snapshot)
    if ownership == "unknown":
        raise RuntimeError(f"Интерфейс {WG_IF} существует, но его принадлежность LanFabric не подтверждена")

    close_firewall_guard(persist=True)
    created = ownership == "absent"
    try:
        run_cmd("modprobe amneziawg")
        setconf_path = str(write_setconf(
            snapshot["server_private_key"], "awg", awg_params=snapshot["awg_params"]
        ))
        if created:
            run_cmd(f"ip link add {WG_IF} type amneziawg")
        else:
            run_cmd(f"ip link set down dev {WG_IF}")
        run_cmd(f"awg setconf {WG_IF} {setconf_path}")
        run_cmd(f"ip -4 addr flush dev {WG_IF}")
        run_cmd(f"ip addr add {SERVER_IP}/24 dev {WG_IF}")
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

def awg_autostart_unit_text():
    """Возвращает узкий boot-only systemd contract для AWG."""
    return f"""[Unit]
Description=LanFabric AWG boot restore
After=systemd-sysctl.service netfilter-persistent.service
Wants=netfilter-persistent.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -u {REMOTE_DIR}/vsrv-admin.py _boot-awg
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
    for path_text in ("/", "/opt", REMOTE_DIR, "/etc", WG_DIR):
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
        AWG_PARAMS_PATH, f"{WG_DIR}/{WG_IF}.private",
    ):
        path = Path(path_text)
        try:
            st = path.stat()
        except OSError as e:
            errors.append(f"Не удалось проверить защищённый файл {path}: {e}")
            continue
        if st.st_uid != 0:
            errors.append(f"Файл {path} не принадлежит root")
        if st.st_mode & 0o077:
            errors.append(f"Файл {path} доступен группе или остальным")

    python_path = Path(os.path.realpath("/usr/bin/python3"))
    try:
        st = python_path.stat()
        if st.st_uid != 0 or (st.st_mode & 0o022):
            errors.append(f"Интерпретатор {python_path} не имеет доверенных root-only прав на запись")
    except OSError as e:
        errors.append(f"Не удалось проверить /usr/bin/python3: {e}")
    if sys.version_info < (3, 12):
        errors.append("Для root-службы требуется Python 3.12+")
    return errors

def ensure_awg_autostart_unit():
    """Устанавливает и разрешает boot-only unit без запуска/перезапуска VPN."""
    load_state_snapshot(expected_backend="awg")
    ensure_state_permissions()
    errors = state_permission_errors()
    if errors:
        raise RuntimeError("Нельзя включить AWG autostart: " + "; ".join(errors))
    _atomic_write_root_file(AWG_AUTOSTART_PATH, awg_autostart_unit_text(), mode=0o644)
    run_cmd("systemctl daemon-reload")
    run_cmd(f"systemctl enable {AWG_AUTOSTART_UNIT}")
    enabled = run_cmd(f"systemctl is-enabled {AWG_AUTOSTART_UNIT}", check=False).strip()
    if enabled != "enabled":
        raise RuntimeError(f"AWG autostart не включён после установки unit: {enabled or 'unknown'}")

def disable_awg_autostart(remove_unit=False):
    """Отключает будущий boot restore; текущий wg0 отдельно не останавливает."""
    run_cmd(f"systemctl disable --now {AWG_AUTOSTART_UNIT} 2>/dev/null || true", check=False)
    if remove_unit:
        run_cmd(f"rm -f {AWG_AUTOSTART_PATH}", check=False)
        run_cmd("systemctl daemon-reload")
        run_cmd(f"systemctl reset-failed {AWG_AUTOSTART_UNIT} 2>/dev/null || true", check=False)

def awg_autostart_state():
    installed = os.path.isfile(AWG_AUTOSTART_PATH)
    enabled = run_cmd(f"systemctl is-enabled {AWG_AUTOSTART_UNIT}", check=False).strip()
    result = run_cmd(
        f"systemctl show {AWG_AUTOSTART_UNIT} -p Result --value 2>/dev/null",
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
        cleanup_owned_firewall()
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

    server_pub = run_cmd(f"echo '{priv}' | {wg_bin} pubkey").strip()
    with open(pub_path, "w") as f:
        f.write(server_pub)

    # --- Конфигурация ---
    log.info("Создание конфигурации интерфейса")

    conf = f"""[Interface]
PrivateKey = {priv}
Address = {SERVER_IP}/24
ListenPort = {WG_BASE_PORT}
PostUp = iptables -A FORWARD -i {WG_IF} -o {WG_IF} -j ACCEPT; iptables -A FORWARD -i {WG_IF} -j DROP
PostDown = iptables -D FORWARD -i {WG_IF} -o {WG_IF} -j ACCEPT; iptables -D FORWARD -i {WG_IF} -j DROP || true
"""
    write_private_file(f"/etc/wireguard/{WG_IF}.conf", conf)

    awg_params = get_or_create_awg_params() if backend == "awg" else None
    write_setconf(priv, backend, awg_params=awg_params)

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
    run_cmd(f"{wg_bin} show {WG_IF}")

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
    if backend == "awg" and "amneziawg" not in detail.lower():
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
    listen_port = run_cmd(f"{wg_bin} show {WG_IF} listen-port", check=False).strip()
    if listen_port != str(WG_BASE_PORT):
        errors.append(f"ListenPort: ожидался {WG_BASE_PORT}, получено {listen_port or 'нет'}")
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
    if not run_cmd(f"ss -ulnH | grep :{WG_BASE_PORT}", check=False):
        errors.append(f"Порт {WG_BASE_PORT}/UDP не слушается")
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
    server_pub = open(f"/etc/wireguard/{WG_IF}.public").read().strip()
    server_ip = str(endpoint).strip() if endpoint else run_cmd("hostname -I | awk '{print $1}'").strip()
    allowed_ips = "0.0.0.0/0" if row["internet"] else VPN_NET
    backend = require_backend()
    awg_params = ""
    if backend == "awg":
        awg_params = "\n" + format_awg_params(read_awg_params_file())

    return f"""[Interface]
PrivateKey = {row["privkey"]}
Address = {row["ip"]}/32
DNS = 8.8.8.8{awg_params}

[Peer]
PublicKey = {server_pub}
Endpoint = {server_ip}:{WG_BASE_PORT}
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
    wg_bin = get_wg_cmd()
    priv = run_cmd(f"{wg_bin} genkey")
    pub = run_cmd(f"echo '{priv}' | {wg_bin} pubkey")
    
    admin_val = 1 if args.admin else 0
    internet_val = 1 if (args.admin or args.internet) else 0
    blocked_val = 1 if args.block else 0
    
    conn.execute(
        "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (args.name, pub, priv, ip, admin_val, internet_val, blocked_val, args.comment or "")
    )
    conn.commit()
    
    row = conn.execute("SELECT * FROM users WHERE name=?", (args.name,)).fetchone()
    cfg_path = write_client_config(row)

    if get_backend() == "awg":
        _sync_awg_runtime_locked(load_state_snapshot(expected_backend="awg"))
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

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "_cleanup-temp-sudoers":
        print(_run_internal_cleanup_temp_sudoers(sys.argv[2:]))
        return

    if len(sys.argv) > 1 and sys.argv[1] == "_boot-awg":
        try:
            with runtime_lock():
                cmd_boot_awg()
        except Exception as e:
            log.error(str(e))
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

    subparsers.add_parser("init", help="Инициализация сервера и установка пакетов").add_argument("--no-amnezia", action="store_true", help="Использовать стандартный WireGuard вместо AmneziaWG")
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

        if args.command in mutating_commands:
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
