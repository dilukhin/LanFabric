#!/usr/bin/env python3
"""
vsrv-admin.py - серверный инструмент управления VPN на базе WireGuard/AmneziaWG.
Управление пирами, маршрутизацией, доступом в интернет и состоянием сервера.
"""
__version__ = "0.0.9"

import sys
import os
import subprocess
import sqlite3
import argparse
import logging
import shlex
import ipaddress
from pathlib import Path

# Константы
DB_PATH = "/opt/vpn-admin/vpn.db"
WG_IF = "wg0"
SERVER_IP = "10.8.0.1"
VPN_NET = "10.8.0.0/24"
CONF_DIR = "/opt/vpn-admin/configs"
WG_BASE_PORT = 51820
BACKEND_PATH = "/opt/vpn-admin/backend"
REMOTE_DIR = "/opt/vpn-admin"
SUDOERS_PATH = "/etc/sudoers.d/vpn-admin"

# Логирование
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SRV] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
for handler in logging.getLogger().handlers:
    handler.flush = sys.stdout.flush
log = logging.getLogger("vsrv")

def print_intro():
    """Выводит краткую информацию о серверном инструменте."""
    print(f"LanFabric SRV v{__version__} — сервер управления VPN")

def get_backend():
    path = "/opt/vpn-admin/backend"
    if not os.path.exists(path):
        raise RuntimeError("Backend не определён. Выполните init")
    return open(path).read().strip()

def get_wg_cmd(allow_missing=False):
    try:
        backend = get_backend()
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

def ensure_iptables_rule(rule):
    """Добавляет правило iptables, если оно ещё не существует."""
    check_rule = rule.replace(" -A ", " -C ", 1)
    add_rule = rule
    res = subprocess.run(check_rule, shell=True, capture_output=True, text=True)
    if res.returncode != 0:
        run_cmd(add_rule)

def delete_iptables_rule(rule):
    """Удаляет правило iptables, если оно существует."""
    delete_rule = rule.replace(" -A ", " -D ", 1)
    run_cmd(f"{delete_rule} 2>/dev/null || true", check=False)

def cleanup_firewall_rules():
    """Удаляет базовые и пользовательские правила LanFabric."""
    delete_iptables_rule(f"iptables -A FORWARD -i {WG_IF} -o {WG_IF} -j ACCEPT")
    delete_iptables_rule(f"iptables -A FORWARD -i {WG_IF} -j DROP")
    delete_iptables_rule(f"iptables -t nat -A POSTROUTING -s {VPN_NET} -j MASQUERADE")

    if os.path.exists(DB_PATH):
        try:
            conn = init_db()
            rows = conn.execute("SELECT ip FROM users WHERE ip IS NOT NULL").fetchall()
            for row in rows:
                ip = row[0]
                delete_iptables_rule(f"iptables -A FORWARD -s {ip} -j ACCEPT")
                delete_iptables_rule(f"iptables -t nat -A POSTROUTING -s {ip} -o eth0 -j MASQUERADE")
        except Exception as e:
            log.warning(f"Не удалось очистить правила клиентов из БД: {e}")

def ensure_base_firewall_rules():
    """Восстанавливает базовые правила LanFabric."""
    ensure_iptables_rule(f"iptables -A FORWARD -i {WG_IF} -o {WG_IF} -j ACCEPT")
    ensure_iptables_rule(f"iptables -A FORWARD -i {WG_IF} -j DROP")

def cmd_stop():
    """Останавливает VPN runtime без удаления пакетов и данных."""
    backend = require_backend()
    log.info(f"Остановка VPN runtime. Backend: {backend}")

    if backend == "wg":
        run_cmd(f"systemctl stop wg-quick@{WG_IF} 2>/dev/null || true", check=False)
    else:
        run_cmd(f"ip link del {WG_IF} 2>/dev/null || true", check=False)

    cleanup_firewall_rules()
    run_cmd("netfilter-persistent save 2>/dev/null || true", check=False)
    log.info("VPN runtime остановлен")
    log.info("Рекомендация: для повторного запуска выполните start, для проверки состояния — status или health")

def cmd_start():
    """Запускает VPN runtime по сохранённому backend без полного init."""
    backend = require_backend()
    wg_bin = get_wg_cmd()
    log.info(f"Запуск VPN runtime. Backend: {backend}")

    if backend == "wg":
        run_cmd(f"systemctl enable wg-quick@{WG_IF}")
        run_cmd(f"systemctl restart wg-quick@{WG_IF}")
    else:
        setconf_path = f"/etc/wireguard/{WG_IF}.setconf"
        if not os.path.exists(setconf_path):
            raise RuntimeError(f"Файл конфигурации backend отсутствует: {setconf_path}. Выполните init")

        run_cmd("command -v awg")
        run_cmd("modprobe amneziawg")

        iface_exists = subprocess.run(
            f"ip link show {WG_IF}",
            shell=True,
            capture_output=True,
            text=True
        ).returncode == 0
        if iface_exists:
            backend_ok = subprocess.run(
                f"{wg_bin} show {WG_IF}",
                shell=True,
                capture_output=True,
                text=True
            ).returncode == 0
            if not backend_ok:
                log.warning(f"Интерфейс {WG_IF} существует, но backend {backend} не может его прочитать. Пересоздание интерфейса")
                run_cmd(f"ip link del {WG_IF} 2>/dev/null || true", check=False)
                iface_exists = False

        if not iface_exists:
            run_cmd(f"ip link add {WG_IF} type amneziawg")
            run_cmd(f"{wg_bin} setconf {WG_IF} {setconf_path}")
            run_cmd(f"ip addr add {SERVER_IP}/24 dev {WG_IF}")

        run_cmd(f"ip link set up dev {WG_IF}")
        ensure_base_firewall_rules()

    run_cmd(f"ip link show {WG_IF}")
    run_cmd(f"{wg_bin} show {WG_IF}")
    cmd_sync()
    log.info("VPN runtime запущен")
    log.info("Рекомендация: выполните status или health. Для подключения клиента скачайте конфиг командой config <имя>")

def cmd_restart():
    """Перезапускает VPN runtime без полного init."""
    log.info("Перезапуск VPN runtime")
    cmd_stop()
    cmd_start()

def cleanup_runtime():
    """Останавливает VPN и удаляет runtime-состояние без удаления данных."""
    log.info("Остановка WireGuard/AmneziaWG и очистка runtime-состояния")

    # systemd WireGuard
    run_cmd(f"systemctl disable --now wg-quick@{WG_IF} 2>/dev/null || true", check=False)

    # Интерфейс
    run_cmd(f"ip link del {WG_IF} 2>/dev/null || true", check=False)

    # Правила LanFabric
    cleanup_firewall_rules()
    run_cmd("netfilter-persistent save 2>/dev/null || true", check=False)

    # Модули
    run_cmd("modprobe -r amneziawg 2>/dev/null || true", check=False)
    run_cmd("modprobe -r wireguard 2>/dev/null || true", check=False)


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

    cleanup_runtime()
    remove_packages(purge=False)

    log.info("Remove завершён. Данные /opt/vpn-admin и /etc/wireguard сохранены.")
    log.info("Рекомендация: для повторного развёртывания выполните init. Для полного удаления используйте purge PURGE")


def cmd_purge(args):
    """Полное удаление LanFabric с сервера."""
    if args.confirm != "PURGE":
        raise RuntimeError("Для подтверждения полного удаления укажите: PURGE")

    log.info("Начало purge: полное удаление LanFabric с сервера")

    cleanup_runtime()
    remove_packages(purge=True)
    cleanup_amnezia_repo()

    log.info("Удаление конфигураций и данных LanFabric")
    run_cmd("rm -rf /etc/wireguard 2>/dev/null || true", check=False)
    run_cmd(f"rm -f {SUDOERS_PATH} 2>/dev/null || true", check=False)
    run_cmd("rm -f /etc/sysctl.d/99-vpn-forward.conf 2>/dev/null || true", check=False)

    log.info("Удаление каталога LanFabric. Серверный модуль будет удалён вместе с каталогом.")
    run_cmd(f"rm -rf {REMOTE_DIR} 2>/dev/null || true", check=False)
    print("Purge завершён. LanFabric полностью удалён с сервера.")
    print("Рекомендация: для новой установки заново выполните init с клиента")

def init_db():
    """Создаёт или подключается к SQLite базе."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
    Path(CONF_DIR).mkdir(parents=True, exist_ok=True)

def cmd_init(args):
    """Инициализация сервера, установка пакетов, настройка интерфейса."""
    log.info("Начало инициализации сервера")
    ensure_dirs()

    # --- Очистка предыдущего состояния ---
    log.info("Очистка предыдущего состояния VPN (если есть)")

    run_cmd("systemctl disable --now wg-quick@wg0 2>/dev/null || true", check=False)
    run_cmd("ip link del wg0 2>/dev/null || true", check=False)

    run_cmd("iptables -D FORWARD -i wg0 -o wg0 -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("iptables -D FORWARD -i wg0 -j DROP 2>/dev/null || true", check=False)
    run_cmd("iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -j MASQUERADE 2>/dev/null || true", check=False)

    run_cmd("rm -f /etc/wireguard/wg0.conf", check=False)
    run_cmd("rm -f /etc/wireguard/wg0.private /etc/wireguard/wg0.public", check=False)

    run_cmd("modprobe -r wireguard 2>/dev/null || true", check=False)
    run_cmd("modprobe -r amneziawg 2>/dev/null || true", check=False)

    run_cmd("rm -f /opt/vpn-admin/backend", check=False)

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
            run_cmd("apt-get install -y amneziawg")
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
    with open(priv_path, "w") as f:
        f.write(priv)

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
    Path(f"/etc/wireguard/{WG_IF}.conf").write_text(conf)

    setconf = f"""[Interface]
PrivateKey = {priv}
ListenPort = {WG_BASE_PORT}
"""
    Path(f"/etc/wireguard/{WG_IF}.setconf").write_text(setconf)

    # --- Поднятие интерфейса ---
    log.info("Запуск интерфейса")

    if backend == "wg":
        run_cmd("systemctl enable wg-quick@wg0")
        run_cmd("systemctl restart wg-quick@wg0")
    else:
        try:
            run_cmd("ip link add wg0 type amneziawg")
        except RuntimeError as e:
            raise RuntimeError(
                f"Не удалось создать интерфейс AmneziaWG wg0: {e}. "
                "Модуль amneziawg загружен, но тип интерфейса amneziawg недоступен"
            )
        run_cmd(f"{wg_bin} setconf wg0 /etc/wireguard/{WG_IF}.setconf")
        run_cmd(f"ip addr add {SERVER_IP}/24 dev wg0")
        run_cmd("ip link set up dev wg0")
        ensure_base_firewall_rules()        

    # --- Проверка ---
    run_cmd("ip link show wg0")
    run_cmd(f"{wg_bin} show {WG_IF}")

    # --- Сохранение правил ---
    run_cmd("netfilter-persistent save")

    log.info("Инициализация завершена. Интерфейс поднят, правила сохранены.")
    log.info("Рекомендация: выполните add <имя> для создания пользователя или health для проверки системы")

def cmd_status():
    """Быстрая проверка состояния."""
    backend = get_backend()
    wg_bin = get_wg_cmd()

    log.info(f"Backend: {backend}")

    state = "UNKNOWN"

    if backend == "wg":
        svc = run_cmd("systemctl is-active wg-quick@wg0", check=False).strip()
        log.info(f"Сервис wg-quick@wg0: {svc or 'unknown'}")
        state = "RUNNING" if svc == "active" else "STOPPED"
    elif backend == "awg":
        log.info("Сервис wg-quick@wg0: не используется для backend awg")
        iface_exists = subprocess.run(
            f"ip link show {WG_IF}",
            shell=True,
            capture_output=True,
            text=True
        ).returncode == 0
        backend_ok = subprocess.run(
            f"{wg_bin} show {WG_IF}",
            shell=True,
            capture_output=True,
            text=True
        ).returncode == 0

        if not iface_exists:
            state = "STOPPED"
        elif backend_ok:
            state = "RUNNING"
        else:
            state = "BROKEN"
    else:
        log.warning(f"Неизвестный backend: {backend}")
        state = "BROKEN"

    iface = run_cmd("ip -brief link show wg0 || echo 'не найден'", check=False)
    log.info("Состояние интерфейса: " + iface)

    wg_state = run_cmd(f"{wg_bin} show {WG_IF}", check=False)
    if wg_state:
        log.info(f"Состояние backend {backend}: OK")
    else:
        log.warning(f"Backend {backend} не вернул состояние интерфейса {WG_IF}")

    log.info(f"Состояние VPN: {state}")
    if state == "RUNNING":
        log.info("Рекомендация: можно скачивать клиентские конфиги командой config <имя> или выполнить health для полной проверки")
    elif state == "STOPPED":
        log.info("Рекомендация: выполните start для запуска VPN runtime")
    elif state == "BROKEN":
        log.warning("Рекомендация: выполните health для подробной диагностики, затем restart или init при необходимости")

    conn = init_db()
    total = conn.execute("SELECT count(*) FROM users").fetchone()[0]
    active = conn.execute("SELECT count(*) FROM users WHERE blocked=0").fetchone()[0]
    log.info(f"Учётные записи: всего {total}, активных {active}")

def cmd_health():
    """Глубокая диагностика."""
    log.info("=== Глубокая диагностика ===")
    errors = []
    advices = []

    # Проверка backend
    backend = None
    try:
        backend = get_backend()
        log.info(f"Backend: {backend}")
        if backend not in ("wg", "awg"):
            errors.append(f"Неизвестный backend: {backend}")
            advices.append("Исправьте /opt/vpn-admin/backend или выполните init заново с явным выбором backend")
    except Exception as e:
        errors.append(f"Backend не определён: {e}")
        advices.append("Выполните init, чтобы явно выбрать backend и создать /opt/vpn-admin/backend")

    # Проверка наличия WireGuard / AmneziaWG
    wg_bin = get_wg_cmd(allow_missing=True)
    if not wg_bin:
        errors.append("Backend-команда не определена: wg/awg недоступен")
        advices.append("Проверьте backend-файл. Backend не должен угадываться по бинарникам")
    else:
        bin_path = run_cmd(f"command -v {wg_bin}", check=False)
        if bin_path:
            log.info(f"Обнаружен бинарник backend: {wg_bin} ({bin_path})")
        else:
            errors.append(f"Бинарник backend не найден: {wg_bin}")
            if backend == "awg":
                advices.append("AmneziaWG не установлен или удалён. Если это штатное удаление — выполните init; если нужен WireGuard — выполните init --no-amnezia")
            elif backend == "wg":
                advices.append("WireGuard не установлен или удалён. Выполните init --no-amnezia")

    # Проверка интерфейса wg0
    iface_ok = True
    try:
        run_cmd(f"ip link show {WG_IF}")
    except RuntimeError:
        iface_ok = False
        errors.append(f"Интерфейс {WG_IF} не поднят или отсутствует")
        if backend == "awg":
            advices.append("Похоже, runtime AmneziaWG потерян после остановки VPS. Выполните start, полный init не требуется")
        elif backend == "wg":
            advices.append("Выполните start или проверьте systemd-сервис wg-quick@wg0")

    # Проверка, что backend может читать состояние интерфейса
    backend_show_ok = True
    if wg_bin:
        try:
            run_cmd(f"{wg_bin} show {WG_IF}")
            log.info(f"Backend {backend or '?'} читает состояние интерфейса {WG_IF}")
        except RuntimeError:
            backend_show_ok = False
            errors.append(f"Backend {backend or '?'} не может прочитать состояние интерфейса {WG_IF}")
            if iface_ok:
                advices.append("Интерфейс существует, но не соответствует выбранному backend. Выполните restart; если ошибка повторится — проверьте тип интерфейса")

    # Проверка порта
    port_open = run_cmd(f"ss -ulnH | grep :{WG_BASE_PORT}", check=False)
    if not port_open:
        errors.append(f"Порт {WG_BASE_PORT}/UDP не слушается")
        if backend == "awg" and (not iface_ok or not backend_show_ok):
            advices.append("После start порт должен появиться автоматически. Если нет — проверьте awg show wg0")
        elif backend == "wg":
            advices.append("Проверьте wg-quick@wg0 через status или выполните restart")

    # Проверка iptables: базовое разрешение VPN-клиентам общаться между собой
    accept_check = subprocess.run(
        f"iptables -C FORWARD -i {WG_IF} -o {WG_IF} -j ACCEPT",
        shell=True,
        capture_output=True,
        text=True
    )
    if accept_check.returncode != 0:
        errors.append("Базовое правило ACCEPT для FORWARD между VPN-клиентами отсутствует")
        advices.append("Выполните start или restart для восстановления базовых iptables-правил")

    drop_check = subprocess.run(
        f"iptables -C FORWARD -i {WG_IF} -j DROP",
        shell=True,
        capture_output=True,
        text=True
    )
    if drop_check.returncode != 0:
        errors.append("Базовое правило DROP для FORWARD отсутствует")
        advices.append("Выполните start или restart для восстановления изоляции клиентов от интернета по умолчанию")

    # Проверка IP forward
    try:
        ipf = run_cmd("sysctl -n net.ipv4.ip_forward", check=False)
        if ipf.strip() != "1":
            errors.append("IPv4 forward выключен (net.ipv4.ip_forward != 1)")
            advices.append("Включите net.ipv4.ip_forward или выполните init, если sysctl-конфигурация потеряна")
    except Exception:
        errors.append("Не удалось проверить net.ipv4.ip_forward")
        advices.append("Проверьте доступность sysctl на сервере")

    # Проверка systemd сервиса
    if backend == "wg":
        svc = run_cmd("systemctl is-active wg-quick@wg0", check=False)
        if svc.strip() != "active":
            errors.append(f"Сервис wg-quick@wg0 не активен (сейчас: {svc.strip() or 'unknown'})")
            advices.append("Выполните start или restart. Для WireGuard используется wg-quick@wg0")
    elif backend == "awg":
        log.info("Сервис wg-quick@wg0: не требуется для backend awg")

    # Проверка базы данных
    try:
        conn = init_db()
        total = conn.execute("SELECT count(*) FROM users").fetchone()[0]
        log.info(f"База данных: пользователей {total}")
    except Exception as e:
        errors.append(f"Ошибка базы данных: {e}")
        advices.append("Проверьте /opt/vpn-admin/vpn.db. Если БД потеряна, потребуется восстановление из резервной копии или новый init")

    # Итог
    if errors:
        log.warning("Обнаружены проблемы:")
        for err in errors:
            log.warning(f"- {err}")
        if advices:
            log.info("Рекомендации:")
            for advice in dict.fromkeys(advices):
                log.info(f"- {advice}")
    else:
        log.info("Система работает штатно, нарушений не выявлено")

def cmd_sync():
    """Пересборка состояния из базы данных."""
    log.info("Синхронизация состояния интерфейса и правил")
    wg_bin = get_wg_cmd()
    # Удаление всех пиров из интерфейса
    current_peers = run_cmd(f"{wg_bin} show {WG_IF} peers")
    for peer in current_peers.splitlines():
        pub = peer.split()[0] if peer else None
        if pub:
            run_cmd(f"{wg_bin} set {WG_IF} peer {pub} remove")

    conn = init_db()
    # Очистка динамических правил клиентов (базовые оставляем)
    rows_all = conn.execute("SELECT ip FROM users WHERE ip IS NOT NULL").fetchall()
    for row in rows_all:
        ip = row[0]
        delete_iptables_rule(f"iptables -A FORWARD -s {ip} -j ACCEPT")
        delete_iptables_rule(f"iptables -t nat -A POSTROUTING -s {ip} -o eth0 -j MASQUERADE")
    
    # Восстановление пиров и правил
    rows = conn.execute("SELECT pubkey, ip, internet, blocked FROM users WHERE blocked=0").fetchall()
    for row in rows:
        pub, ip, internet, _ = row
        allowed = f"{ip}/32"
        run_cmd(f"{wg_bin} set {WG_IF} peer {pub} allowed-ips {allowed} persistent-keepalive 25")
        if internet:
            ensure_iptables_rule(f"iptables -A FORWARD -s {ip} -j ACCEPT")
            ensure_iptables_rule(f"iptables -t nat -A POSTROUTING -s {ip} -o eth0 -j MASQUERADE")
    run_cmd("netfilter-persistent save")
    log.info("Синхронизация завершена")
    log.info("Рекомендация: выполните health для проверки правил или config <имя> для скачивания клиентского конфига")

def build_client_config(row):
    """Формирует клиентский конфиг из данных БД."""
    server_pub = open(f"/etc/wireguard/{WG_IF}.public").read().strip()
    server_ip = run_cmd("hostname -I | awk '{print $1}'").strip()
    allowed_ips = "0.0.0.0/0" if row["internet"] else VPN_NET

    return f"""[Interface]
PrivateKey = {row["privkey"]}
Address = {row["ip"]}/32
DNS = 8.8.8.8

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
    conn = init_db()
    row = conn.execute("SELECT * FROM users WHERE name=?", (args.name,)).fetchone()
    if not row:
        raise RuntimeError(f"Учётная запись '{args.name}' не найдена")

    sys.stdout.write(build_client_config(row))

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
    
    if not blocked_val:
        run_cmd(f"{wg_bin} set {WG_IF} peer {pub} allowed-ips {ip}/32 persistent-keepalive 25")
        if internet_val:
            ensure_iptables_rule(f"iptables -A FORWARD -s {ip} -j ACCEPT")
            ensure_iptables_rule(f"iptables -t nat -A POSTROUTING -s {ip} -o eth0 -j MASQUERADE")
            run_cmd("netfilter-persistent save")
            
    row = conn.execute("SELECT * FROM users WHERE name=?", (args.name,)).fetchone()
    cfg_path = write_client_config(row)
    
    log.info(f"Учётная запись '{args.name}' создана. IP: {ip}, Админ: {bool(admin_val)}, Интернет: {bool(internet_val)}")
    log.info(f"Конфиг сохранён: {cfg_path}")
    if internet_val:
        log.info("Рекомендация: скачайте конфиг командой config и импортируйте его в клиент. Интернет-трафик будет направлен через VPN")
    else:
        log.info("Рекомендация: скачайте конфиг командой config. По умолчанию будет доступна только VPN-сеть")

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
    log.info("Рекомендация: выполните sync для применения сетевых правил. Если менялся интернет-доступ, заново скачайте config <имя>")

def cmd_block(args):
    """Блокировка учётной записи."""
    conn = init_db()
    user = conn.execute("SELECT pubkey, ip, internet FROM users WHERE name=?", (args.name,)).fetchone()
    if not user:
        raise RuntimeError(f"Учётная запись '{args.name}' не найдена")
        
    pub, ip, internet = user
    wg_bin = get_wg_cmd()
    run_cmd(f"{wg_bin} set {WG_IF} peer {pub} remove")
    if internet:
        run_cmd(f"iptables -D FORWARD -s {ip} -j ACCEPT || true")
        run_cmd(f"iptables -t nat -D POSTROUTING -s {ip} -o eth0 -j MASQUERADE || true")
        run_cmd("netfilter-persistent save")
        
    conn.execute("UPDATE users SET blocked=1 WHERE name=?", (args.name,))
    conn.commit()
    log.info(f"Учётная запись '{args.name}' заблокирована. Соединение разорвано.")
    log.info("Рекомендация: выполните list для проверки статуса или sync для полной пересборки runtime-правил")

def cmd_delete(args):
    """Удаление учётной записи с подтверждением."""
    if args.confirm != args.name:
        raise RuntimeError("Подтверждение удаления не совпадает с именем учётной записи")
        
    conn = init_db()
    user = conn.execute("SELECT pubkey, ip FROM users WHERE name=?", (args.name,)).fetchone()
    if not user:
        raise RuntimeError(f"Учётная запись '{args.name}' не найдена")
        
    pub, ip = user
    wg_bin = get_wg_cmd()
    run_cmd(f"{wg_bin} set {WG_IF} peer {pub} remove || true")
    run_cmd(f"iptables -D FORWARD -s {ip} -j ACCEPT || true")
    run_cmd(f"iptables -t nat -D POSTROUTING -s {ip} -o eth0 -j MASQUERADE || true")
    run_cmd("netfilter-persistent save")
    
    conn.execute("DELETE FROM users WHERE name=?", (args.name,))
    conn.commit()
    
    cfg = Path(f"{CONF_DIR}/{args.name}.conf")
    if cfg.exists():
        cfg.unlink()
        
    log.info(f"Учётная запись '{args.name}' полностью удалена.")
    log.info("Рекомендация: выполните list для проверки списка пользователей")

def cmd_list():
    """Список учётных записей."""
    conn = init_db()
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
    
    if len(sys.argv) == 1:
        print_intro()
        print("Краткая справка: vsrv-admin.py {init|backend|start|stop|restart|status|health|sync|add|edit|block|delete|list|config|remove|purge|help} [--version]")
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

    subparsers.add_parser("list", help="Вывод списка учётных записей")
    subparsers.add_parser("help", help="Подробная справка")
    parser.add_argument("--version", action="version", version=f"vsrv-admin {__version__}")
    
    args = parser.parse_args()
    if args.command == "help" or not args.command:
        parser.print_help(sys.stderr)
        sys.exit(0)
        
    try:
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
    except Exception as e:
        log.error(str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()