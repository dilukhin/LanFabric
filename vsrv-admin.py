#!/usr/bin/env python3
"""
vsrv-admin.py - серверный инструмент управления VPN на базе WireGuard/AmneziaWG.
Управление пирами, маршрутизацией, доступом в интернет и состоянием сервера.
"""
__version__ = "1.0.12"

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

# Логирование
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SRV] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
for handler in logging.getLogger().handlers:
    handler.flush = sys.stdout.flush
log = logging.getLogger("vsrv")

def get_wg_cmd(allow_missing=False):
    """Определяет используемый бинарный файл wireguard. По умолчанию amneziawg (awg)."""
    if os.path.exists("/usr/bin/awg"):
        return "awg"
    if os.path.exists("/usr/bin/wg"):
        return "wg"
    if allow_missing:
        return None        
    raise RuntimeError(
        "WireGuard не установлен (бинарники wg/awg не найдены). "
        "Выполните init или проверьте установку пакетов."
    )

def run_cmd(cmd, check=True):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Ошибка выполнения '{cmd}': {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout.strip()

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

    # Выбор WG бинарника и пакета с автоматическим откатом
    wg_bin = "wireguard"
    pkg_name = "wireguard"

    repo_added = False
    key_added = False

    if not args.no_amnezia:
        log.info("Попытка установки AmneziaWG через PPA")
        try:
            run_cmd("apt-get update -qq")
            run_cmd("apt-get install -y software-properties-common gnupg2")

            run_cmd("add-apt-repository -y ppa:amnezia/ppa")
            repo_added = True

            run_cmd("apt-get update -qq")
            run_cmd("apt-get install -y amneziawg")

            wg_bin = "awg"
            pkg_name = "amneziawg"
            log.info("AmneziaWG установлен успешно")

        except RuntimeError as e:
            log.error(f"AmneziaWG недоступен ({e})")

            # очистка
            if repo_added:
                run_cmd("rm -f /etc/apt/sources.list.d/amnezia-ubuntu-ppa*.list || true", check=False)
                run_cmd("apt-get update -qq", check=False)

            raise RuntimeError(
                "AmneziaWG недоступен. Для продолжения со стандартным WireGuard "
                "перезапустите с флагом --no-amnezia"
            )

    # Установка пакетов
    log.info("Обновление списка пакетов и установка зависимостей")
    run_cmd("apt-get update -qq")

    if args.no_amnezia:
        log.info("Установка стандартного WireGuard...")
        run_cmd("DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard")

    run_cmd("DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent")
    # Включение IP-форвардинга
    log.info("Включение IPv4 forward")
    current = run_cmd("sysctl -n net.ipv4.ip_forward", check=False)
    if current.strip() != "1":
        log.info("Включение IPv4 forward")
        run_cmd("sysctl -w net.ipv4.ip_forward=1")

    conf_path = "/etc/sysctl.d/99-vpn-forward.conf"
    if not os.path.exists(conf_path):
        with open(conf_path, "w") as f:
            f.write("net.ipv4.ip_forward=1\n")

    # Генерация ключей сервера
    log.info("Генерация ключей сервера")
    priv_path = "/etc/wireguard/wg0.private"
    pub_path = "/etc/wireguard/wg0.public"
    if not os.path.exists(priv_path):
        priv = run_cmd(f"{wg_bin} genkey")
        with open(priv_path, "w") as f:
            f.write(priv)
    server_pub = run_cmd(f"{wg_bin} pubkey < {priv_path}").strip()
    with open(pub_path, "w") as f:
        f.write(server_pub)

    # Создание базового конфига
    log.info("Создание конфигурации интерфейса")
    conf = f"""[Interface]
PrivateKey = {open(priv_path).read().strip()}
Address = {SERVER_IP}/24
ListenPort = {WG_BASE_PORT}
PostUp = iptables -A FORWARD -i {WG_IF} -o {WG_IF} -j ACCEPT; iptables -A FORWARD -i {WG_IF} -j DROP
PostDown = iptables -D FORWARD -i {WG_IF} -o {WG_IF} -j ACCEPT; iptables -D FORWARD -i {WG_IF} -j DROP || true
"""
    Path(f"/etc/wireguard/{WG_IF}.conf").write_text(conf)

    # Запуск службы
    log.info("Активация и запуск wg-quick@wg0.service")
    run_cmd("systemctl enable wg-quick@wg0")
    run_cmd("systemctl restart wg-quick@wg0")

    # Сохранение правил
    run_cmd("netfilter-persistent save")
    log.info("Инициализация завершена. Интерфейс поднят, правила сохранены.")

def cmd_status():
    """Быстрая проверка состояния."""
    log.info("Статус службы: " + run_cmd("systemctl is-active wg-quick@wg0"))
    log.info("Состояние интерфейса: " + run_cmd("ip -brief link show wg0 || echo 'не найден'"))
    conn = init_db()
    total = conn.execute("SELECT count(*) FROM users").fetchone()[0]
    active = conn.execute("SELECT count(*) FROM users WHERE blocked=0").fetchone()[0]
    log.info(f"Учётные записи: всего {total}, активных {active}")

def cmd_health():
    """Глубокая диагностика."""
    log.info("=== Глубокая диагностика ===")
    errors = []

    # Проверка наличия WireGuard
    wg_bin = get_wg_cmd(allow_missing=True)
    if not wg_bin:
        errors.append("WireGuard не установлен (бинарники wg/awg не найдены)")
    else:
        log.info(f"Обнаружен бинарник WireGuard: {wg_bin}")

    # Проверка интерфейса wg0
    try:
        run_cmd("ip link show wg0")
    except RuntimeError:
        errors.append("Интерфейс wg0 не поднят или отсутствует")

    # Проверка порта (только если wg есть смысл ожидать)
    port_open = run_cmd("ss -ulnH | grep :51820", check=False)
    if not port_open:
        errors.append("Порт 51820/UDP не слушается")

    # Проверка iptables (базовое правило DROP)
    try:
        run_cmd("iptables -L FORWARD -n | grep DROP")
    except RuntimeError:
        errors.append("Базовое правило DROP для FORWARD отсутствует")

    # Проверка IP forward
    try:
        ipf = run_cmd("sysctl -n net.ipv4.ip_forward", check=False)
        if ipf.strip() != "1":
            errors.append("IPv4 forward выключен (net.ipv4.ip_forward != 1)")
    except Exception:
        errors.append("Не удалось проверить net.ipv4.ip_forward")

    # Проверка systemd сервиса
    svc = run_cmd("systemctl is-active wg-quick@wg0", check=False)
    if svc.strip() != "active":
        errors.append(f"Сервис wg-quick@wg0 не активен (сейчас: {svc.strip() or 'unknown'})")

    # Проверка базы данных
    try:
        conn = init_db()
        total = conn.execute("SELECT count(*) FROM users").fetchone()[0]
        log.info(f"База данных: пользователей {total}")
    except Exception as e:
        errors.append(f"Ошибка базы данных: {e}")

    # Итог
    if errors:
        log.warning("Обнаружены проблемы:")
        for err in errors:
            log.warning(f"- {err}")
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
    # Очистка динамических правил (базовые оставляем)
    run_cmd("iptables -D FORWARD -i wg0 -s 10.8.0.0/24 -j ACCEPT 2>/dev/null || true")
    run_cmd("iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -j MASQUERADE 2>/dev/null || true")
    
    # Восстановление пиров и правил
    rows = conn.execute("SELECT pubkey, ip, internet, blocked FROM users WHERE blocked=0").fetchall()
    for row in rows:
        pub, ip, internet, _ = row
        allowed = f"{ip}/32"
        run_cmd(f"{wg_bin} set {WG_IF} peer {pub} allowed-ips {allowed} persistent-keepalive 25")
        if internet:
            run_cmd(f"iptables -A FORWARD -s {ip} -j ACCEPT")
            run_cmd(f"iptables -t nat -A POSTROUTING -s {ip} -o eth0 -j MASQUERADE")
    run_cmd("netfilter-persistent save")
    log.info("Синхронизация завершена")

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
            run_cmd(f"iptables -A FORWARD -s {ip} -j ACCEPT")
            run_cmd(f"iptables -t nat -A POSTROUTING -s {ip} -o eth0 -j MASQUERADE")
            run_cmd("netfilter-persistent save")
            
    server_pub = open("/etc/wireguard/wg0.public").read().strip()
    server_ip = run_cmd("hostname -I | awk '{print $1}'").strip()
    
    cfg_path = Path(f"{CONF_DIR}/{args.name}.conf")
    cfg_content = f"""[Interface]
PrivateKey = {priv}
Address = {ip}/32
DNS = 8.8.8.8

[Peer]
PublicKey = {server_pub}
Endpoint = {server_ip}:{WG_BASE_PORT}
AllowedIPs = {VPN_NET}
PersistentKeepalive = 25
"""
    cfg_path.write_text(cfg_content)
    cfg_path.chmod(0o600)
    
    log.info(f"Учётная запись '{args.name}' создана. IP: {ip}, Админ: {bool(admin_val)}, Интернет: {bool(internet_val)}")
    log.info(f"Конфиг сохранён: {cfg_path}")

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
    log.info("Параметры учётной записи обновлены. Требуется перезапуск или синхронизация для применения сетевых правил.")

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
        print("Краткая справка: vsrv-admin.py {init|status|health|sync|add|edit|block|delete|list|help} [--version]")
        sys.exit(0)

    parser = argparse.ArgumentParser(description="Серверное управление VPN-сетью", add_help=False)
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("init", help="Инициализация сервера и установка пакетов").add_argument("--no-amnezia", action="store_true", help="Использовать стандартный WireGuard вместо AmneziaWG")
    subparsers.add_parser("status", help="Быстрая проверка состояния")
    subparsers.add_parser("health", help="Глубокая диагностика системы")
    subparsers.add_parser("sync", help="Пересборка состояния из базы данных")
    
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
    except Exception as e:
        log.error(str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()