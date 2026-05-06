#!/usr/bin/env python3
"""
vcli-admin.py - клиентский инструмент оркестрации VPN.
Удалённое управление сервером, загрузка конфигураций и проверка состояния.
"""
__version__ = "0.0.8"

import sys
import os
import subprocess
import argparse
import logging
import shlex

# Константы
SERVER_SCRIPT = "vsrv-admin.py"
REMOTE_DIR = "/opt/vpn-admin"
REMOTE_SCRIPT = f"{REMOTE_DIR}/{SERVER_SCRIPT}"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CLI] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("vcli")

def print_intro():
    """Выводит краткую информацию о клиентском инструменте."""
    print(f"LanFabric CLI v{__version__} — клиент управления VPN")
    
def build_ssh_cmd(args, use_tty=False, force_no_debug=False):
    """Формирует базовый список аргументов для SSH."""
    base = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5"]
    if use_tty or getattr(args, "ssh_tty", False):
        base.append("-t")
    if args.auth == "key":
        key_path = get_key_path(args.key)
        if not os.path.isfile(key_path):
            raise RuntimeError(f"Файл ключа не найден: {key_path}")
        base.extend(["-i", key_path])
    if args.debug and not force_no_debug:
        base.append("-v")
    base.append(f"{args.user}@{args.host}")
    return base

def exec_remote(args, remote_cmd_list, use_tty=False, stream_output=True, force_no_debug=False):
    """Выполняет команду на удалённом сервере с потоковым выводом или захватом stdout."""
    ssh_cmd = build_ssh_cmd(args, use_tty, force_no_debug=force_no_debug)
    safe_remote_cmd = " ".join(shlex.quote(str(c)) for c in remote_cmd_list)
    ssh_cmd.append(safe_remote_cmd)

    if args.debug:
        log.debug(f"SSH команда: {' '.join(shlex.quote(c) for c in ssh_cmd)}")

    # TTY режим — просто пробрасываем как есть
    if use_tty or getattr(args, "ssh_tty", False):
        res = subprocess.run(ssh_cmd)
        if res.returncode != 0:
            raise RuntimeError(f"Ошибка SSH (TTY): код возврата {res.returncode}")
        return ""

    # Потоковый режим
    process = subprocess.Popen(
        ssh_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        encoding='utf-8',
        errors='replace'
    )

    output_lines = []

    for line in iter(process.stdout.readline, ''):
        line = line.rstrip()
        if line:
            if stream_output:
                print(line)          # сразу в консоль
            output_lines.append(line)

    process.stdout.close()
    returncode = process.wait()

    if returncode != 0:
        raise RuntimeError("Ошибка SSH (см. вывод выше)")

    return "\n".join(output_lines)

def run_local(cmd_list, debug=False):
    """Выполняет команду локально."""
    if debug:
        log.debug(f"Локальная команда: {' '.join(shlex.quote(c) for c in cmd_list)}")
    res = subprocess.run(cmd_list, capture_output=True, encoding='utf-8', errors='replace')
    if res.returncode != 0:
        raise RuntimeError(f"Локальная ошибка: {res.stderr.strip()}")
    return res.stdout.strip()
    
def ensure_sudo_nopasswd(args):
    """Автоматическая настройка sudo без пароля. При отказе переключается в TTY-режим."""
    log.info("Проверка прав sudo...")
    try:
        exec_remote(args, ["sudo", "-n", "true"])
        log.info("Доступ к sudo без пароля подтверждён.")
        return
    except RuntimeError:
        pass

    log.warning("Требуется пароль sudo. Запуск одноразовой настройки...")
    sudoers_rule = (
        f"{args.user} ALL=(ALL) NOPASSWD: "
        "/usr/bin/apt-get, /usr/bin/systemctl, /sbin/iptables, "
        "/usr/bin/netfilter-persistent, /usr/bin/wg, /usr/bin/awg, "
        "/usr/bin/ip, /bin/mkdir, /bin/chmod, /bin/chown, /bin/rm, "
        f"/usr/bin/python3 {REMOTE_SCRIPT} *"
    )
    setup_cmd = (
        f"sudo sh -c 'echo \"{sudoers_rule}\" > /etc/sudoers.d/vpn-admin && "
        "chmod 0440 /etc/sudoers.d/vpn-admin && "
        "visudo -cf /etc/sudoers.d/vpn-admin'"
    )
    try:
        exec_remote(args, [setup_cmd], use_tty=True)
        log.info("Настройка sudoers завершена. Пароль больше не потребуется.")
    except RuntimeError as e:
        log.error(f"Не удалось настроить sudo автоматически: {e}")
        log.info("Включён режим интерактивного ввода пароля (--tty) для текущей сессии.")
        args.ssh_tty = True

def cmd_init(args):
    """Создание среды на сервере."""
    log.info("Проверка соединения с сервером")
    try:
        exec_remote(args, ["whoami"])
    except Exception as e:
        raise RuntimeError(f"Не удалось подключиться: {e}")
        
    # Автоматическая настройка прав до выполнения системных команд
    ensure_sudo_nopasswd(args)
        
    try:
        # Получаем версию из серверного скрипта через его встроенный --version
        out = exec_remote(args, ["python3", REMOTE_SCRIPT, "--version"])
        # Формат: "vsrv-admin X.Y.Z", извлекаем только версию
        remote_ver = out.split()[-1] if out else None
        if remote_ver == __version__:
            log.info(f"Версия на сервере совпадает ({__version__}). Пропускаем обновление.")
            return
        elif remote_ver:
            log.warning(f"На сервере версия {remote_ver}, ожидается {__version__}. Будет замена.")
    except RuntimeError:
        pass  # Файл/скрипт не найден — продолжим установку
        
    log.info("Подготовка директорий и копирование скрипта")
    exec_remote(args, ["sudo", "mkdir", "-p", REMOTE_DIR])
    exec_remote(args, ["sudo", "chown", f"{args.user}:{args.user}", REMOTE_DIR])
    
    local_script_path = os.path.abspath(__file__).replace("vcli-admin.py", SERVER_SCRIPT)
    if not os.path.exists(local_script_path):
        raise RuntimeError(f"Серверный скрипт не найден рядом с клиентским: {local_script_path}")
        
    scp_cmd = ["scp", "-o", "StrictHostKeyChecking=no"]
    if args.auth == "key":
        scp_cmd.extend(["-i", get_key_path(args.key)])
    scp_cmd.extend([local_script_path, f"{args.user}@{args.host}:{REMOTE_SCRIPT}"])
    run_local(scp_cmd, args.debug)
    exec_remote(args, ["sudo", "chmod", "+x", REMOTE_SCRIPT])
    
    log.info("Запуск инициализации на сервере")
    init_cmd = ["sudo", "python3", "-u", REMOTE_SCRIPT, "init"]
    if args.no_amnezia:
        init_cmd.append("--no-amnezia")
    exec_remote(args, init_cmd)
    log.info("Среда успешно создана и проверена")

def cmd_remove(args):
    """Удаление среды с сервера через серверный скрипт."""
    if args.confirm not in ("REMOVE", "PURGE"):
        raise RuntimeError("Для подтверждения укажите REMOVE или PURGE")

    remote_cmd = ["sudo", "python3", "-u", REMOTE_SCRIPT, args.command, args.confirm]

    log.info(f"Выполнение на сервере: {' '.join(shlex.quote(c) for c in remote_cmd)}")
    exec_remote(args, remote_cmd)
        
def cmd_config(args):
    """Скачивание конфигурации клиента через серверный скрипт с sudo-доступом."""
    local_file = f"{args.name}.conf"
    log.info(f"Загрузка конфигурации для {args.name}")

    remote_cmd = ["sudo", "python3", "-u", REMOTE_SCRIPT, "config", args.name]

    try:
        # Для конфига нужен чистый stdout: без потоковой печати и без ssh -v даже при --debug.
        content = exec_remote(args, remote_cmd, stream_output=False, force_no_debug=True)
        if not content.strip():
            raise RuntimeError("сервер вернул пустой конфиг")
        with open(local_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
            if not content.endswith("\n"):
                f.write("\n")
        os.chmod(local_file, 0o600)
        log.info(f"Конфиг сохранён: {os.path.abspath(local_file)}")
        log.info("Дальше: импортируйте конфиг в WireGuard/AmneziaWG-клиент и включите туннель")
        log.info("Проверка: ping 10.8.0.1, затем проверьте внешний IP через браузер или curl ifconfig.me")
    except RuntimeError as e:
        raise RuntimeError(f"Не удалось скачать конфиг. Проверьте имя учётки: {e}")

def cmd_forward(args):
    """Проброс команд управления на серверный скрипт."""
    remote_cmd = ["sudo", "python3", "-u", REMOTE_SCRIPT, args.command]
    
    if hasattr(args, "name") and args.name:
        remote_cmd.append(args.name)
    if hasattr(args, "confirm") and args.confirm:
        remote_cmd.append(args.confirm)
        
    if hasattr(args, "admin"):
        if args.command == "add" and args.admin:
            remote_cmd.append("--admin")
        elif args.command == "edit" and args.admin is not None:
            remote_cmd.extend(["--admin", str(args.admin)])
            
    if hasattr(args, "internet"):
        if args.command == "add" and args.internet:
            remote_cmd.append("--internet")
        elif args.command == "edit" and args.internet is not None:
            remote_cmd.extend(["--internet", str(args.internet)])
            
    if hasattr(args, "comment") and args.comment:
        remote_cmd.extend(["--comment", str(args.comment)])
        
    log.info(f"Выполнение на сервере: {' '.join(shlex.quote(c) for c in remote_cmd)}")
    exec_remote(args, remote_cmd)

def get_key_path(key_arg):
    """Корректное разрешение пути к SSH-ключу (поддержка ~, .ssh/, абсолютных путей)."""
    if not key_arg:
        return os.path.expanduser("~/.ssh/id_rsa")
    path = os.path.expanduser(os.path.expandvars(key_arg))
    if os.path.isfile(path):
        return os.path.abspath(path)
    # Если передано только имя файла, пробуем стандартную директорию ~/.ssh/
    fallback = os.path.join(os.path.expanduser("~/.ssh"), os.path.basename(path))
    if os.path.isfile(fallback):
        return os.path.abspath(fallback)
    return os.path.abspath(path)  # Возвращаем абсолютный путь для точной диагностики

def main():
    
    if len(sys.argv) == 1:
        print_intro()
        print("Краткая справка: vcli-admin.py {init|start|stop|restart|remove|purge|add|edit|block|delete|list|config|status|health|sync} [опции] [--help]")
        sys.exit(0)
        
    if "--version" not in sys.argv:
        print_intro()

    parser = argparse.ArgumentParser(description="Клиентское управление VPN-сетью")
    parser.add_argument("--version", action="version", version=f"vcli-admin {__version__}")

    # Глобальные параметры (объявлены явно, без parents, чтобы избежать конфликтов с subparsers)
    parser.add_argument("--host", required=True, help="IP или хост сервера")
    parser.add_argument("--user", default="root", help="SSH пользователь")
    parser.add_argument("--auth", choices=["key", "password"], default="key", help="Метод SSH аутентификации")
    parser.add_argument("--key", default=None, help="Путь к приватному ключу SSH")
    parser.add_argument("--debug", action="store_true", help="Вывод отладочной информации о командах и SSH")
    parser.add_argument("--tty", action="store_true", dest="ssh_tty", help="Принудительный TTY-режим для ручного ввода пароля sudo")

    subparsers = parser.add_subparsers(dest="command", required=True, help="Команда управления")

    p_init = subparsers.add_parser("init", help="Развёртывание среды на сервере")
    p_init.add_argument("--no-amnezia", action="store_true", help="Использовать стандартный WireGuard вместо AmneziaWG")

    p_remove = subparsers.add_parser("remove", help="Удаление VPN runtime и пакетов без удаления данных")
    p_remove.add_argument("confirm", help="Для подтверждения введите REMOVE")
    
    p_purge = subparsers.add_parser("purge", help="Полное удаление LanFabric с сервера")
    p_purge.add_argument("confirm", help="Для подтверждения введите PURGE")

    p_add = subparsers.add_parser("add", help="Создание учётной записи")
    p_add.add_argument("name", help="Имя пользователя")
    p_add.add_argument("--admin", action="store_true", help="Назначить администратора")
    p_add.add_argument("--internet", action="store_true", help="Разрешить доступ в интернет")
    p_add.add_argument("--comment", default="", help="Комментарий к учётке")

    p_edit = subparsers.add_parser("edit", help="Редактирование параметров учётки")
    p_edit.add_argument("name", help="Имя учётки")
    p_edit.add_argument("--admin", choices=["true", "false"], default=None, help="Переключить админ-флаг")
    p_edit.add_argument("--internet", choices=["true", "false"], default=None, help="Переключить интернет")
    p_edit.add_argument("--comment", default=None, help="Обновить комментарий")

    p_block = subparsers.add_parser("block", help="Блокировка учётки")
    p_block.add_argument("name", help="Имя учётки")

    p_del = subparsers.add_parser("delete", help="Удаление учётки")
    p_del.add_argument("name", help="Имя учётки")
    p_del.add_argument("confirm", help="Введите имя учётки для подтверждения удаления")

    subparsers.add_parser("start", help="Запуск VPN runtime без полного init")
    subparsers.add_parser("stop", help="Остановка VPN runtime без удаления данных")
    subparsers.add_parser("restart", help="Перезапуск VPN runtime без полного init")
    subparsers.add_parser("list", help="Список учётных записей")
    subparsers.add_parser("status", help="Быстрая проверка состояния")
    subparsers.add_parser("health", help="Глубокая диагностика")
    subparsers.add_parser("sync", help="Пересборка состояния из базы данных")

    p_cfg = subparsers.add_parser("config", help="Скачать .conf клиента на локальную машину")
    p_cfg.add_argument("name", help="Имя учётной записи")

    subparsers.add_parser("help", help="Подробная справка")

    args = parser.parse_args()
    if args.debug:
        log.setLevel(logging.DEBUG)
    if args.command == "help":
        parser.print_help()
        sys.exit(0)
        
    try:
        if args.command == "init":
            cmd_init(args)
        elif args.command in ("remove", "purge"):
            cmd_remove(args)
        elif args.command == "config":
            cmd_config(args)
        else:
            cmd_forward(args)
    except Exception as e:
        log.error(str(e))
        log.info("Проверьте:")
        log.info("1) доступ сервера в интернет")
        log.info("2) наличие sudo без пароля или используйте --tty")
        log.info("3) при проблемах с AmneziaWG используйте --no-amnezia")
        sys.exit(1)

if __name__ == "__main__":
    main()