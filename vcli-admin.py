#!/usr/bin/env python3
"""
vcli-admin.py - клиентский инструмент оркестрации VPN.
Удалённое управление сервером, загрузка конфигураций и проверка состояния.
"""
__version__ = "0.0.9"

import sys
import os
import subprocess
import argparse
import logging
import shlex
import platform
import re

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

def require_host(args):
    """Проверяет, что для серверной команды указан хост."""
    if not getattr(args, "host", None):
        raise RuntimeError("Для этой команды укажите --host <сервер>")
    
def build_ssh_cmd(args, use_tty=False, force_no_debug=False):
    """Формирует базовый список аргументов для SSH."""
    require_host(args)
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

    captured_output = "\n".join(output_lines)

    if returncode != 0:
        if captured_output:
            raise RuntimeError(f"Ошибка SSH: {captured_output}")
        raise RuntimeError("Ошибка SSH без вывода")

    return captured_output

def run_local(cmd_list, debug=False):
    """Выполняет команду локально."""
    if debug:
        log.debug(f"Локальная команда: {' '.join(shlex.quote(c) for c in cmd_list)}")
    res = subprocess.run(cmd_list, capture_output=True, encoding='utf-8', errors='replace')
    if res.returncode != 0:
        raise RuntimeError(f"Локальная ошибка: {res.stderr.strip() or res.stdout.strip()}")
    return res.stdout.strip()

def run_local_result(cmd_list, debug=False):
    """Выполняет локальную команду и возвращает код, stdout, stderr без исключения."""
    if debug:
        log.debug(f"Локальная команда: {' '.join(shlex.quote(c) for c in cmd_list)}")
    try:
        res = subprocess.run(cmd_list, capture_output=True, encoding='utf-8', errors='replace')
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except FileNotFoundError as e:
        return 127, "", str(e)

def parse_version(version):
    """Разбирает версию формата major.minor.patch."""
    value = str(version).strip()
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise RuntimeError(f"Некорректный формат версии: {version}")
    return tuple(int(part) for part in match.groups())

def compare_versions(local_version, remote_version):
    """Сравнивает версии и возвращает equal, patch_mismatch или incompatible."""
    local = parse_version(local_version)
    remote = parse_version(remote_version)
    if local == remote:
        return "equal"
    if local[:2] == remote[:2]:
        return "patch_mismatch"
    return "incompatible"

def local_server_module_path():
    """Возвращает путь к локальному серверному модулю рядом с клиентским модулем."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base_dir, SERVER_SCRIPT)
    if not os.path.exists(path):
        raise RuntimeError(f"Серверный модуль не найден рядом с клиентским: {path}")
    return path

def extract_remote_version(output):
    """Извлекает номер версии из вывода серверного модуля."""
    for token in str(output).split():
        try:
            parse_version(token)
            return token
        except RuntimeError:
            continue
    raise RuntimeError(f"Не удалось определить версию сервера из вывода: {output}")

def get_remote_version(args):
    """Получает версию серверного модуля без отладочного мусора."""
    out = exec_remote(
        args,
        ["sudo", "python3", REMOTE_SCRIPT, "--version"],
        stream_output=False,
        force_no_debug=True
    )
    return extract_remote_version(out)

def ensure_remote_version_compatible(args):
    """Запрещает работу с сервером при несовместимых версиях модулей."""
    remote_ver = get_remote_version(args)
    state = compare_versions(__version__, remote_ver)
    if state == "equal":
        return remote_ver
    if state == "patch_mismatch":
        raise RuntimeError(
            f"Версия клиента: {__version__}. Версия сервера: {remote_ver}. "
            "Отличается только patch-версия. Выполните команду patch, затем повторите действие"
        )
    raise RuntimeError(
        f"Версия клиента: {__version__}. Версия сервера: {remote_ver}. "
        "Отличается major или minor-версия. Разрешена только команда init"
    )

def get_remote_backend(args):
    """Получает backend сервера чистым stdout."""
    out = exec_remote(
        args,
        ["sudo", "python3", "-u", REMOTE_SCRIPT, "backend"],
        stream_output=False,
        force_no_debug=True
    ).strip()
    backend = out.splitlines()[-1].strip() if out else ""
    if backend not in ("wg", "awg"):
        raise RuntimeError(f"Сервер вернул неизвестный backend: {out}")
    return backend

def copy_server_module(args):
    """Копирует локальный серверный модуль на сервер."""
    local_path = local_server_module_path()
    exec_remote(args, ["sudo", "mkdir", "-p", REMOTE_DIR])
    exec_remote(args, ["sudo", "chown", f"{args.user}:{args.user}", REMOTE_DIR])

    scp_cmd = ["scp", "-o", "StrictHostKeyChecking=no"]
    if args.auth == "key":
        scp_cmd.extend(["-i", get_key_path(args.key)])
    scp_cmd.extend([local_path, f"{args.user}@{args.host}:{REMOTE_SCRIPT}"])
    run_local(scp_cmd, args.debug)
    exec_remote(args, ["sudo", "chmod", "+x", REMOTE_SCRIPT])
    log.info(f"Серверный модуль обновлён до версии {__version__}")

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
        
    need_copy = True
    try:
        # Получаем версию из серверного модуля через его встроенный --version
        out = exec_remote(args, ["sudo", "python3", REMOTE_SCRIPT, "--version"], stream_output=False, force_no_debug=True)
        remote_ver = extract_remote_version(out) if out else None
        if remote_ver == __version__:
            log.info(f"Версия серверного модуля совпадает ({__version__}). Копирование не требуется.")
            need_copy = False
        elif remote_ver:
            log.warning(f"На сервере версия {remote_ver}, ожидается {__version__}. Будет замена.")
    except RuntimeError:
        pass  # Файл или модуль не найден — продолжим установку
        
    if need_copy:
        log.info("Подготовка директорий и копирование серверного модуля")
        copy_server_module(args)
    
    log.info("Запуск инициализации на сервере")
    init_cmd = ["sudo", "python3", "-u", REMOTE_SCRIPT, "init"]
    if args.no_amnezia:
        init_cmd.append("--no-amnezia")
    exec_remote(args, init_cmd)
    log.info("Среда успешно создана и проверена")

def cmd_patch(args):
    """Обновляет серверный модуль при отличии только patch-версии."""
    log.info("Проверка версии сервера перед patch")
    try:
        remote_ver = get_remote_version(args)
    except RuntimeError as e:
        raise RuntimeError(f"Не удалось получить версию сервера. Выполните init: {e}")

    state = compare_versions(__version__, remote_ver)
    if state == "equal":
        log.info(f"Версии уже совпадают: {__version__}. Patch не требуется")
        return
    if state == "incompatible":
        raise RuntimeError(
            f"Версия клиента: {__version__}. Версия сервера: {remote_ver}. "
            "Отличается major или minor-версия. Разрешена только команда init"
        )

    log.info(f"Версия клиента: {__version__}. Версия сервера: {remote_ver}. Обновление patch-версии")
    ensure_sudo_nopasswd(args)
    copy_server_module(args)
    new_remote_ver = get_remote_version(args)
    if compare_versions(__version__, new_remote_ver) != "equal":
        raise RuntimeError(f"После patch версия сервера осталась несовместимой: {new_remote_ver}")
    log.info("Patch завершён. Теперь можно повторить исходную команду")

def manual_client_instruction(client_type):
    """Возвращает инструкцию по ручной установке VPN-клиента."""
    if client_type == "awg":
        return (
            "Нужен клиент AmneziaWG.\n"
            "Автоматическая установка недоступна или завершилась ошибкой.\n"
            "Скачайте вручную последний stable release для Windows x64/amd64:\n"
            "https://github.com/amnezia-vpn/amneziawg-windows-client/releases\n"
            "После установки импортируйте .conf, включите туннель и проверьте: "
            "ping 10.8.0.1, ping 8.8.8.8, https://ifconfig.me"
        )
    return (
        "Нужен клиент WireGuard.\n"
        "Автоматическая установка недоступна или завершилась ошибкой.\n"
        "Скачайте вручную установщик для Windows:\n"
        "https://www.wireguard.com/install/\n"
        "После установки импортируйте .conf, включите туннель и проверьте подключение"
    )

def client_package_info(client_type):
    """Возвращает описание winget-пакета для нужного клиента."""
    if client_type == "awg":
        return {
            "name": "AmneziaWG",
            "id": "Amnezia.AmneziaWG",
        }
    return {
        "name": "WireGuard",
        "id": "WireGuard.WireGuard",
    }

def extract_winget_version(output):
    """Пытается извлечь версию из вывода winget."""
    for line in output.splitlines():
        line = line.strip()
        if re.match(r"^(Version|Версия)\s*[: ]", line, re.IGNORECASE):
            return line.split()[-1].strip()
    match = re.search(r"\b\d+(?:\.\d+){1,3}\b", output)
    return match.group(0) if match else None

def print_winget_summary(output):
    """Печатает основные строки сведений winget show."""
    wanted = ("Name", "Название", "Id", "Идентификатор", "Version", "Версия", "Publisher", "Издатель", "Source", "Источник")
    printed = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(wanted):
            log.info(stripped)
            printed = True
    if not printed and output:
        log.info(output.splitlines()[0].strip())

def is_winget_available(args):
    """Проверяет наличие winget."""
    code, out, err = run_local_result(["winget", "--version"], args.debug)
    if code == 0:
        log.info(f"winget найден: {out or 'версия не определена'}")
        return True
    log.warning(f"winget не найден или не запускается: {err or out}")
    return False

def winget_show_package(args, package_id):
    """Получает сведения о winget-пакете."""
    cmd = ["winget", "show", "-e", "--id", package_id, "--accept-source-agreements"]
    code, out, err = run_local_result(cmd, args.debug)
    if code != 0:
        raise RuntimeError(f"winget не смог получить сведения о пакете {package_id}: {err or out}")
    version = extract_winget_version(out)
    if not version:
        raise RuntimeError(f"winget не вернул версию пакета {package_id}")
    print_winget_summary(out)
    log.info(f"Доступная версия пакета: {version}")
    return version

def winget_list_package(args, package_id):
    """Проверяет установленный winget-пакет."""
    cmd = ["winget", "list", "-e", "--id", package_id, "--accept-source-agreements"]
    code, out, err = run_local_result(cmd, args.debug)
    if code != 0:
        return False, None
    version = extract_winget_version(out)
    return True, version

def install_windows_client(args, client_type):
    """Проверяет и устанавливает VPN-клиент на Windows через winget."""
    package = client_package_info(client_type)
    log.info(f"Нужен клиент: {package['name']}")
    log.info(f"winget package id: {package['id']}")

    if not is_winget_available(args):
        log.info(manual_client_instruction(client_type))
        return

    try:
        winget_show_package(args, package["id"])
    except RuntimeError as e:
        log.warning(str(e))
        log.info(manual_client_instruction(client_type))
        return

    installed, installed_version = winget_list_package(args, package["id"])
    if installed:
        log.info(f"Клиент уже установлен: {package['name']} {installed_version or 'версия не определена'}")
        log.info("Дальше: импортируйте .conf в клиент и включите туннель")
        return

    if args.check_only:
        log.info("Клиент не установлен. Режим --check-only: установка не выполняется")
        return

    if args.manual:
        log.info(manual_client_instruction(client_type))
        return

    if not args.yes:
        answer = input(f"Установить {package['name']} через winget? [y/N]: ").strip().lower()
        if answer not in ("y", "yes", "д", "да"):
            log.info("Установка отменена пользователем")
            log.info(manual_client_instruction(client_type))
            return

    cmd = [
        "winget", "install", "-e", "--id", package["id"],
        "--accept-package-agreements", "--accept-source-agreements"
    ]
    code, out, err = run_local_result(cmd, args.debug)
    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    if code != 0:
        log.warning(f"winget install завершился ошибкой: {code}")
        log.info(manual_client_instruction(client_type))
        return

    installed, installed_version = winget_list_package(args, package["id"])
    if not installed:
        log.warning("Установка завершилась без ошибки, но повторная проверка пакет не нашла")
        log.info(manual_client_instruction(client_type))
        return

    log.info(f"Клиент установлен: {package['name']} {installed_version or 'версия не определена'}")
    log.info("Дальше: импортируйте .conf в клиент, включите туннель и проверьте ping 10.8.0.1")

def cmd_install_client(args):
    """Устанавливает или проверяет локальный VPN-клиент."""
    client_type = args.client_type
    if client_type == "auto":
        ensure_remote_version_compatible(args)
        backend = get_remote_backend(args)
        client_type = backend
        log.info(f"Тип клиента выбран автоматически по backend сервера: {backend}")
    else:
        log.info(f"Тип клиента задан вручную: {client_type}. Сервер не опрашивался")

    system = platform.system()
    log.info(f"ОС: {system}")
    if system != "Windows":
        log.info("Автоматическая установка клиента сейчас реализована только для Windows")
        log.info(manual_client_instruction(client_type))
        return

    install_windows_client(args, client_type)

def cmd_remove(args):
    """Удаление среды с сервера через серверный модуль."""
    ensure_remote_version_compatible(args)
    if args.confirm not in ("REMOVE", "PURGE"):
        raise RuntimeError("Для подтверждения укажите REMOVE или PURGE")

    remote_cmd = ["sudo", "python3", "-u", REMOTE_SCRIPT, args.command, args.confirm]

    log.info(f"Выполнение на сервере: {' '.join(shlex.quote(c) for c in remote_cmd)}")
    exec_remote(args, remote_cmd)
        
def cmd_config(args):
    """Скачивание конфигурации клиента через серверный модуль с sudo-доступом."""
    ensure_remote_version_compatible(args)
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
    """Проброс команд управления на серверный модуль."""
    ensure_remote_version_compatible(args)
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
        print("Краткая справка: vcli-admin.py {init|patch|install-client|start|stop|restart|remove|purge|add|edit|block|delete|list|config|status|health|sync} [опции] [--help]")
        sys.exit(0)
        
    if "--version" not in sys.argv:
        print_intro()

    parser = argparse.ArgumentParser(description="Клиентское управление VPN-сетью")
    parser.add_argument("--version", action="version", version=f"vcli-admin {__version__}")

    # Глобальные параметры (объявлены явно, без parents, чтобы избежать конфликтов с subparsers)
    parser.add_argument("--host", default=None, help="IP или хост сервера")
    parser.add_argument("--user", default="root", help="SSH пользователь")
    parser.add_argument("--auth", choices=["key", "password"], default="key", help="Метод SSH аутентификации")
    parser.add_argument("--key", default=None, help="Путь к приватному ключу SSH")
    parser.add_argument("--debug", action="store_true", help="Вывод отладочной информации о командах и SSH")
    parser.add_argument("--tty", action="store_true", dest="ssh_tty", help="Принудительный TTY-режим для ручного ввода пароля sudo")

    subparsers = parser.add_subparsers(dest="command", required=True, help="Команда управления")

    p_init = subparsers.add_parser("init", help="Развёртывание среды на сервере")
    p_init.add_argument("--no-amnezia", action="store_true", help="Использовать стандартный WireGuard вместо AmneziaWG")

    subparsers.add_parser("patch", help="Обновить серверный модуль при отличии только patch-версии")

    p_install_client = subparsers.add_parser("install-client", help="Проверить или установить локальный VPN-клиент")
    p_install_client.add_argument("--client-type", choices=["auto", "wg", "awg"], default="auto", help="Тип клиента: auto по backend сервера, wg или awg; wg/awg не требуют --host")
    p_install_client.add_argument("--yes", action="store_true", help="Установить без интерактивного подтверждения")
    p_install_client.add_argument("--check-only", action="store_true", help="Только проверить, ничего не устанавливать")
    p_install_client.add_argument("--manual", action="store_true", help="Не устанавливать, вывести инструкцию")

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
        elif args.command == "patch":
            cmd_patch(args)
        elif args.command == "install-client":
            cmd_install_client(args)
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
        log.info("3) если отличается только patch-версия, выполните patch")
        log.info("4) при несовместимых major/minor-версиях выполните init")
        log.info("5) при проблемах с AmneziaWG используйте init --no-amnezia")
        sys.exit(1)

if __name__ == "__main__":
    main()