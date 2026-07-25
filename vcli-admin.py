#!/usr/bin/env python3
"""
vcli-admin.py - клиентский инструмент оркестрации VPN.
Удалённое управление сервером, загрузка конфигураций и проверка состояния.
"""
__version__ = "0.0.17"

import sys
import os
import subprocess
import argparse
import logging
import shlex
import platform
import locale
import re
import tempfile
import uuid
import hashlib
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path

# Константы
SERVER_SCRIPT = "vsrv-admin.py"
REMOTE_DIR = "/opt/vpn-admin"
REMOTE_SCRIPT = f"{REMOTE_DIR}/{SERVER_SCRIPT}"
LANFABRIC_SSH_KEY = os.path.join(os.path.expanduser("~/.ssh"), "lanfabric_ed25519")
TEMP_TRUST_TTL_SECONDS = 3600

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CLI] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("vcli")
ADVICE_LINES = []

class VersionMismatchError(RuntimeError):
    """Ошибка несовпадения версий клиента и сервера."""
    def __init__(self, message, advice_lines):
        super().__init__(message)
        self.advice_lines = advice_lines

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

def format_current_command(args, command):
    """Формирует команду клиента с текущими параметрами подключения."""
    parts = ["python", os.path.basename(__file__)]
    if getattr(args, "host", None):
        parts.extend(["--host", args.host])
    if getattr(args, "user", None):
        parts.extend(["--user", args.user])
    if getattr(args, "auth", None):
        parts.extend(["--auth", args.auth])
    if getattr(args, "key", None):
        parts.extend(["--key", args.key])
    parts.append(command)
    return " ".join(shlex.quote(str(part)) for part in parts)

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

def exec_remote(args, remote_cmd_list, use_tty=False, stream_output=True, force_no_debug=False, timeout=30):
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

    # Непотоковый режим нужен для служебных команд с чистым stdout:
    # version, backend, config. Здесь нельзя зависать на readline().
    if not stream_output:
        try:
            res = subprocess.run(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"SSH-команда не завершилась за {timeout} секунд: {safe_remote_cmd}")
        captured_output = (res.stdout or "").strip()
        if res.returncode != 0:
            if captured_output:
                raise RuntimeError(f"Ошибка SSH: {captured_output}")
            raise RuntimeError("Ошибка SSH без вывода")
        return captured_output

    # Потоковый режим для длинных серверных операций.
    process = subprocess.Popen(
        ssh_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        encoding="utf-8",
        errors="replace"
    )

    output_lines = []

    for line in iter(process.stdout.readline, ''):
        line = line.rstrip()
        if line:
            print(line)
            output_lines.append(line)

    process.stdout.close()
    returncode = process.wait()

    captured_output = "\n".join(output_lines)

    if returncode != 0:
        if captured_output:
            raise RuntimeError(f"Ошибка SSH: {captured_output}")
        raise RuntimeError("Ошибка SSH без вывода")

    return captured_output

def local_output_encodings():
    """Возвращает список вероятных кодировок вывода локальных команд."""
    encodings = []

    for enc in (
        locale.getpreferredencoding(False),
        getattr(sys.stdout, "encoding", None),
        getattr(sys.stderr, "encoding", None),
    ):
        if enc and enc not in encodings:
            encodings.append(enc)

    if platform.system() == "Windows":
        for enc in ("utf-8-sig", "utf-8", "cp866", "cp1251", "mbcs"):
            if enc not in encodings:
                encodings.append(enc)
    else:
        for enc in ("utf-8", "utf-8-sig"):
            if enc not in encodings:
                encodings.append(enc)

    return encodings

def decode_local_output(data, stream_name):
    """Декодирует bytes-вывод локальной команды с fallback по кодировкам."""
    if not data:
        return ""

    for enc in local_output_encodings():
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
        except LookupError:
            continue

    fallback = locale.getpreferredencoding(False) or "utf-8"
    log.warning(
        f"Не удалось строго декодировать {stream_name} локальной команды. "
        f"Вывод будет показан с заменой нечитаемых символов"
    )
    return data.decode(fallback, errors="replace")

def safe_print(text, file=None):
    """Печатает текст, не прерывая команду из-за неподдерживаемых символов."""
    if not text:
        return

    stream = file or sys.stdout
    try:
        print(text, file=stream)
        return
    except UnicodeEncodeError:
        encoding = getattr(stream, "encoding", None) or locale.getpreferredencoding(False) or "utf-8"
        log.warning(
            "Кодировка текущего вывода не поддерживает часть символов. "
            "Они будут заменены при печати"
        )
        safe_text = str(text).encode(encoding, errors="replace").decode(encoding, errors="replace")
        print(safe_text, file=stream)


def is_console_output():
    """Проверяет, что stdout и stderr подключены к консоли, а не к файлу."""
    return bool(sys.stdout.isatty() and sys.stderr.isatty())

def looks_like_winget_progress_line(line):
    """Определяет служебные строки прогресса winget, которые не надо писать в лог."""
    stripped = str(line).strip()
    if not stripped:
        return True

    if stripped in ("-", "\\", "|", "/"):
        return True

    # Прогресс winget часто содержит только псевдографику, проценты и размеры.
    # В неправильной кодировке блоки могут выглядеть как последовательности "в–".
    if " / " in stripped and ("MB" in stripped or "KB" in stripped or " B" in stripped):
        if "█" in stripped or "▒" in stripped or "░" in stripped or "в–" in stripped:
            return True

    if stripped.endswith("%") and ("█" in stripped or "▒" in stripped or "░" in stripped or "в–" in stripped):
        return True

    return False

def clean_winget_output(text):
    """Удаляет из вывода winget строки spinner/progress, оставляя смысловые сообщения."""
    if not text:
        return ""

    lines = []
    for line in str(text).splitlines():
        if looks_like_winget_progress_line(line):
            continue
        lines.append(line.rstrip())

    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()

    return "\n".join(lines)

def run_local_passthrough(cmd_list, debug=False):
    """Выполняет локальную команду с прямым выводом в консоль."""
    if debug:
        log.debug(f"Локальная команда: {' '.join(shlex.quote(c) for c in cmd_list)}")
    try:
        res = subprocess.run(cmd_list)
        return res.returncode
    except FileNotFoundError as e:
        raise RuntimeError(str(e))

def run_local(cmd_list, debug=False):
    """Выполняет команду локально."""
    if debug:
        log.debug(f"Локальная команда: {' '.join(shlex.quote(c) for c in cmd_list)}")
    code, out, err = run_local_result(cmd_list, debug=False)
    if code != 0:
        raise RuntimeError(f"Локальная ошибка: {err or out}")
    return out.strip()

def run_local_result(cmd_list, debug=False):
    """Выполняет локальную команду и возвращает код, stdout, stderr без исключения."""
    if debug:
        log.debug(f"Локальная команда: {' '.join(shlex.quote(c) for c in cmd_list)}")
    try:
        res = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = decode_local_output(res.stdout, "stdout").strip()
        err = decode_local_output(res.stderr, "stderr").strip()
        return res.returncode, out, err
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
        raise VersionMismatchError(
            f"Версия клиента: {__version__}. Версия сервера: {remote_ver}. Отличается только patch-версия",
            [
                "Выполните обновление серверного модуля:",
                format_current_command(args, "patch"),
                "Затем повторите исходную команду.",
            ]
        )
    raise VersionMismatchError(
        f"Версия клиента: {__version__}. Версия сервера: {remote_ver}. Отличается major или minor-версия",
        [
            "Разрешена только повторная инициализация серверной части:",
            format_current_command(args, "init"),
            "После init повторите нужную команду.",
        ]
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

def shell_single_quote(text):
    """Безопасно заключает строку в одинарные кавычки для POSIX shell."""
    return "'" + str(text).replace("'", "'\\''") + "'"


def current_client_id():
    """Возвращает устойчивый идентификатор текущего клиентского компьютера."""
    raw = "|".join([
        platform.node() or "unknown-host",
        os.environ.get("USERNAME") or os.environ.get("USER") or "unknown-user",
        str(Path.home()),
    ])
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def utc_now_text():
    """Возвращает текущее UTC-время для маркеров LanFabric."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def lanfabric_marker(kind, args, nonce, ttl=None):
    """Формирует комментарий-маркер для ключей и sudoers LanFabric."""
    parts = [kind, f"host={args.host}", f"user={args.user}", f"client={current_client_id()}", f"created={utc_now_text()}"]
    if ttl is not None:
        parts.append(f"ttl={ttl}")
    parts.append(f"nonce={nonce}")
    return ":".join(parts)


def ensure_local_keypair(private_key, marker):
    """Создаёт локальную пару SSH-ключей LanFabric, если её ещё нет."""
    private_key = os.path.abspath(os.path.expanduser(private_key))
    public_key = private_key + ".pub"
    os.makedirs(os.path.dirname(private_key), mode=0o700, exist_ok=True)
    if os.path.exists(private_key) and os.path.exists(public_key):
        return private_key, public_key
    run_local(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", marker, "-f", private_key])
    try:
        os.chmod(private_key, 0o600)
        os.chmod(public_key, 0o644)
    except OSError:
        pass
    return private_key, public_key


def create_temp_keypair(marker):
    """Создаёт временную пару SSH-ключей для одной команды."""
    temp_dir = tempfile.mkdtemp(prefix="lanfabric-ssh-")
    private_key = os.path.join(temp_dir, "id_ed25519")
    run_local(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", marker, "-f", private_key])
    try:
        os.chmod(private_key, 0o600)
        os.chmod(private_key + ".pub", 0o644)
    except OSError:
        pass
    return temp_dir, private_key, private_key + ".pub"


def delete_temp_keypair(temp_dir):
    """Удаляет локальный каталог с временной парой ключей."""
    if not temp_dir:
        return
    try:
        for name in os.listdir(temp_dir):
            try:
                os.remove(os.path.join(temp_dir, name))
            except OSError:
                pass
        os.rmdir(temp_dir)
    except OSError as e:
        log.warning(f"Не удалось удалить временный каталог ключей {temp_dir}: {e}")


def read_public_key_line(public_key_path, marker):
    """Читает публичный ключ и заменяет комментарий на маркер LanFabric."""
    text = Path(public_key_path).read_text(encoding="utf-8").strip()
    parts = text.split()
    if len(parts) < 2:
        raise RuntimeError(f"Некорректный публичный SSH-ключ: {public_key_path}")
    return f"{parts[0]} {parts[1]} {marker}"


def ensure_remote_ssh_dir(args):
    """Создаёт ~/.ssh на сервере с безопасными правами."""
    exec_remote(args, ["mkdir", "-p", ".ssh"])
    exec_remote(args, ["chmod", "700", ".ssh"])
    exec_remote(args, ["sh", "-c", "touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"])


def add_authorized_key_line(args, line):
    """Добавляет строку в authorized_keys, если такой строки ещё нет."""
    ensure_remote_ssh_dir(args)
    script = "set -eu\nak=\"$HOME/.ssh/authorized_keys\"\nline=$1\nif ! grep -Fxq -- \"$line\" \"$ak\" 2>/dev/null; then printf '%s\\n' \"$line\" >> \"$ak\"; fi\nchmod 600 \"$ak\""
    exec_remote(args, ["sh", "-c", script, "lanfabric-add-key", line])


def remove_authorized_key_by_marker(args, marker, all_lanfabric=False, temp_only=False):
    """Удаляет из authorized_keys только строки LanFabric по маркеру."""
    ensure_remote_ssh_dir(args)
    script = """
import os, sys
marker = sys.argv[1]
all_lanfabric = sys.argv[2] == '1'
temp_only = sys.argv[3] == '1'
ak = os.path.expanduser('~/.ssh/authorized_keys')
try:
    lines = open(ak, 'r', encoding='utf-8').readlines()
except FileNotFoundError:
    sys.exit(0)
new = []
removed = 0
for line in lines:
    if all_lanfabric:
        drop = 'lanfabric-temp:' in line or 'lanfabric-trust:' in line
    elif temp_only:
        drop = 'lanfabric-temp:' in line
    else:
        drop = bool(marker and marker in line)
    if drop:
        removed += 1
    else:
        new.append(line)
open(ak, 'w', encoding='utf-8').writelines(new)
os.chmod(ak, 0o600)
print(removed)
""".strip()
    out = exec_remote(args, ["python3", "-c", script, marker or "", "1" if all_lanfabric else "0", "1" if temp_only else "0"], stream_output=False)
    lines = str(out or "0").splitlines()
    return int(lines[-1]) if lines else 0


def cleanup_stale_lanfabric_temp_keys(args, remove_all_temp=False):
    """Удаляет просроченные или все временные SSH-ключи LanFabric."""
    ensure_remote_ssh_dir(args)
    script = """
import os, sys, time, datetime, re
remove_all = sys.argv[1] == '1'
ak = os.path.expanduser('~/.ssh/authorized_keys')
try:
    lines = open(ak, 'r', encoding='utf-8').readlines()
except FileNotFoundError:
    sys.exit(0)
now = time.time()
new = []
removed = 0
for line in lines:
    pos = line.find('lanfabric-temp:')
    if pos < 0:
        new.append(line)
        continue
    marker = line[pos:].strip().split()[0]
    fields = {}
    for part in re.split(r':(?=\\w+=)', marker)[1:]:
        if '=' in part:
            k, v = part.split('=', 1)
            fields[k] = v
    try:
        created = fields.get('created', '').replace('Z', '+00:00')
        ttl = int(fields.get('ttl', '0'))
        expired = ttl > 0 and now > datetime.datetime.fromisoformat(created).timestamp() + ttl
    except Exception:
        expired = True
    if remove_all or expired:
        removed += 1
    else:
        new.append(line)
open(ak, 'w', encoding='utf-8').writelines(new)
os.chmod(ak, 0o600)
print(removed)
""".strip()
    out = exec_remote(args, ["python3", "-c", script, "1" if remove_all_temp else "0"], stream_output=False)
    lines = str(out or "0").splitlines()
    removed = int(lines[-1]) if lines else 0
    if removed:
        log.info(f"Удалены временные SSH-ключи LanFabric: {removed}")
    return removed


def get_client_external_ip_from_ssh(args):
    """Определяет IP клиента глазами SSH-сервера через SSH_CLIENT."""
    try:
        return exec_remote(args, ["sh", "-c", "printf '%s' \"${SSH_CLIENT%% *}\""], stream_output=False, force_no_debug=True).strip() or None
    except RuntimeError:
        return None


def sudoers_rule_for_user(user):
    """Возвращает sudoers-правило LanFabric для SSH-пользователя."""
    return (
        f"{user} ALL=(ALL) NOPASSWD: "
        "/usr/bin/apt-get, /usr/bin/apt, /usr/bin/add-apt-repository, "
        "/usr/bin/systemctl, /usr/sbin/iptables, /sbin/iptables, "
        "/usr/bin/netfilter-persistent, /usr/bin/wg, /usr/bin/awg, "
        "/usr/sbin/ip, /usr/bin/ip, /usr/sbin/modprobe, /sbin/modprobe, "
        "/bin/mkdir, /bin/chmod, /bin/chown, /bin/rm, /usr/bin/rm, "
        f"/usr/bin/python3 {REMOTE_SCRIPT} *"
    )


def write_sudoers_file(args, path, marker, use_tty=False):
    """Создаёт sudoers-файл LanFabric и проверяет его через visudo."""
    content = marker + "\n" + sudoers_rule_for_user(args.user) + "\n"
    script = """
import os, sys, subprocess
path = sys.argv[1]
content = sys.argv[2]
with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
os.chmod(path, 0o440)
res = subprocess.run(['visudo', '-cf', path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
if res.returncode != 0:
    try:
        os.remove(path)
    except OSError:
        pass
    sys.stdout.write(res.stdout)
    sys.exit(res.returncode)
""".strip()
    exec_remote(args, ["sudo", "python3", "-c", script, path, content], use_tty=use_tty)


def setup_temporary_sudo_trust(args, nonce):
    """Создаёт временный sudoers-файл LanFabric для текущей команды."""
    marker = "# " + lanfabric_marker("lanfabric-temp-sudo", args, nonce, ttl=TEMP_TRUST_TTL_SECONDS)
    safe_user = re.sub(r"[^A-Za-z0-9_.-]", "_", args.user)
    path = f"/etc/sudoers.d/lanfabric-temp-{safe_user}-{nonce}"
    log.info("Настройка временного sudo trust LanFabric")
    write_sudoers_file(args, path, marker, use_tty=True)
    exec_remote(args, ["sudo", "-n", "true"], stream_output=False)
    return path


def cleanup_temporary_sudo_trust(args, path):
    """Удаляет временный sudoers-файл LanFabric."""
    if not path:
        return
    try:
        exec_remote(args, ["sudo", "-n", "rm", "-f", path], stream_output=False, timeout=10)
        log.info("Временный sudo trust LanFabric удалён")
    except RuntimeError as e:
        log.warning(f"Не удалось удалить временный sudo trust: {e}")
        add_advice("Удалите временные записи LanFabric вручную:", format_current_command(args, "untrust") + " --temp")


def cleanup_stale_temporary_sudo_trust(args, remove_all_temp=False, allow_tty=False):
    """Удаляет просроченные или все временные sudoers-файлы LanFabric."""
    script = """
import os, sys, glob, time, datetime, re
remove_all = sys.argv[1] == '1'
removed = 0
for path in glob.glob('/etc/sudoers.d/lanfabric-temp-*'):
    try:
        text = open(path, 'r', encoding='utf-8').read(4096)
    except OSError:
        continue
    pos = text.find('lanfabric-temp-sudo:')
    if pos < 0:
        continue
    marker = text[pos:].split()[0]
    fields = {}
    for part in re.split(r':(?=\\w+=)', marker)[1:]:
        if '=' in part:
            k, v = part.split('=', 1)
            fields[k] = v
    try:
        created = fields.get('created', '').replace('Z', '+00:00')
        ttl = int(fields.get('ttl', '0'))
        expired = ttl > 0 and time.time() > datetime.datetime.fromisoformat(created).timestamp() + ttl
    except Exception:
        expired = True
    if remove_all or expired:
        try:
            os.remove(path)
            removed += 1
        except OSError:
            pass
print(removed)
""".strip()
    try:
        sudo_cmd = ["sudo", "python3", "-c", script, "1" if remove_all_temp else "0"] if allow_tty else ["sudo", "-n", "python3", "-c", script, "1" if remove_all_temp else "0"]
        out = exec_remote(args, sudo_cmd, stream_output=False, timeout=15, use_tty=allow_tty)
    except RuntimeError as e:
        log.warning(f"Не удалось очистить временные sudoers LanFabric: {e}")
        return 0
    lines = str(out or "0").splitlines()
    removed = int(lines[-1]) if lines else 0
    if removed:
        log.info(f"Удалены временные sudoers LanFabric: {removed}")
    return removed


def setup_permanent_sudo_trust(args):
    """Создаёт постоянный sudoers-файл LanFabric после явного trust."""
    marker = "# " + lanfabric_marker("lanfabric-trust-sudo", args, uuid.uuid4().hex[:12])
    safe_user = re.sub(r"[^A-Za-z0-9_.-]", "_", args.user)
    path = f"/etc/sudoers.d/lanfabric-trust-{safe_user}"
    write_sudoers_file(args, path, marker, use_tty=True)
    log.info(f"Постоянный sudo trust LanFabric настроен: {path}")


def cleanup_permanent_sudo_trust(args, all_lanfabric=False, allow_tty=False):
    """Удаляет постоянные sudoers-файлы LanFabric."""
    safe_user = re.sub(r"[^A-Za-z0-9_.-]", "_", args.user)
    if all_lanfabric:
        script = "for f in /etc/sudoers.d/lanfabric-* /etc/sudoers.d/vpn-admin; do [ -f \"$f\" ] && grep -q 'lanfabric-' \"$f\" && rm -f \"$f\"; done"
        exec_remote(args, (["sudo", "sh", "-c", script] if allow_tty else ["sudo", "-n", "sh", "-c", script]), use_tty=allow_tty)
    else:
        exec_remote(args, (["sudo", "rm", "-f", f"/etc/sudoers.d/lanfabric-trust-{safe_user}"] if allow_tty else ["sudo", "-n", "rm", "-f", f"/etc/sudoers.d/lanfabric-trust-{safe_user}"]), use_tty=allow_tty)



def add_temporary_authorized_key_line(args, key_line):
    """Одним SSH-подключением чистит старые временные ключи и добавляет новый временный ключ."""
    script = """
import os, sys, time, datetime, re
base_key = sys.argv[1]
ak_dir = os.path.expanduser('~/.ssh')
ak = os.path.join(ak_dir, 'authorized_keys')
os.makedirs(ak_dir, mode=0o700, exist_ok=True)
try:
    os.chmod(ak_dir, 0o700)
except OSError:
    pass
try:
    lines = open(ak, 'r', encoding='utf-8').readlines()
except FileNotFoundError:
    lines = []
now = time.time()
new = []
removed = 0
for line in lines:
    pos = line.find('lanfabric-temp:')
    if pos < 0:
        new.append(line)
        continue
    marker = line[pos:].strip().split()[0]
    fields = {}
    for part in re.split(r':(?=\\w+=)', marker)[1:]:
        if '=' in part:
            k, v = part.split('=', 1)
            fields[k] = v
    try:
        created = fields.get('created', '').replace('Z', '+00:00')
        ttl = int(fields.get('ttl', '0'))
        expired = ttl > 0 and now > datetime.datetime.fromisoformat(created).timestamp() + ttl
    except Exception:
        expired = True
    if expired:
        removed += 1
    else:
        new.append(line)
client_ip = (os.environ.get('SSH_CLIENT') or '').split()[0] if os.environ.get('SSH_CLIENT') else ''
if client_ip:
    full_key = 'from="{}",no-agent-forwarding,no-X11-forwarding,no-port-forwarding {}'.format(client_ip, base_key)
else:
    full_key = 'no-agent-forwarding,no-X11-forwarding,no-port-forwarding ' + base_key
if not any(line.strip() == full_key for line in new):
    new.append(full_key + '\n')
open(ak, 'w', encoding='utf-8').writelines(new)
os.chmod(ak, 0o600)
print('CLIENT_IP=' + client_ip)
print('REMOVED=' + str(removed))
""".strip()
    out = exec_remote(args, ["python3", "-c", script, key_line], stream_output=False, force_no_debug=True)
    client_ip = None
    removed = 0
    for line in str(out).splitlines():
        if line.startswith("CLIENT_IP="):
            client_ip = line.split("=", 1)[1] or None
        elif line.startswith("REMOVED="):
            try:
                removed = int(line.split("=", 1)[1])
            except ValueError:
                removed = 0
    if removed:
        log.info(f"Удалены просроченные временные SSH-ключи LanFabric: {removed}")
    return client_ip

def setup_temporary_ssh_trust(args, nonce):
    """Добавляет временный SSH-ключ LanFabric и переключает args на key."""
    marker = lanfabric_marker("lanfabric-temp", args, nonce, ttl=TEMP_TRUST_TTL_SECONDS)
    temp_dir, private_key, public_key = create_temp_keypair(marker)
    original_auth = args.auth
    original_key = args.key
    key_line = read_public_key_line(public_key, marker)
    client_ip = add_temporary_authorized_key_line(args, key_line)
    if client_ip:
        log.info(f"IP клиента по данным SSH-сервера: {client_ip}")
    else:
        log.warning("Не удалось определить IP клиента через SSH_CLIENT. Временный SSH trust добавлен без ограничения from=")
        add_advice("Проверьте SSH-сервер: переменная SSH_CLIENT не определилась, временный ключ был добавлен без from=")
    args.auth = "key"
    args.key = private_key
    log.info("Временный SSH trust LanFabric включён для текущей команды")
    return {"marker": marker, "temp_dir": temp_dir, "original_auth": original_auth, "original_key": original_key}


def cleanup_temporary_ssh_trust(args, state):
    """Удаляет временный SSH-ключ LanFabric и локальные временные файлы."""
    if not state:
        return
    try:
        remove_authorized_key_by_marker(args, state.get("marker"))
        log.info("Временный SSH trust LanFabric удалён")
    except RuntimeError as e:
        log.warning(f"Не удалось удалить временный SSH trust: {e}")
        add_advice("Удалите временные ключи LanFabric вручную:", format_current_command(args, "untrust") + " --temp")
    finally:
        delete_temp_keypair(state.get("temp_dir"))
        args.auth = state.get("original_auth")
        args.key = state.get("original_key")


def server_command_needs_password_session(args):
    """Определяет, нужна ли временная password-сессия для серверной команды."""
    if args.auth != "password":
        return False
    if args.command == "endpoint-route":
        return False
    if args.command == "install-client" and getattr(args, "client_type", "auto") != "auto":
        return False
    return args.command in (
        "init", "patch", "install-client", "start", "stop", "restart", "remove", "purge",
        "add", "edit", "block", "delete", "list", "config", "status", "health", "sync",
    )


@contextmanager
def temporary_password_session_if_needed(args):
    """Создаёт временный SSH/sudo trust для одной команды с гарантированной очисткой."""
    ssh_state = None
    sudo_path = None
    if not server_command_needs_password_session(args):
        if getattr(args, "host", None) and args.command not in ("endpoint-route", "help"):
            try:
                cleanup_stale_lanfabric_temp_keys(args)
                cleanup_stale_temporary_sudo_trust(args)
            except Exception as e:
                log.debug(f"Фоновая очистка временных записей LanFabric не выполнена: {e}")
        yield
        return
    nonce = uuid.uuid4().hex[:12]
    try:
        ssh_state = setup_temporary_ssh_trust(args, nonce)
        sudo_path = setup_temporary_sudo_trust(args, nonce)
        cleanup_stale_temporary_sudo_trust(args)
        yield
    finally:
        if sudo_path:
            cleanup_temporary_sudo_trust(args, sudo_path)
        if ssh_state:
            cleanup_temporary_ssh_trust(args, ssh_state)


def ensure_sudo_nopasswd(args):
    """Проверяет sudo без пароля или выполняет явную разовую настройку через TTY."""
    log.info("Проверка прав sudo...")
    try:
        exec_remote(args, ["sudo", "-n", "true"], stream_output=False, timeout=10)
        log.info("Доступ к sudo без пароля подтверждён.")
        cleanup_stale_temporary_sudo_trust(args)
        return
    except RuntimeError:
        pass

    log.warning("Требуется пароль sudo. Будет выполнена настройка sudoers через интерактивный TTY")
    marker = "# " + lanfabric_marker("lanfabric-trust-sudo", args, uuid.uuid4().hex[:12])
    try:
        write_sudoers_file(args, "/etc/sudoers.d/vpn-admin", marker, use_tty=True)
        exec_remote(args, ["sudo", "-n", "true"], stream_output=False, timeout=10)
        log.info("Настройка sudoers завершена. Пароль sudo больше не потребуется.")
    except RuntimeError as e:
        log.error(f"Не удалось настроить sudo автоматически: {e}")
        log.info("Включён режим интерактивного ввода пароля (--tty) для текущей сессии.")
        args.ssh_tty = True


def cmd_trust(args):
    """Постоянно доверяет текущий клиентский компьютер данному серверу."""
    require_host(args)
    if args.confirm != "TRUST":
        raise RuntimeError("Для подтверждения постоянного trust укажите: trust TRUST")
    log.warning("Этот компьютер получит постоянный доступ к управлению LanFabric на сервере без SSH-пароля")
    nonce = uuid.uuid4().hex[:12]
    marker = lanfabric_marker("lanfabric-trust", args, nonce)
    private_key, public_key = ensure_local_keypair(LANFABRIC_SSH_KEY, marker)
    cleanup_stale_lanfabric_temp_keys(args)
    add_authorized_key_line(args, read_public_key_line(public_key, marker))
    args.auth = "key"
    args.key = private_key
    setup_permanent_sudo_trust(args)
    log.info(f"Постоянный trust LanFabric настроен. Ключ: {private_key}")
    add_advice("Дальше используйте подключение по ключу:", format_current_command(args, "status"))


def cmd_untrust(args):
    """Удаляет постоянные или временные доверенные записи LanFabric."""
    require_host(args)
    cleanup_stale_lanfabric_temp_keys(args)
    if args.temp:
        removed_keys = cleanup_stale_lanfabric_temp_keys(args, remove_all_temp=True)
        removed_sudo = cleanup_stale_temporary_sudo_trust(args, remove_all_temp=True, allow_tty=True)
        log.info(f"Удалены временные записи LanFabric: SSH-ключей {removed_keys}, sudoers {removed_sudo}")
        return
    if args.all_lanfabric:
        if args.all_lanfabric != "REMOVE-ALL-LANFABRIC-KEYS":
            raise RuntimeError("Для удаления всех ключей LanFabric укажите REMOVE-ALL-LANFABRIC-KEYS")
        removed_keys = remove_authorized_key_by_marker(args, None, all_lanfabric=True)
        cleanup_permanent_sudo_trust(args, all_lanfabric=True, allow_tty=True)
        log.info(f"Удалены все SSH-ключи LanFabric у пользователя {args.user}: {removed_keys}")
        return
    marker_prefix = f"lanfabric-trust:host={args.host}:user={args.user}:client={current_client_id()}:"
    removed = remove_authorized_key_by_marker(args, marker_prefix)
    cleanup_permanent_sudo_trust(args, all_lanfabric=False, allow_tty=True)
    log.info(f"Удалён постоянный trust текущего клиента. SSH-ключей удалено: {removed}")

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
        add_advice("Patch не требуется. Можно выполнять обычные команды управления сервером")
        return
    if state == "incompatible":
        raise VersionMismatchError(
            f"Версия клиента: {__version__}. Версия сервера: {remote_ver}. Отличается major или minor-версия",
            [
                "Patch запрещён при отличии major или minor-версии.",
                "Выполните повторную инициализацию серверной части:",
                format_current_command(args, "init"),
            ]
        )

    log.info(f"Версия клиента: {__version__}. Версия сервера: {remote_ver}. Обновление patch-версии")
    ensure_sudo_nopasswd(args)
    copy_server_module(args)
    new_remote_ver = get_remote_version(args)
    if compare_versions(__version__, new_remote_ver) != "equal":
        raise RuntimeError(f"После patch версия сервера осталась несовместимой: {new_remote_ver}")
    add_advice("Patch завершён. Теперь можно повторить исходную команду")

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
        add_advice(manual_client_instruction(client_type))
        return

    try:
        winget_show_package(args, package["id"])
    except RuntimeError as e:
        log.warning(str(e))
        add_advice(manual_client_instruction(client_type))
        return

    installed, installed_version = winget_list_package(args, package["id"])
    if installed:
        log.info(f"Клиент уже установлен: {package['name']} {installed_version or 'версия не определена'}")
        add_advice(
            "Дальше: скачайте конфиг командой config <имя> и импортируйте .conf в клиент",
            "Для full-tunnel на Windows команда config автоматически добавит маршрут к Endpoint",
        )
        return

    if args.check_only:
        add_advice("Клиент не установлен. Режим --check-only: установка не выполняется")
        return

    if args.manual:
        add_advice(manual_client_instruction(client_type))
        return

    if not args.yes:

        if not sys.stdin.isatty() or not sys.stdout.isatty():
            add_advice(
                "Запустите команду с --yes для автоматической установки:",
                format_current_command(args, "install-client") + " --yes",
                "Или используйте --manual, чтобы вывести инструкцию без установки:",
                format_current_command(args, "install-client") + " --manual",
            )
            raise RuntimeError("Интерактивное подтверждение невозможно при перенаправлении вывода")

        answer = input(
            f"Установить {package['name']} через winget? [y/N]: "
        ).strip().lower()

        if answer not in ("y", "yes", "д", "да"):
            log.info("Установка отменена пользователем")
            add_advice(
                "Можно выполнить install-client --yes для автоматической установки "
                "или install-client --manual для ручной установки"
            )
            return

    cmd = [
        "winget", "install", "-e", "--id", package["id"],
        "--accept-package-agreements", "--accept-source-agreements"
    ]

    if is_console_output():
        code = run_local_passthrough(cmd, args.debug)
    else:
        code, out, err = run_local_result(cmd, args.debug)
        clean_out = clean_winget_output(out)
        clean_err = clean_winget_output(err)
        if clean_out:
            safe_print(clean_out)
        if clean_err:
            safe_print(clean_err, file=sys.stderr)

    if code != 0:
        log.warning(f"winget install завершился ошибкой: {code}")
        add_advice(manual_client_instruction(client_type))
        return

    installed, installed_version = winget_list_package(args, package["id"])
    if not installed:
        log.warning("Установка завершилась без ошибки, но повторная проверка пакет не нашла")
        add_advice(manual_client_instruction(client_type))
        return

    log.info(f"Клиент установлен: {package['name']} {installed_version or 'версия не определена'}")
    add_advice(
        "Дальше: скачайте конфиг командой config <имя>, импортируйте .conf в клиент и включите туннель",
        "Для full-tunnel на Windows команда config автоматически добавит маршрут к Endpoint",
        "Проверка после подключения: ping 10.8.0.1, ping 8.8.8.8, curl https://ifconfig.me",
    )

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
        add_advice(manual_client_instruction(client_type))
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
        
def get_windows_default_gateway(args):
    """Возвращает основной IPv4 gateway Windows для маршрута к Endpoint."""
    if platform.system() != "Windows":
        raise RuntimeError("Команда endpoint-route сейчас поддерживается только на Windows")

    code, out, err = run_local_result(["route", "print", "-4"], args.debug)
    if code != 0:
        raise RuntimeError(f"Не удалось получить таблицу маршрутов Windows: {err or out}")

    candidates = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        if parts[0] != "0.0.0.0" or parts[1] != "0.0.0.0":
            continue
        gateway = parts[2]
        iface = parts[3]
        if gateway.lower() == "on-link":
            continue
        if iface.startswith("10.8."):
            continue
        try:
            metric = int(parts[4])
        except ValueError:
            metric = 9999
        candidates.append((metric, gateway, iface))

    if not candidates:
        raise RuntimeError("Не найден обычный IPv4 default gateway. Отключите туннель и повторите endpoint-route add")

    candidates.sort(key=lambda item: item[0])
    return candidates[0]


def windows_endpoint_route_exists(args, gateway=None):
    """Проверяет наличие Windows-маршрута /32 к Endpoint."""
    code, out, err = run_local_result(["route", "print", args.host], args.debug)
    if code != 0:
        return False

    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        if parts[0] != args.host or parts[1] != "255.255.255.255":
            continue
        if gateway and parts[2] != gateway:
            continue
        return True
    return False


def run_windows_route_elevated(args, gateway):
    """Добавляет маршрут к Endpoint через UAC-запрос Windows."""
    # route delete может завершиться ошибкой, если маршрута ещё нет. Это штатно.
    cmd_line = (
        f"route delete {args.host} >nul 2>nul & "
        f"route add {args.host} mask 255.255.255.255 {gateway} metric 1"
    )
    ps_cmd = (
        "$p = Start-Process -FilePath 'cmd.exe' "
        f"-ArgumentList @('/c', '{cmd_line}') "
        "-Verb RunAs -Wait -PassThru; exit $p.ExitCode"
    )
    code, out, err = run_local_result(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
        args.debug
    )
    if code != 0:
        raise RuntimeError(
            "Не удалось добавить маршрут через UAC. "
            "Возможно, запрос повышения прав был отменён. "
            f"Подробности: {err or out}"
        )


def ensure_windows_endpoint_route(args, allow_elevate=False):
    """Обеспечивает Windows-маршрут к Endpoint мимо full-tunnel VPN."""
    if platform.system() != "Windows":
        return False

    metric, gateway, iface = get_windows_default_gateway(args)
    log.info(f"Найден основной gateway Windows: {gateway} через интерфейс {iface}, метрика {metric}")

    if windows_endpoint_route_exists(args, gateway=gateway):
        log.info(f"Маршрут к Endpoint уже есть: {args.host}/32 -> {gateway}")
        return True

    if not allow_elevate:
        # Удаляем старый маршрут к этому Endpoint, чтобы команда была повторяемой.
        run_local_result(["route", "delete", args.host], args.debug)
        code, out, err = run_local_result(
            ["route", "add", args.host, "mask", "255.255.255.255", gateway, "metric", "1"],
            args.debug
        )
        if code != 0:
            raise RuntimeError(
                "Не удалось добавить маршрут к Endpoint. "
                "Запустите командную строку от имени администратора или разрешите UAC-запрос. "
                f"Подробности: {err or out}"
            )
    else:
        log.info("Для full-tunnel нужен маршрут к Endpoint мимо VPN. Сейчас будет запрос повышения прав Windows")
        run_windows_route_elevated(args, gateway)

    if not windows_endpoint_route_exists(args, gateway=gateway):
        raise RuntimeError("Маршрут к Endpoint не найден после добавления")

    log.info(f"Маршрут к Endpoint добавлен: {args.host}/32 -> {gateway}")
    return True


def cmd_endpoint_route(args):
    """Управляет Windows-маршрутом к Endpoint мимо full-tunnel VPN."""
    require_host(args)
    if platform.system() != "Windows":
        raise RuntimeError("Команда endpoint-route сейчас поддерживается только на Windows")

    if args.route_action == "status":
        code, out, err = run_local_result(["route", "print", args.host], args.debug)
        if out:
            safe_print(out)
        if err:
            safe_print(err, file=sys.stderr)
        if windows_endpoint_route_exists(args):
            add_advice("Маршрут к Endpoint найден. Можно включать full-tunnel VPN")
        else:
            add_advice("Маршрут к Endpoint не найден. Выполните endpoint-route add до включения full-tunnel VPN")
        return

    if args.route_action == "delete":
        code, out, err = run_local_result(["route", "delete", args.host], args.debug)
        if code != 0:
            log.info(f"Маршрут к Endpoint не найден или уже удалён: {args.host}")
            add_advice("Удалять нечего. Для проверки выполните endpoint-route status")
            return
        log.info(f"Маршрут к Endpoint удалён: {args.host}")
        add_advice("Перед следующим включением full-tunnel VPN снова выполните config <имя> или endpoint-route add")
        return

    ensure_windows_endpoint_route(args, allow_elevate=True)
    add_advice(
        "Теперь включите туннель и проверьте ping 10.8.0.1.",
        "Для удаления маршрута выполните endpoint-route delete."
    )


def cmd_config(args):
    """Скачивание конфигурации клиента через серверный модуль с sudo-доступом."""
    ensure_remote_version_compatible(args)
    local_file = f"{args.name}.conf"
    log.info(f"Загрузка конфигурации для {args.name}")

    remote_cmd = ["sudo", "python3", "-u", REMOTE_SCRIPT, "config", args.name, "--endpoint", args.host]

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

        full_tunnel = bool(re.search(r"^\s*AllowedIPs\s*=\s*0\.0\.0\.0/0\s*$", content, re.MULTILINE))
        endpoint_route_ok = True

        if platform.system() == "Windows" and full_tunnel:
            try:
                ensure_windows_endpoint_route(args, allow_elevate=True)
                add_advice("Маршрут к Endpoint добавлен автоматически. Теперь можно включать full-tunnel VPN")
            except RuntimeError as route_error:
                endpoint_route_ok = False
                log.warning(str(route_error))
                add_advice(
                    "Автоматически добавить маршрут к Endpoint не удалось.",
                    "До включения full-tunnel VPN выполните:",
                    format_current_command(args, "endpoint-route") + " add",
                )

        advice = [
            "Проверьте, что Endpoint в конфиге равен публичному адресу сервера: " + args.host,
            "Для backend awg конфиг должен содержать параметры Jc, Jmin, Jmax, S1, S2, H1-H4",
        ]
        if full_tunnel and platform.system() == "Windows" and not endpoint_route_ok:
            advice.append("Не включайте full-tunnel VPN, пока не добавлен маршрут к Endpoint")
        advice.extend([
            "Дальше: импортируйте конфиг в WireGuard/AmneziaWG-клиент и включите туннель",
            "Проверка: ping 10.8.0.1, ping 8.8.8.8, затем curl https://ifconfig.me",
        ])
        add_advice(*advice)
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
        print("Краткая справка: vcli-admin.py {trust|untrust|init|patch|install-client|endpoint-route|start|stop|restart|remove|purge|add|edit|block|delete|list|config|status|health|sync} [опции] [--help]")
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

    p_trust = subparsers.add_parser("trust", help="Постоянно доверить текущий клиент этому серверу")
    p_trust.add_argument("confirm", help="Для подтверждения введите TRUST")

    p_untrust = subparsers.add_parser("untrust", help="Удалить постоянные или временные доверенные записи LanFabric")
    p_untrust.add_argument("--temp", action="store_true", help="Удалить временные SSH-ключи и временные sudoers LanFabric")
    p_untrust.add_argument("--all-lanfabric", default=None, metavar="REMOVE-ALL-LANFABRIC-KEYS", help="Удалить все ключи и sudoers LanFabric у SSH-пользователя")

    p_install_client = subparsers.add_parser("install-client", help="Проверить или установить локальный VPN-клиент")
    p_install_client.add_argument("--client-type", choices=["auto", "wg", "awg"], default="auto", help="Тип клиента: auto по backend сервера, wg или awg; wg/awg не требуют --host")
    p_install_client.add_argument("--yes", action="store_true", help="Установить без интерактивного подтверждения")
    p_install_client.add_argument("--check-only", action="store_true", help="Только проверить, ничего не устанавливать")
    p_install_client.add_argument("--manual", action="store_true", help="Не устанавливать, вывести инструкцию")

    p_endpoint_route = subparsers.add_parser("endpoint-route", help="Добавить, удалить или проверить Windows-маршрут к Endpoint")
    p_endpoint_route.add_argument("route_action", choices=["add", "delete", "status"], help="Действие с маршрутом к --host: add, delete или status")

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
        with temporary_password_session_if_needed(args):
            if args.command == "init":
                cmd_init(args)
            elif args.command == "patch":
                cmd_patch(args)
            elif args.command == "trust":
                cmd_trust(args)
            elif args.command == "untrust":
                cmd_untrust(args)
            elif args.command == "install-client":
                cmd_install_client(args)
            elif args.command == "endpoint-route":
                cmd_endpoint_route(args)
            elif args.command in ("remove", "purge"):
                cmd_remove(args)
            elif args.command == "config":
                cmd_config(args)
            else:
                cmd_forward(args)
        flush_advice()
    except VersionMismatchError as e:
        log.error(str(e))
        add_advice(*e.advice_lines)
        flush_advice()
        sys.exit(1)
    except Exception as e:
        log.error(str(e))
        if not ADVICE_LINES:
            add_advice(
                "Проверьте доступность сервера и SSH-доступ.",
                "Проверьте наличие sudo без пароля или используйте --tty.",
                "Если проблема связана с backend AmneziaWG, используйте init --no-amnezia только при явном выборе WireGuard."
            )
        flush_advice()
        sys.exit(1)

if __name__ == "__main__":
    main()
