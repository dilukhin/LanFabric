#!/usr/bin/env python3
"""Временная отдельная служба AWG 3.1; Python 3.8+, стандартная библиотека."""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path('/opt/lanfabric-awg31')
SCRIPT = ROOT / 'awg31_service.py'
STATE = ROOT / 'state'
BIN = ROOT / 'bin'
AWG = BIN / 'awg'
GO = BIN / 'amneziawg-go'
INTERFACE = 'lfawg0'
SOCKET = Path('/run/amneziawg/lfawg0.sock')
UNIT_NAME = 'lanfabric-awg31.service'
UNIT = Path('/etc/systemd/system') / UNIT_NAME
SYSCTL = Path('/etc/sysctl.d/99-lanfabric-awg31.conf')
CHAIN_IN, CHAIN_FWD, CHAIN_NAT = 'LF31-IN', 'LF31-FWD', 'LF31-NAT'
PEER_NAMES = ('dima', 'dina')
PROFILE_KEYS = ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4',
                'HeaderProtectionKey', 'RekeyAfterTime', 'RekeyTimeout', 'RejectAfterTime',
                'KeepaliveTimeout', 'MaxHandshakeAttempts', 'ContentPaddingAddition',
                'RandomTrailers', 'DisableCookies')
SELECTORS = {key: key.lower() for key in PROFILE_KEYS[:11]}
SELECTORS.update({'HeaderProtectionKey': 'header-protection-key',
                  'RekeyAfterTime': 'rekey-after-time', 'RekeyTimeout': 'rekey-timeout',
                  'RejectAfterTime': 'reject-after-time', 'KeepaliveTimeout': 'keepalive-timeout',
                  'MaxHandshakeAttempts': 'max-handshake-attemps',
                  'ContentPaddingAddition': 'content-padding-addition',
                  'RandomTrailers': 'random-trailers', 'DisableCookies': 'disable-cookies'})


def run(argv, data=None, timeout=20):
    """Никогда не выводит stdout/stderr внешней команды при ошибке."""
    try:
        result = subprocess.run([str(x) for x in argv], input=data, capture_output=True,
                                text=True, encoding='utf-8', errors='replace', timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('Не удалось выполнить системную операцию в установленный срок') from None
    if result.returncode:
        raise RuntimeError('Системная операция завершилась ошибкой; содержимое ответа скрыто')
    return result.stdout.strip()


def trusted(path, executable=False):
    """Проверяет владельца и права каждого элемента доверенного пути."""
    path = Path(path)
    for entry in (path,) + tuple(path.parents):
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('Нарушены владелец или права доверенного пути')
    if executable and (not path.is_file() or not os.access(str(path), os.X_OK)):
        raise RuntimeError('Обязательный исполняемый файл недоступен')


def require_root():
    if os.geteuid() != 0:
        raise RuntimeError('Команда требует запуска от root')
    if Path(__file__).resolve() != SCRIPT:
        raise RuntimeError('Служба должна быть установлена в /opt/lanfabric-awg31')
    for path in (ROOT, SCRIPT, AWG, GO):
        trusted(path, executable=path in (AWG, GO))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_private(path, text):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            output.write(text)
    except Exception:
        # Файл создан этой операцией с O_EXCL; частичный новый файл не сохраняется.
        Path(path).unlink()
        raise


def key_valid(value):
    try:
        raw = base64.b64decode(value, validate=True)
        if len(raw) != 32 or not any(raw) or base64.b64encode(raw).decode('ascii') != value:
            raise ValueError
    except (ValueError, TypeError):
        raise RuntimeError('Некорректный ключ AWG') from None
    return value


def new_keypair():
    private = key_valid(run([AWG, 'genkey']))
    public = key_valid(run([AWG, 'pubkey'], data=private + '\n'))
    return private, public


def header_key():
    for _ in range(3):
        raw = secrets.token_bytes(32)
        if any(raw):
            return base64.b64encode(raw).decode('ascii')
    raise RuntimeError('Не удалось создать ненулевой ключ защиты заголовка')

def profile():
    return {'Jc': str(4 + secrets.randbelow(3)), 'Jmin': '10', 'Jmax': '50',
            'S1': '12', 'S2': '12', 'S3': '12', 'S4': '12',
            'H1': '1', 'H2': '2', 'H3': '3', 'H4': '4',
            'HeaderProtectionKey': header_key(),
            'RekeyAfterTime': '100-120', 'RekeyTimeout': '3-7', 'RejectAfterTime': '150-180',
            'KeepaliveTimeout': '5-15', 'MaxHandshakeAttempts': '15-20',
            'ContentPaddingAddition': '10-100', 'RandomTrailers': 'on', 'DisableCookies': 'on'}


def profile_text(params):
    return '\n'.join('{} = {}'.format(key, params[key]) for key in PROFILE_KEYS)


def validate_inputs(endpoint, port, network, wan):
    try:
        endpoint = str(ipaddress.IPv4Address(endpoint))
        net = ipaddress.IPv4Network(network, strict=True)
    except ValueError:
        raise RuntimeError('Требуются IPv4-адрес сервера и корректная сеть /24') from None
    private = [ipaddress.IPv4Network(x) for x in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    if net.prefixlen != 24 or not any(net.subnet_of(item) for item in private):
        raise RuntimeError('Для VPN требуется частная сеть RFC1918 с маской /24')
    if not 1 <= port <= 65535 or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', wan) or wan == INTERFACE:
        raise RuntimeError('Некорректный UDP-порт или внешний интерфейс')
    return endpoint, net


def validate_wan(data):
    defaults = json.loads(run(['ip', '-j', '-4', 'route', 'show', 'default']))
    if len(defaults) != 1 or defaults[0].get('dev') != data['wan']:
        raise RuntimeError('Внешний интерфейс не соответствует единственному IPv4-маршруту по умолчанию')
    policy = json.loads(run(['ip', '-j', '-4', 'rule', 'show']))
    expected = {(0, 'local'), (32766, 'main'), (32767, 'default')}
    numeric_tables = {255: 'local', 254: 'main', 253: 'default'}
    actual = set()
    for item in policy:
        if (item.get('src') != 'all' or
                set(item) - {'priority', 'src', 'table', 'protocol', 'flags', 'dst'} or
                item.get('flags', []) or item.get('dst', 'all') != 'all'):
            raise RuntimeError('Политика маршрутизации отличается от стандартных трёх правил')
        actual.add((item.get('priority'), numeric_tables.get(item.get('table'), item.get('table'))))
    if len(policy) != 3 or actual != expected:
        raise RuntimeError('Политика маршрутизации отличается от стандартных трёх правил')
    addresses = json.loads(run(['ip', '-j', '-4', 'address', 'show', 'dev', data['wan']]))
    if len(addresses) != 1 or 'UP' not in addresses[0].get('flags', []):
        raise RuntimeError('Внешний интерфейс выключен или неоднозначен')
    if data['endpoint'] not in [entry.get('local') for entry in addresses[0].get('addr_info', [])]:
        raise RuntimeError('Публичный адрес отсутствует на внешнем интерфейсе')

def preflight(args):
    endpoint, network = validate_inputs(args.endpoint, args.port, args.network, args.wan)
    for path in (STATE, UNIT, SOCKET, SYSCTL):
        if path.exists() or path.is_symlink():
            raise RuntimeError('Уже есть состояние или ресурс службы; повторная инициализация запрещена')
    links = json.loads(run(['ip', '-j', 'link', 'show']))
    if any(item['ifname'] == INTERFACE for item in links):
        raise RuntimeError('Имя интерфейса уже занято')
    validate_wan({'endpoint': endpoint, 'wan': args.wan})
    for item in json.loads(run(['ip', '-j', '-4', 'route', 'show', 'table', 'all'])):
        destination = item.get('dst', 'default')
        if destination != 'default' and network.overlaps(ipaddress.IPv4Network(destination, strict=False)):
            raise RuntimeError('Выбранная сеть пересекается с существующим маршрутом')
    if run(['ss', '-ulnH', 'sport = :{}'.format(args.port)]):
        raise RuntimeError('Выбранный UDP-порт уже занят')
    baseline = run(['iptables-save'])
    clean_baseline(baseline)
    if run(['sysctl', '-n', 'net.ipv6.conf.all.forwarding']) != '0':
        raise RuntimeError('Стенд имеет включённую IPv6-маршрутизацию')
    for binary, expected in ((GO, args.go_sha256), (AWG, args.awg_sha256)):
        if not re.fullmatch(r'[0-9a-f]{64}', expected) or not secrets.compare_digest(digest(binary), expected):
            raise RuntimeError('Контрольная сумма исполняемого файла не совпадает с закреплённой')
    return endpoint, network, baseline


def firewall_identity(text):
    return '\n'.join(re.sub(r'\[[0-9]+:[0-9]+\]', '[0:0]', line)
                     for line in text.splitlines() if line and not line.startswith('#'))

def clean_baseline(text):
    """Затрагиваемые цепочки должны быть пустыми ACCEPT; остальные не изменяются."""
    table = None
    affected = {'filter': ('INPUT', 'FORWARD'), 'nat': ('POSTROUTING',)}
    for line in text.splitlines():
        if line.startswith('*'):
            table = line[1:]
        if any(line.startswith(':' + name + ' ') for name in (CHAIN_IN, CHAIN_FWD, CHAIN_NAT)):
            raise RuntimeError('Имя собственной сетевой цепочки уже занято')
        for chain in affected.get(table, ()):
            if line.startswith('-A ' + chain + ' '):
                raise RuntimeError('Затрагиваемая цепочка уже настроена; требуется отдельное решение')
            if line.startswith(':' + chain + ' ') and line.split()[1] != 'ACCEPT':
                raise RuntimeError('Сетевая политика стенда отличается от пустой ACCEPT')

def stage_state(args, endpoint, network, baseline):
    """Ключи и оба полных профиля готовятся до изменения системы."""
    staging = Path(tempfile.mkdtemp(prefix='.stage-', dir=str(ROOT)))
    os.chmod(str(staging), 0o700)
    try:
        private, public = new_keypair()
        params = profile()
        server = '[Interface]\nPrivateKey = {}\nListenPort = {}\n{}\n'.format(private, args.port, profile_text(params))
        peers = []
        for index, name in enumerate(PEER_NAMES, 2):
            peer_private, peer_public = new_keypair()
            address = str(network.network_address + index)
            peers.append({'name': name, 'ip': address, 'public_key': peer_public})
            server += '\n[Peer]\nPublicKey = {}\nAllowedIPs = {}/32\nPersistentKeepalive = 25\n'.format(peer_public, address)
            client = '[Interface]\nPrivateKey = {}\nAddress = {}/32\nDNS = 1.1.1.1\nMTU = 1280\n{}\n\n[Peer]\nPublicKey = {}\nEndpoint = {}:{}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n'.format(peer_private, address, profile_text(params), public, endpoint, args.port)
            write_private(staging / (name + '.conf'), client)
        write_private(staging / 'server.conf', server)
        # HPK и PrivateKey находятся только в конфигурациях, не в manifest.
        manifest = {'endpoint': endpoint, 'port': args.port, 'network': str(network), 'wan': args.wan,
                    'server_ip': str(network.network_address + 1), 'server_public_key': public,
                    'peers': peers, 'go_sha256': args.go_sha256, 'awg_sha256': args.awg_sha256,
                    'old_forward': run(['sysctl', '-n', 'net.ipv4.ip_forward']),
                    'baseline_sha256': hashlib.sha256(firewall_identity(baseline).encode()).hexdigest()}
        if manifest['old_forward'] not in ('0', '1'):
            raise RuntimeError('Исходное состояние IPv4 forwarding неизвестно')
        if len({peer['public_key'] for peer in peers} | {public}) != 3:
            raise RuntimeError('Ключи сервера и двух участников должны различаться')
        write_private(staging / 'manifest.json', json.dumps(manifest, sort_keys=True) + '\n')
        return staging, manifest
    except Exception:
        shutil.rmtree(str(staging))
        raise


def load_manifest():
    trusted(STATE)
    path = STATE / 'manifest.json'
    trusted(path)
    if path.stat().st_mode & 0o077:
        raise RuntimeError('Состояние службы доступно другим пользователям')
    data = json.loads(path.read_text(encoding='utf-8'))
    validate_inputs(data['endpoint'], data['port'], data['network'], data['wan'])
    if tuple(peer['name'] for peer in data['peers']) != PEER_NAMES:
        raise RuntimeError('Некорректное состояние участников')
    key_valid(data['server_public_key'])
    if (data['old_forward'] not in ('0', '1') or
            len({peer['public_key'] for peer in data['peers']} | {data['server_public_key']}) != 3):
        raise RuntimeError('Некорректные ключи участников или прежнее состояние forwarding')
    net = ipaddress.IPv4Network(data['network'])
    if data['server_ip'] != str(net.network_address + 1):
        raise RuntimeError('Некорректное состояние адреса сервера')
    for index, peer in enumerate(data['peers'], 2):
        if peer['ip'] != str(net.network_address + index):
            raise RuntimeError('Некорректное состояние адресов участников')
        key_valid(peer['public_key'])
    for binary, expected in ((GO, data['go_sha256']), (AWG, data['awg_sha256'])):
        if not secrets.compare_digest(digest(binary), expected):
            raise RuntimeError('Исполняемые файлы изменились после развёртывания')
    return data


def rules(data):
    """Точный список правил только для собственных цепочек и участников."""
    result = [('filter', CHAIN_IN, ['-i', data['wan'], '-p', 'udp', '-m', 'udp', '--dport', str(data['port']), '-j', 'ACCEPT']),
              ('filter', CHAIN_IN, ['-i', INTERFACE, '-d', data['server_ip'] + '/32', '-p', 'icmp', '-m', 'icmp', '--icmp-type', '8', '-j', 'ACCEPT']),
              ('filter', CHAIN_IN, ['-i', INTERFACE, '-j', 'DROP'])]
    for peer in data['peers']:
        result.extend([('filter', CHAIN_FWD, ['-i', INTERFACE, '-s', peer['ip'] + '/32', '-o', data['wan'], '-j', 'ACCEPT']),
                       ('filter', CHAIN_FWD, ['-i', data['wan'], '-o', INTERFACE, '-d', peer['ip'] + '/32', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']),
                       ('nat', CHAIN_NAT, ['-s', peer['ip'] + '/32', '-o', data['wan'], '-j', 'MASQUERADE'])])
    for source in data['peers']:
        for target in data['peers']:
            if source['name'] != target['name']:
                result.append(('filter', CHAIN_FWD, ['-i', INTERFACE, '-o', INTERFACE, '-s', source['ip'] + '/32', '-d', target['ip'] + '/32', '-j', 'ACCEPT']))
    result.extend([('filter', CHAIN_FWD, ['-i', INTERFACE, '-j', 'DROP']),
                   ('filter', CHAIN_FWD, ['-o', INTERFACE, '-j', 'DROP'])])
    return result


def hooks(data):
    return [('filter', 'INPUT', ['-j', CHAIN_IN]),
            ('filter', 'FORWARD', ['-i', INTERFACE, '-j', CHAIN_FWD]),
            ('filter', 'FORWARD', ['-o', INTERFACE, '-j', CHAIN_FWD]),
            ('nat', 'POSTROUTING', ['-s', data['network'], '-o', data['wan'], '-j', CHAIN_NAT])]


def firewall(data, created):
    for table, chain in (('filter', CHAIN_IN), ('filter', CHAIN_FWD), ('nat', CHAIN_NAT)):
        run(['iptables', '-w', '5', '-t', table, '-N', chain])
        created.append(('chain', table, chain))
    for table, chain, spec in rules(data):
        run(['iptables', '-w', '5', '-t', table, '-A', chain] + spec)
    for table, chain, spec in hooks(data):
        run(['iptables', '-w', '5', '-t', table, '-I', chain, '1'] + spec)
        created.append(('hook', table, chain, spec))


def normalized_rule(tokens):
    """iptables печатает адреса до интерфейсов независимо от порядка аргументов."""
    if len(tokens) < 2 or tokens[0] != '-A' or (len(tokens) - 2) % 2:
        raise RuntimeError('Некорректный формат собственного сетевого правила')
    options = []
    for index in range(2, len(tokens), 2):
        flag, value = tokens[index:index + 2]
        if flag in ('-s', '-d'):
            value = str(ipaddress.IPv4Network(value, strict=False))
        elif flag == '--ctstate':
            value = ','.join(sorted(value.split(',')))
        options.append((flag, value))
    return (tokens[1], tuple(sorted(options)))

def verify_firewall(data):
    """Проверяет точные собственные правила и их порядок без очистки цепочек."""
    for table, chain in (('filter', CHAIN_IN), ('filter', CHAIN_FWD), ('nat', CHAIN_NAT)):
        actual = [shlex.split(line) for line in run(['iptables', '-t', table, '-S', chain]).splitlines()
                  if line.startswith('-A ')]
        expected = [['-A', chain] + spec for rule_table, rule_chain, spec in rules(data)
                    if rule_table == table and rule_chain == chain]
        if [normalized_rule(x) for x in actual] != [normalized_rule(x) for x in expected]:
            raise RuntimeError('Собственные сетевые правила или их порядок изменены')
    for table, chain in (('filter', 'INPUT'), ('filter', 'FORWARD'), ('nat', 'POSTROUTING')):
        expected = [['-A', chain] + spec for hook_table, hook_chain, spec in reversed(hooks(data))
                    if hook_table == table and hook_chain == chain]
        parent = run(['iptables', '-t', table, '-S', chain]).splitlines()
        actual = [shlex.split(line) for line in parent if line.startswith('-A ')]
        if ('-P {} ACCEPT'.format(chain) not in parent or
                [normalized_rule(x) for x in actual] != [normalized_rule(x) for x in expected]):
            raise RuntimeError('Собственные сетевые переходы отсутствуют или перемещены')


def ensure_firewall(data):
    saved = run(['iptables-save'])
    present = [name for name in (CHAIN_IN, CHAIN_FWD, CHAIN_NAT)
               if any(line.startswith(':' + name + ' ') for line in saved.splitlines())]
    if not present:
        clean_baseline(saved)
        # Состояние из manifest принадлежит службе; новые цепочки восстанавливаются перед UP.
        firewall(data, [])
    elif len(present) != 3:
        raise RuntimeError('Собственные сетевые цепочки присутствуют частично; запуск остановлен')
    verify_firewall(data)

def unit_text():
    return '[Unit]\nDescription=Временная служба LanFabric AWG 3.1\nWants=network-online.target\nAfter=network-online.target systemd-sysctl.service\nStartLimitIntervalSec=60\nStartLimitBurst=5\n\n[Service]\nType=simple\nEnvironment=WG_PROCESS_FOREGROUND=1\nEnvironment=GOMEMLIMIT=256MiB\nMemoryAccounting=yes\nMemoryMax=512M\nUMask=0077\nExecStart={} -f {}\nExecStartPost=/usr/bin/python3 {} --internal-configure\nRestart=always\nRestartSec=5\nTimeoutStartSec=60\nTimeoutStopSec=20\n\n[Install]\nWantedBy=multi-user.target\n'.format(GO, INTERFACE, SCRIPT)


def server_profile():
    path = STATE / 'server.conf'
    trusted(path)
    if path.stat().st_mode & 0o077:
        raise RuntimeError('Конфигурация сервера доступна другим пользователям')
    result = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        if line == '[Peer]':
            break
        if '=' in line:
            key, value = (part.strip() for part in line.split('=', 1))
            if key in PROFILE_KEYS:
                if key in result:
                    raise RuntimeError('Повторяющееся поле профиля')
                result[key] = value
    if set(result) != set(PROFILE_KEYS):
        raise RuntimeError('Неполный современный профиль сервера')
    key_valid(result['HeaderProtectionKey'])
    return result


def verify_runtime(data):
    params = server_profile()
    for key in PROFILE_KEYS:
        actual = run([AWG, 'show', INTERFACE, SELECTORS[key]], timeout=2)
        if not secrets.compare_digest(actual.encode('utf-8'), params[key].encode('utf-8')):
            raise RuntimeError('Применённый профиль AWG не совпадает с сохранённым')
    if run([AWG, 'show', INTERFACE, 'public-key']) != data['server_public_key'] or run([AWG, 'show', INTERFACE, 'listen-port']) != str(data['port']):
        raise RuntimeError('Ключ или порт интерфейса не соответствует состоянию')
    expected = {peer['public_key']: peer['ip'] + '/32' for peer in data['peers']}
    actual = {}
    for line in run([AWG, 'show', INTERFACE, 'allowed-ips']).splitlines():
        parts = line.split()
        if len(parts) != 2:
            raise RuntimeError('Некорректное состояние участников интерфейса')
        actual[parts[0]] = parts[1]
    if actual != expected:
        raise RuntimeError('Состав или адреса участников интерфейса не совпадают')
    if not run(['ss', '-ulnH', 'sport = :{}'.format(data['port'])]):
        raise RuntimeError('UDP-порт службы не слушается')


def configure():
    data = load_manifest()
    validate_wan(data)
    deadline = time.monotonic() + 15
    while not SOCKET.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError('Управляющий сокет AWG не появился за 15 секунд')
        time.sleep(0.1)
    trusted(SOCKET)
    info = SOCKET.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError('Управляющий сокет AWG имеет небезопасные права')
    ensure_firewall(data)
    run([AWG, 'setconf', INTERFACE, STATE / 'server.conf'])
    verify_runtime(data)
    run(['ip', 'address', 'add', data['server_ip'] + '/24', 'dev', INTERFACE])
    run(['ip', 'link', 'set', 'dev', INTERFACE, 'mtu', '1280'])
    run(['ip', 'link', 'set', 'dev', INTERFACE, 'up'])


def rollback(data, created):
    """Откатывает только созданные ресурсы после подтверждения остановки интерфейса."""
    failed = False
    if any(item[0] == 'unit' for item in created):
        try:
            run(['systemctl', 'stop', UNIT_NAME])
            active = run(['systemctl', 'show', UNIT_NAME, '--property=ActiveState', '--value'])
            pid = run(['systemctl', 'show', UNIT_NAME, '--property=MainPID', '--value'])
            if active not in ('inactive', 'failed') or pid != '0':
                return True
            links = json.loads(run(['ip', '-j', 'link', 'show']))
            if any(item['ifname'] == INTERFACE for item in links):
                # После закрытия Go его непостоянный TUN должен исчезнуть.
                # Сохранившееся имя само по себе не доказывает нашу принадлежность.
                return True
        except (RuntimeError, ValueError):
            # Не удалять защиту и ключи, когда живой интерфейс не удалось остановить.
            return True
        try:
            run(['systemctl', 'disable', UNIT_NAME])
        except RuntimeError:
            failed = True
    for item in reversed(created):
        try:
            if item[0] == 'hook':
                run(['iptables', '-w', '5', '-t', item[1], '-D', item[2]] + item[3])
            elif item[0] == 'chain':
                run(['iptables', '-w', '5', '-t', item[1], '-F', item[2]])
                run(['iptables', '-w', '5', '-t', item[1], '-X', item[2]])
            elif item[0] in ('file', 'unit'):
                item[1].unlink()
            elif item[0] == 'forward':
                run(['sysctl', '-w', 'net.ipv4.ip_forward=' + data['old_forward']])
            elif item[0] == 'state':
                shutil.rmtree(str(item[1]))
        except (RuntimeError, OSError):
            failed = True
    if any(item[0] == 'unit' for item in created):
        try:
            run(['systemctl', 'daemon-reload'])
        except RuntimeError:
            failed = True
    return failed

def provision(args):
    endpoint, network, baseline = preflight(args)
    staging, data = stage_state(args, endpoint, network, baseline)
    created = []
    try:
        # Сравнить стенд ещё раз непосредственно перед первыми сетевыми изменениями.
        if firewall_identity(run(['iptables-save'])) != firewall_identity(baseline):
            raise RuntimeError('Сетевые правила изменились во время подготовки')
        os.rename(str(staging), str(STATE))
        created.append(('state', STATE))
        firewall(data, created)
        write_private(SYSCTL, 'net.ipv4.ip_forward=1\n')
        created.append(('file', SYSCTL))
        created.append(('forward',))
        run(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
        write_private(UNIT, unit_text())
        created.append(('unit', UNIT))
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', UNIT_NAME], timeout=65)
        health()
    except Exception:
        failed = rollback(data, created)
        if staging.exists():
            shutil.rmtree(str(staging))
        message = 'Развёртывание завершилось ошибкой; выполнен откат собственных ресурсов'
        if failed:
            message = 'Развёртывание завершилось ошибкой; полнота отката не подтверждена, требуется проверка'
        raise RuntimeError(message) from None


def health():
    data = load_manifest()
    validate_wan(data)
    if run(['systemctl', 'is-active', UNIT_NAME]) != 'active':
        raise RuntimeError('Служба не активна')
    pid = run(['systemctl', 'show', UNIT_NAME, '--property=MainPID', '--value'])
    if not re.fullmatch(r'[1-9][0-9]*', pid) or Path('/proc/{}/exe'.format(pid)).resolve() != GO:
        raise RuntimeError('Основной процесс службы не соответствует выбранной реализации')
    trusted(SOCKET)
    info = SOCKET.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError('Управляющий сокет AWG имеет небезопасные права')
    verify_runtime(data)
    if run(['sysctl', '-n', 'net.ipv6.conf.all.forwarding']) != '0':
        raise RuntimeError('IPv6-маршрутизация должна быть выключена')
    if run(['sysctl', '-n', 'net.ipv4.ip_forward']) != '1':
        raise RuntimeError('Маршрутизация IPv4 выключена')
    addresses = json.loads(run(['ip', '-j', '-4', 'address', 'show', 'dev', INTERFACE]))
    actual = [(item['local'], item['prefixlen']) for link in addresses for item in link.get('addr_info', [])]
    if actual != [(data['server_ip'], 24)]:
        raise RuntimeError('Адрес интерфейса не совпадает с состоянием')
    links = json.loads(run(['ip', '-j', 'link', 'show', 'dev', INTERFACE]))
    if len(links) != 1 or 'UP' not in links[0].get('flags', []) or links[0].get('mtu') != 1280:
        raise RuntimeError('Состояние или MTU интерфейса некорректны')
    verify_firewall(data)
    print('Серверная конфигурация AWG 3.1 и два участника проверены')


def export(name):
    load_manifest()
    path = STATE / (name + '.conf')
    trusted(path)
    if path.stat().st_mode & 0o077:
        raise RuntimeError('Профиль клиента доступен другим пользователям')
    sys.stdout.write(path.read_text(encoding='utf-8'))


def main():
    parser = argparse.ArgumentParser(description='Временная служба AWG 3.1')
    parser.add_argument('--internal-configure', action='store_true', help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest='command')
    setup = commands.add_parser('provision', help='Первичное развёртывание на чистом стенде')
    setup.add_argument('--endpoint', required=True, help='Публичный IPv4 сервера')
    setup.add_argument('--port', type=int, required=True, help='Свободный UDP-порт')
    setup.add_argument('--network', required=True, help='Частная сеть VPN /24')
    setup.add_argument('--wan', required=True, help='Внешний интерфейс')
    setup.add_argument('--go-sha256', required=True, help='Закреплённая SHA-256 Go реализации')
    setup.add_argument('--awg-sha256', required=True, help='Закреплённая SHA-256 tools')
    download = commands.add_parser('export', help='Явно вывести секретный профиль клиента')
    download.add_argument('name', choices=PEER_NAMES)
    commands.add_parser('health', help='Проверить службу без вывода секретов')
    args = parser.parse_args()
    try:
        require_root()
        if args.internal_configure and args.command is None:
            configure()
        elif args.internal_configure:
            raise RuntimeError('Внутренний режим нельзя совмещать с командой')
        elif args.command == 'provision':
            provision(args)
        elif args.command == 'export':
            export(args.name)
        elif args.command == 'health':
            health()
        else:
            parser.error('Требуется команда provision, export или health')
    except RuntimeError as error:
        # Все RuntimeError создаются здесь; ответы внешних команд подавлены в run().
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        print('Ошибка службы AWG 3.1. Проверьте безопасный отчёт агента.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
