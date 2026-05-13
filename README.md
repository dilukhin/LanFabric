# LanFabric

LanFabric — CLI-инструменты управления VPN на базе WireGuard / AmneziaWG для организации изолированной L3-сети поверх интернета с управляемым доступом клиентов в интернет.

Основной сценарий: администратор запускает клиентский модуль на Windows или Linux, модуль подключается к серверу по SSH, копирует и запускает серверный модуль, а серверный модуль управляет WireGuard / AmneziaWG, SQLite, iptables и systemd.

## Состав проекта

```text
vcli-admin.py   клиентский модуль администратора, запускается на Windows/Linux
vsrv-admin.py   серверный модуль, запускается на Ubuntu
README.md       описание проекта и сценариев использования
```

Схема работы:

```text
администратор
  |
  | vcli-admin.py
  | SSH/SCP
  v
сервер Ubuntu
  |
  | vsrv-admin.py
  | WireGuard / AmneziaWG
  v
VPN-клиенты
```

## Основные свойства

- Управление полностью через CLI.
- Связь клиента с сервером через SSH/SCP.
- Серверные действия выполняются через `sudo`.
- Поддерживаются backend `awg` и `wg`.
- Backend выбирается при `init` и сохраняется на сервере.
- Автоматического fallback между AmneziaWG и WireGuard нет.
- Интернет пользователям запрещён по умолчанию.
- Доступ в интернет выдаётся явно через `add --internet` или `edit --internet true`.
- Пользователи VPN хранятся в SQLite.
- Используются только стандартная библиотека Python и системные утилиты.
- Команды выводят рекомендации по дальнейшим действиям.
- Для full-tunnel на Windows клиентский модуль автоматически добавляет маршрут к Endpoint мимо VPN через UAC-запрос.

## Требования

### Сервер

- Ubuntu 22.04 или 24.04.
- Python 3.12+.
- SSH-доступ.
- Пользователь с `sudo`.
- Доступ в интернет для установки пакетов.
- Открытый UDP-порт `51820` во внешнем firewall/security group/cloud firewall.

### Клиент администратора

- Windows или Linux.
- Python 3.12+.
- Установленные `ssh` и `scp`.
- Для автоматической установки VPN-клиента на Windows нужен `winget`.
- Для автоматического добавления Windows-маршрута к Endpoint нужен UAC-запрос.

## Backend

LanFabric поддерживает два backend:

```text
awg   AmneziaWG
wg    стандартный WireGuard
```

Backend сохраняется на сервере:

```text
/opt/vpn-admin/backend
```

Правила выбора:

- обычный `init` выбирает AmneziaWG (`awg`);
- `init --no-amnezia` выбирает стандартный WireGuard (`wg`);
- если AmneziaWG установить или запустить нельзя, `init` завершается ошибкой;
- silent fallback `awg -> wg` запрещён;
- backend нельзя угадывать по наличию `/usr/bin/wg` или `/usr/bin/awg`.

Для backend `awg` LanFabric генерирует и сохраняет параметры AmneziaWG:

```text
/opt/vpn-admin/awg_params
```

Эти параметры добавляются и в серверный `/etc/wireguard/wg0.setconf`, и в клиентские конфиги:

```ini
Jc = ...
Jmin = ...
Jmax = ...
S1 = ...
S2 = ...
H1 = ...
H2 = ...
H3 = ...
H4 = ...
```

## Версии и обновление

Версия задаётся в начале каждого модуля:

```python
__version__ = "major.minor.patch"
```

Текущая версия:

```text
0.0.14
```

Правила совместимости:

- если версии клиента и сервера совпадают полностью, команда разрешена;
- если отличается только `patch`, обычные серверные команды блокируются, нужно выполнить `patch`;
- если отличаются `major` или `minor`, разрешён только `init`;
- пользователь не копирует серверный модуль вручную, команда `patch` делает это сама.

Проверка версии клиента:

```bash
python vcli-admin.py --version
```

Проверка версии серверного модуля после установки:

```bash
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm status
```

Обновление серверного модуля при отличии только patch-версии:

```bash
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm patch
```

## Быстрый старт

В примерах используются условные значения:

```text
сервер:         198.51.100.42
SSH-пользователь: donpedro
VPN-пользователи: alice, bob
SSH-ключ:       id_yandex_vm
```

### 1. Инициализация сервера с AmneziaWG

```bash
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm init
```

### 2. Инициализация сервера со стандартным WireGuard

```bash
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm init --no-amnezia
```

### 3. Проверка состояния

```bash
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm status
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm health
```

### 4. Создание пользователя с интернетом

```bash
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm add alice --internet
```

### 5. Установка локального VPN-клиента

```bash
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm install-client
```

### 6. Скачивание конфига

```bash
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm config alice
```

Файл будет сохранён локально:

```text
alice.conf
```

На Windows при full-tunnel-конфиге команда `config` автоматически проверит и добавит маршрут к Endpoint мимо VPN. Если потребуются права администратора, появится UAC-запрос.

### 7. Импорт и проверка

Импортировать `alice.conf` в WireGuard/AmneziaWG-клиент, включить туннель и проверить:

```bash
ping 10.8.0.1
ping 8.8.8.8
curl https://ifconfig.me
```

При работающем full-tunnel внешний IP должен совпасть с публичным IP сервера.

## Глобальные параметры клиента

Общий вид:

```bash
python vcli-admin.py --host <сервер> --user <ssh-user> --auth key --key <ключ> <команда> [параметры]
```

Параметры:

```text
--host       IP или DNS-имя сервера
--user       SSH-пользователь, по умолчанию root
--auth       key или password
--key        путь к приватному SSH-ключу
--debug      подробный вывод команд и SSH
--tty        принудительный TTY-режим для ручного ввода sudo-пароля
--version    версия клиентского модуля
```

`--host` не нужен только для `install-client --client-type wg` и `install-client --client-type awg`, когда тип клиента задан вручную и сервер не опрашивается.

## Команды

### init

Разворачивает серверное окружение.

```bash
python vcli-admin.py --host <сервер> init
python vcli-admin.py --host <сервер> init --no-amnezia
```

Что делает:

- проверяет SSH-доступ;
- настраивает `sudo` без пароля для нужных команд;
- копирует серверный модуль;
- очищает старое runtime-состояние VPN;
- устанавливает WireGuard или AmneziaWG;
- сохраняет выбранный backend;
- для `awg` создаёт параметры AmneziaWG;
- генерирует серверные ключи;
- создаёт и запускает интерфейс `wg0`;
- включает IPv4 forwarding;
- сохраняет iptables-правила.

После успешного `init` можно выполнять `add`, `status`, `health`.

### patch

Обновляет серверный модуль без полного `init`, если у клиента и сервера отличается только patch-версия.

```bash
python vcli-admin.py --host <сервер> patch
```

Если отличаются `major` или `minor`, `patch` запрещён, требуется `init`.

### install-client

Проверяет или устанавливает локальный VPN-клиент.

```bash
python vcli-admin.py --host <сервер> install-client
python vcli-admin.py --host <сервер> install-client --client-type auto
python vcli-admin.py install-client --client-type awg
python vcli-admin.py install-client --client-type wg
python vcli-admin.py install-client --client-type awg --yes
python vcli-admin.py install-client --client-type awg --check-only
python vcli-admin.py install-client --client-type awg --manual
```

Параметры:

```text
--client-type auto   выбрать клиент по backend сервера, значение по умолчанию
--client-type awg    установить или проверить AmneziaWG без запроса к серверу
--client-type wg     установить или проверить WireGuard без запроса к серверу
--yes                установить без интерактивного подтверждения
--check-only         только проверить, ничего не устанавливать
--manual             не устанавливать, вывести инструкцию
```

На Windows установка выполняется через `winget`:

```text
Amnezia.AmneziaWG
WireGuard.WireGuard
```

Если вывод перенаправлен в файл, для установки нужно использовать `--yes`, иначе команда не будет ждать невидимого интерактивного подтверждения.

### endpoint-route

Управляет Windows-маршрутом к Endpoint мимо full-tunnel VPN.

```bash
python vcli-admin.py --host <сервер> endpoint-route add
python vcli-admin.py --host <сервер> endpoint-route status
python vcli-admin.py --host <сервер> endpoint-route delete
```

Обычно вручную выполнять не нужно: команда `config <имя>` сама добавляет маршрут при скачивании full-tunnel-конфига на Windows.

Команда нужна как fallback, если автоматическое добавление маршрута не удалось или UAC-запрос был отменён.

Зачем нужен маршрут: при `AllowedIPs = 0.0.0.0/0` Windows направляет весь трафик в туннель. Без отдельного маршрута к Endpoint попытка связаться с VPN-сервером может уйти в ещё неработающий туннель.

Пример ручного маршрута, который команда добавляет автоматически:

```cmd
route add 198.51.100.42 mask 255.255.255.255 <основной-шлюз> metric 1
```

Удаление:

```bash
python vcli-admin.py --host <сервер> endpoint-route delete
```

### start

Запускает VPN runtime без полного `init`.

```bash
python vcli-admin.py --host <сервер> start
```

Для `awg` команда:

- загружает модуль `amneziawg`;
- пересобирает `/etc/wireguard/wg0.setconf` с сохранёнными AWG-параметрами;
- создаёт `wg0 type amneziawg`, если интерфейс отсутствует;
- применяет `awg setconf wg0 /etc/wireguard/wg0.setconf`;
- назначает `10.8.0.1/24`;
- поднимает интерфейс;
- восстанавливает базовые firewall-правила;
- выполняет `sync`.

Для `wg` команда запускает `wg-quick@wg0`.

Команда полезна после остановки или сна VPS, когда данные сохранились, но runtime-интерфейс исчез.

### stop

Останавливает VPN runtime без удаления данных.

```bash
python vcli-admin.py --host <сервер> stop
```

Удаляет runtime-интерфейс и текущие runtime-правила, но сохраняет БД, backend, ключи и конфиги.

### restart

Перезапускает VPN runtime.

```bash
python vcli-admin.py --host <сервер> restart
```

Эквивалентно:

```text
stop
start
```

### status

Быстро показывает состояние VPN.

```bash
python vcli-admin.py --host <сервер> status
```

Возможные состояния:

```text
RUNNING   VPN запущен
STOPPED   VPN остановлен
BROKEN    интерфейс или backend в неконсистентном состоянии
UNKNOWN   состояние не удалось определить
```

Также выводит количество учётных записей и рекомендации.

### health

Глубокая диагностика.

```bash
python vcli-admin.py --host <сервер> health
```

Проверяет:

- backend-файл;
- наличие backend-бинарника `awg` или `wg`;
- интерфейс `wg0`;
- чтение состояния через backend;
- UDP-порт `51820`;
- базовые iptables-правила;
- порядок FORWARD-правил;
- IPv4 forwarding;
- systemd-сервис для `wg`;
- БД пользователей.

Важно: `health` проверяет сервер изнутри. Он не доказывает, что внешний cloud firewall пропускает UDP `51820` снаружи.

### add

Создаёт учётную запись VPN.

```bash
python vcli-admin.py --host <сервер> add alice
python vcli-admin.py --host <сервер> add alice --internet
python vcli-admin.py --host <сервер> add alice --admin
python vcli-admin.py --host <сервер> add alice --comment "комментарий"
```

Что делает:

- генерирует ключи пользователя;
- выделяет IP из диапазона `10.8.0.2-10.8.0.254`;
- добавляет пользователя в БД;
- добавляет peer в текущий интерфейс;
- при `--internet` добавляет разрешающее FORWARD-правило и NAT;
- создаёт клиентский конфиг на сервере.

Если пользователю разрешён интернет, в клиентском конфиге будет:

```ini
AllowedIPs = 0.0.0.0/0
```

Если интернет не разрешён:

```ini
AllowedIPs = 10.8.0.0/24
```

`--admin` сейчас включает флаг администратора в БД и автоматически включает интернет-доступ. Полноценная ролевая модель пока не реализована.

### edit

Меняет параметры существующего пользователя.

```bash
python vcli-admin.py --host <сервер> edit alice --admin true
python vcli-admin.py --host <сервер> edit alice --admin false
python vcli-admin.py --host <сервер> edit alice --internet true
python vcli-admin.py --host <сервер> edit alice --internet false
python vcli-admin.py --host <сервер> edit alice --comment "новый комментарий"
```

После изменения сетевых параметров нужно применить правила:

```bash
python vcli-admin.py --host <сервер> sync
```

Если менялся интернет-доступ, нужно заново скачать конфиг:

```bash
python vcli-admin.py --host <сервер> config alice
```

### sync

Пересобирает runtime-состояние из БД.

```bash
python vcli-admin.py --host <сервер> sync
```

Что делает:

- удаляет текущих peers из интерфейса;
- заново добавляет активных пользователей;
- пересобирает динамические правила интернет-доступа;
- ставит пользовательские ACCEPT-правила до общего DROP;
- сохраняет iptables-правила.

Правильный порядок FORWARD-правил:

```text
-A FORWARD -i wg0 -o wg0 -j ACCEPT
-A FORWARD -s 10.8.0.2/32 -j ACCEPT
-A FORWARD -i wg0 -j DROP
```

### list

Показывает пользователей.

```bash
python vcli-admin.py --host <сервер> list
```

Пример:

```text
ИМЯ             IP           АДМИН  ИНЕТ   СТАТУС     КОММЕНТАРИЙ
----------------------------------------------------------------------
alice           10.8.0.2     НЕТ    ДА     АКТИВ
```

### block

Блокирует пользователя.

```bash
python vcli-admin.py --host <сервер> block alice
```

Что делает:

- удаляет peer из интерфейса;
- удаляет правила интернет-доступа пользователя;
- помечает пользователя как заблокированного в БД.

### delete

Удаляет пользователя.

```bash
python vcli-admin.py --host <сервер> delete alice alice
```

Второй аргумент — подтверждение. Он должен совпадать с именем пользователя.

Что делает:

- удаляет peer;
- удаляет правила пользователя;
- удаляет запись из БД;
- удаляет клиентский конфиг на сервере.

### config

Скачивает клиентский конфиг через серверный модуль.

```bash
python vcli-admin.py --host <сервер> config alice
```

Файл сохраняется локально:

```text
alice.conf
```

Особенности:

- Endpoint в конфиге берётся из `--host`, а не из `hostname -I` на сервере;
- это защищает от попадания приватного cloud-IP в клиентский конфиг;
- для backend `awg` конфиг содержит параметры AmneziaWG;
- на Windows для full-tunnel-конфига команда автоматически добавляет маршрут к Endpoint мимо VPN.

Пример full-tunnel-конфига для backend `awg`:

```ini
[Interface]
PrivateKey = ...
Address = 10.8.0.2/32
DNS = 8.8.8.8
Jc = 7
Jmin = 40
Jmax = 90
S1 = ...
S2 = ...
H1 = ...
H2 = ...
H3 = ...
H4 = ...

[Peer]
PublicKey = ...
Endpoint = 198.51.100.42:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

### remove

Удаляет VPN runtime и VPN-пакеты, но сохраняет данные LanFabric.

```bash
python vcli-admin.py --host <сервер> remove REMOVE
```

Сохраняются:

```text
/opt/vpn-admin
/etc/wireguard
```

Удаляются или останавливаются:

- runtime-интерфейс `wg0`;
- runtime-правила iptables;
- загруженные VPN-модули, если возможно;
- пакеты WireGuard/AmneziaWG через `apt-get remove`.

### purge

Полностью удаляет LanFabric с сервера.

```bash
python vcli-admin.py --host <сервер> purge PURGE
```

Удаляет:

```text
/opt/vpn-admin
/etc/wireguard
/etc/sudoers.d/vpn-admin
/etc/sysctl.d/99-vpn-forward.conf
```

Также удаляет VPN-пакеты через `apt-get purge`, выполняет `autoremove`, `autoclean` и удаляет источники пакетов AmneziaWG.

`/opt/vpn-admin` удаляется последним действием. Серверный модуль удаляет сам себя вместе с каталогом, это ожидаемое поведение.

## Сеть по умолчанию

```text
VPN_NET      10.8.0.0/24
SERVER_IP    10.8.0.1
CLIENTS      10.8.0.2-10.8.0.254
UDP PORT     51820
INTERFACE    wg0
```

## Хранение данных на сервере

```text
/opt/vpn-admin/
  vsrv-admin.py
  vpn.db
  backend
  awg_params
  configs/

/etc/wireguard/
  wg0.conf
  wg0.setconf
  wg0.private
  wg0.public

/etc/sudoers.d/vpn-admin
/etc/sysctl.d/99-vpn-forward.conf
```

## Логирование

Формат логов:

```text
YYYY-MM-DD HH:MM:SS [CLI] LEVEL: сообщение
YYYY-MM-DD HH:MM:SS [SRV] LEVEL: сообщение
```

Особенности:

- сервер запускается через `python3 -u`;
- длинные серверные операции выводятся потоково;
- служебные команды `--version`, `backend`, `config` выполняются с чистым stdout;
- `--debug` включает подробный вывод SSH и локальных команд;
- рекомендации выводятся в конце блока:

```text
*** РЕКОМЕНДАЦИИ ***
...
*** КОНЕЦ РЕКОМЕНДАЦИЙ ***
```

## Типовые сценарии

### VPS был остановлен или уснул

Симптомы:

- backend есть;
- БД есть;
- `wg0` отсутствует;
- порт `51820/UDP` не слушается.

Действие:

```bash
python vcli-admin.py --host <сервер> start
python vcli-admin.py --host <сервер> status
python vcli-admin.py --host <сервер> health
```

### Пользователю включили интернет через edit

```bash
python vcli-admin.py --host <сервер> edit alice --internet true
python vcli-admin.py --host <сервер> sync
python vcli-admin.py --host <сервер> config alice
```

Затем импортировать новый конфиг в VPN-клиент.

### Нужно проверить, что full-tunnel работает

На Windows после включения туннеля:

```cmd
ping 10.8.0.1
ping 8.8.8.8
curl https://ifconfig.me
```

Ожидаемый результат:

- `10.8.0.1` отвечает;
- `8.8.8.8` отвечает;
- `ifconfig.me` показывает публичный IP сервера.

### Клиент показывает «подключен», но пакетов нет

Проверить на Windows:

```cmd
"C:\Program Files\AmneziaWG\awg.exe" show
route print
```

Признаки успешного handshake:

```text
latest handshake: ... ago
transfer: ... received, ... sent
```

Если `AllowedIPs = 0.0.0.0/0`, должен быть маршрут к Endpoint мимо VPN:

```text
<публичный-IP-сервера>  255.255.255.255  <основной-шлюз>
```

Если маршрута нет:

```bash
python vcli-admin.py --host <сервер> endpoint-route add
```

Или заново выполнить:

```bash
python vcli-admin.py --host <сервер> config alice
```

### Проверить, доходит ли UDP до сервера

На сервере:

```bash
sudo tcpdump -ni eth0 -l -U 'host <внешний-IP-клиента> and udp'
```

На Windows можно отправить тестовый UDP-пакет:

```cmd
python -c "import socket;s=socket.socket(2,2);s.sendto(b'test',('198.51.100.42',51820));s.close()"
```

Если тестовый UDP виден, но VPN-клиент не отправляет UDP, проверять профиль, маршрут к Endpoint и вывод `awg.exe show`.

### Интернет не работает, но handshake есть

На сервере проверить порядок правил:

```bash
sudo iptables -S
sudo iptables -t nat -S
```

Разрешающее правило пользователя должно стоять до общего DROP:

```text
-A FORWARD -s 10.8.0.2/32 -j ACCEPT
-A FORWARD -i wg0 -j DROP
```

Восстановить правила штатно:

```bash
python vcli-admin.py --host <сервер> sync
python vcli-admin.py --host <сервер> health
```

### Cloud firewall / security group

Для работы VPN должен быть открыт входящий UDP `51820` на публичный IP сервера:

```text
Direction: ingress
Protocol: UDP
Port: 51820
Source: 0.0.0.0/0
```

SSH по TCP 22 не доказывает, что UDP 51820 открыт.

## Безопасность

- VPN-ключи пользователей генерируются на сервере.
- Клиентские конфиги хранятся в `/opt/vpn-admin/configs`.
- Конфиги имеют закрытые права.
- Команда `config` отдаёт файл через серверный модуль, чтобы не открывать прямой доступ к конфигам обычному SSH-пользователю.
- `sudoers` ограничивается набором команд, необходимых LanFabric.
- Интернет-доступ выдаётся явно.
- Backend сохраняется явно, не определяется эвристически.

## Ограничения текущей версии

- Нет web UI.
- Нет API.
- Нет L2/relay-режима.
- Нет полноценной ролевой модели для `admin`.
- Нет отдельного systemd-unit для ручного `awg`-runtime.
- NAT-правила пока используют внешний интерфейс `eth0`.
- Автоматическое добавление маршрута к Endpoint реализовано только для Windows.
- Автоматическая установка VPN-клиента реализована только для Windows через `winget`.

## Направления развития

- Вынести backend-логику в отдельный слой `BackendManager`.
- Добавить автоопределение внешнего интерфейса вместо жёсткого `eth0`.
- Добавить systemd-unit для автоподъёма `awg` после старта VPS.
- Добавить команду регенерации конфигов существующих пользователей.
- Добавить backup/restore БД и конфигов.
- Развить флаг `admin` в полноценную модель прав.
- Добавить диагностику внешней доступности UDP `51820`.
- Добавить поддержку Linux/macOS-клиентских маршрутов к Endpoint.

## Краткая памятка успешного сценария

```bash
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm init
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm add alice --internet
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm install-client --yes
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm config alice
```

Дальше импортировать `alice.conf`, включить туннель и проверить:

```cmd
ping 10.8.0.1
ping 8.8.8.8
curl https://ifconfig.me
```
