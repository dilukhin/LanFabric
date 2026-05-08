# LanFabric

LanFabric — CLI-инструменты управления VPN на базе WireGuard / AmneziaWG для организации изолированной L3-сети поверх интернета.

Основная задача проекта — быстро поднять приватную сеть, в которой клиенты видят друг друга как в локальной сети, а доступ в интернет выдаётся централизованно и только тем пользователям, которым он явно разрешён.

## Состав проекта

```text
vcli-admin.py   клиентский CLI, запускается на Windows/Linux
vsrv-admin.py   серверный исполнитель, запускается на Ubuntu
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
- Связь клиента с сервером через SSH.
- Аутентификация по SSH-ключу или паролю.
- Серверные действия выполняются через `sudo`.
- Backend выбирается явно при `init` и сохраняется на сервере.
- Автоматического fallback между AmneziaWG и WireGuard нет.
- Интернет пользователям запрещён по умолчанию.
- Данные пользователей хранятся в SQLite.
- Используются только стандартная библиотека Python и системные утилиты.

## Требования

### Сервер

- Ubuntu 22.04 или 24.04.
- Python 3.12+.
- Доступ в интернет для установки пакетов.
- Пользователь с `sudo`.
- Открытый UDP-порт `51820` на внешнем firewall/cloud firewall.

### Клиент администратора

- Windows или Linux.
- Python 3.12+.
- Установленные `ssh` и `scp`.
- SSH-доступ к серверу.

## Backend

LanFabric поддерживает два backend:

```text
awg   AmneziaWG
wg    стандартный WireGuard
```

Выбранный backend сохраняется на сервере в файле:

```text
/opt/vpn-admin/backend
```

Правила выбора:

- обычный `init` выбирает AmneziaWG (`awg`);
- `init --no-amnezia` выбирает WireGuard (`wg`);
- если AmneziaWG не удалось установить или запустить, `init` завершается ошибкой;
- автоматического отката на WireGuard нет;
- чтобы выбрать WireGuard, нужно явно выполнить `init --no-amnezia`.

Это сделано намеренно: backend не должен угадываться по наличию бинарников `awg` или `wg`, иначе легко получить смешанное и трудно диагностируемое состояние.

## Быстрый старт

Пример ниже использует сервер `198.51.100.42`, пользователя `donpedro` и ключ `id_yandex_vm`.

### Инициализация сервера с AmneziaWG

```bash
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm init
```

### Инициализация сервера со стандартным WireGuard

```bash
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm init --no-amnezia
```

### Проверка состояния

```bash
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm status
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm health
```

### Создание пользователя без интернета

```bash
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm add user1
```

### Создание пользователя с интернетом

```bash
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm add user1 --internet
```

### Создание администратора

```bash
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm add user1 --admin
```

На текущем этапе `admin` — это флаг в базе данных и задел под будущие политики доступа. При создании пользователя `--admin` также включает интернет-доступ. Отдельные административные возможности внутри VPN пока не реализованы.

### Скачать клиентский конфиг

```bash
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm config user1
```

Файл будет сохранён локально как:

```text
user1.conf
```

Команда `config` получает конфиг через серверный модуль, а не прямым `scp` к файлу. Это нужно потому, что конфиги на сервере хранятся с закрытыми правами и могут быть недоступны обычному SSH-пользователю.

### Установить клиент на локальной машине

```bash
python vcli-admin.py --host 198.51.100.42 --user donpedro --auth key --key id_yandex_vm install-client
```

Если нужно установить клиент без запроса к серверу:

```bash
python vcli-admin.py install-client --client-type awg
python vcli-admin.py install-client --client-type wg
```

## Команды клиента

Общий вид:

```bash
python vcli-admin.py --host <сервер> --user <ssh-user> --auth key --key <ключ> <команда> [параметры]
```

Глобальные параметры:

```text
--host       IP или DNS-имя сервера; не нужен для install-client --client-type wg/awg
--user       SSH-пользователь, по умолчанию root
--auth       key или password
--key        путь к приватному SSH-ключу
--debug      подробный вывод SSH-команд
--tty        принудительный TTY-режим для ручного ввода sudo-пароля
--version    версия клиента
```

### init

Разворачивает серверное окружение.

```bash
python vcli-admin.py --host <сервер> init
python vcli-admin.py --host <сервер> init --no-amnezia
```

Что делает:

- проверяет SSH-доступ;
- настраивает `sudo` без пароля для нужных команд;
- копирует серверный модуль `vsrv-admin.py` на сервер;
- очищает старое runtime-состояние VPN;
- устанавливает WireGuard или AmneziaWG;
- сохраняет выбранный backend;
- генерирует серверные ключи;
- создаёт и запускает интерфейс `wg0`;
- включает IPv4 forwarding;
- сохраняет iptables-правила.

### patch

Обновляет серверный модуль без полного `init`, если у клиента и сервера отличается только patch-версия.

```bash
python vcli-admin.py --host <сервер> patch
```

Правило версий:

- если совпадают `major.minor.patch`, команда не нужна;
- если отличаются только `patch`, нужно выполнить `patch`;
- если отличаются `major` или `minor`, разрешена только команда `init`;
- остальные команды управления сервером при несовпадении версий не выполняются.

Команда сама копирует серверный модуль на сервер. Пользователь ничего не копирует вручную.

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

Для `auto` клиент запрашивает backend у сервера:

```text
awg -> AmneziaWG
wg  -> WireGuard
```

Для `wg` и `awg` сервер не опрашивается, поэтому `--host` можно не указывать.

На Windows установка выполняется через `winget` по точному package id:

```text
Amnezia.AmneziaWG
WireGuard.WireGuard
```

Перед установкой команда получает сведения через `winget show`, показывает доступную версию пакета и после установки проверяет установленный пакет через `winget list`. Если `winget` недоступен, версия пакета не определяется или установка завершается ошибкой, выводится инструкция для ручной установки.

### start

Запускает VPN runtime без полного `init`.

```bash
python vcli-admin.py --host <сервер> start
```

Для `awg` команда восстанавливает вручную управляемое состояние:

- загружает модуль `amneziawg`;
- создаёт `wg0 type amneziawg`;
- применяет `/etc/wireguard/wg0.setconf`;
- назначает адрес `10.8.0.1/24`;
- поднимает интерфейс;
- восстанавливает базовые правила;
- выполняет синхронизацию пиров из БД.

Для `wg` команда запускает `wg-quick@wg0`.

Эта команда нужна после перезапуска или сна прерываемого VPS, когда данные и конфиги сохранились, но runtime-интерфейс `wg0` исчез.

### stop

Останавливает VPN runtime без удаления данных.

```bash
python vcli-admin.py --host <сервер> stop
```

Команда удаляет runtime-интерфейс и текущие runtime-правила, но не удаляет БД, конфиги и установленное окружение.

### restart

Перезапускает VPN runtime без полного `init`.

```bash
python vcli-admin.py --host <сервер> restart
```

Эквивалентно последовательности:

```text
stop
start
```

### status

Быстро показывает состояние VPN.

```bash
python vcli-admin.py --host <сервер> status
```

Для `wg` состояние определяется через `systemctl is-active wg-quick@wg0`.

Для `awg` состояние определяется по наличию интерфейса `wg0` и успешности команды `awg show wg0`.

Возможные состояния:

```text
RUNNING   VPN запущен
STOPPED   VPN остановлен
BROKEN    интерфейс или backend в неконсистентном состоянии
UNKNOWN   состояние не удалось определить
```

Команда также выводит рекомендации по дальнейшим действиям.

### health

Глубокая диагностика.

```bash
python vcli-admin.py --host <сервер> health
```

Проверяет:

- backend-файл;
- наличие бинарника `awg` или `wg`;
- интерфейс `wg0`;
- возможность прочитать состояние через backend;
- UDP-порт `51820`;
- базовые iptables-правила;
- IPv4 forwarding;
- systemd-сервис для `wg`;
- БД пользователей.

Если обнаружены проблемы, команда выводит рекомендации. Например, если backend и БД есть, но интерфейс отсутствует, обычно нужно выполнить:

```bash
python vcli-admin.py --host <сервер> start
```

а не полный `init`.

### add

Создаёт пользователя.

```bash
python vcli-admin.py --host <сервер> add <имя>
python vcli-admin.py --host <сервер> add <имя> --internet
python vcli-admin.py --host <сервер> add <имя> --admin
python vcli-admin.py --host <сервер> add <имя> --comment "комментарий"
```

Что делает:

- генерирует ключи пользователя;
- выделяет первый свободный IP из диапазона `10.8.0.2-10.8.0.254`;
- добавляет пользователя в БД;
- добавляет peer в текущий интерфейс;
- при `--internet` добавляет NAT/FORWARD-правила;
- создаёт клиентский `.conf`.

Если пользователю разрешён интернет, в клиентском конфиге используется:

```ini
AllowedIPs = 0.0.0.0/0
```

Если интернет не разрешён:

```ini
AllowedIPs = 10.8.0.0/24
```

### edit

Меняет параметры существующего пользователя.

```bash
python vcli-admin.py --host <сервер> edit <имя> --admin true
python vcli-admin.py --host <сервер> edit <имя> --admin false
python vcli-admin.py --host <сервер> edit <имя> --internet true
python vcli-admin.py --host <сервер> edit <имя> --internet false
python vcli-admin.py --host <сервер> edit <имя> --comment "новый комментарий"
```

`edit` меняет данные в БД. После изменения сетевых параметров нужно применить правила:

```bash
python vcli-admin.py --host <сервер> sync
```

Если менялся интернет-доступ, нужно заново скачать конфиг:

```bash
python vcli-admin.py --host <сервер> config <имя>
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
- сохраняет iptables-правила.

Команда полезна после `edit`, после ручных изменений и после восстановления runtime.

### list

Показывает пользователей.

```bash
python vcli-admin.py --host <сервер> list
```

Пример:

```text
ИМЯ             IP           АДМИН  ИНЕТ   СТАТУС     КОММЕНТАРИЙ
----------------------------------------------------------------------
dima            10.8.0.2     ДА     ДА     АКТИВ
```

### block

Блокирует пользователя.

```bash
python vcli-admin.py --host <сервер> block <имя>
```

Что делает:

- удаляет peer из интерфейса;
- удаляет правила интернет-доступа пользователя;
- помечает пользователя как заблокированного в БД.

### delete

Удаляет пользователя.

```bash
python vcli-admin.py --host <сервер> delete <имя> <подтверждение>
```

Подтверждение должно совпадать с именем пользователя:

```bash
python vcli-admin.py --host <сервер> delete dima dima
```

Что делает:

- удаляет peer;
- удаляет правила пользователя;
- удаляет запись из БД;
- удаляет клиентский конфиг на сервере.

### config

Скачивает клиентский конфиг.

```bash
python vcli-admin.py --host <сервер> config <имя>
```

Файл сохраняется в текущий локальный каталог как:

```text
<имя>.conf
```

### remove

Удаляет runtime и VPN-пакеты, но сохраняет данные LanFabric.

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

## Подключение клиента

Перед импортом конфига можно установить подходящий клиент командой:

```bash
python vcli-admin.py --host <сервер> install-client
```

Если backend известен заранее и сервер опрашивать не нужно:

```bash
python vcli-admin.py install-client --client-type awg
python vcli-admin.py install-client --client-type wg
```

### Для WireGuard

1. Скачать конфиг:

```bash
python vcli-admin.py --host <сервер> config <имя>
```

2. Импортировать файл `<имя>.conf` в WireGuard-клиент.
3. Включить туннель.

### Для AmneziaWG

Если сервер поднят в backend `awg`, клиент тоже должен поддерживать AmneziaWG.

1. Скачать конфиг:

```bash
python vcli-admin.py --host <сервер> config <имя>
```

2. Импортировать файл `<имя>.conf` в AmneziaWG-совместимый клиент.
3. Включить туннель.

На текущем этапе конфиг формируется в WireGuard-подобном формате. При необходимости полноценной маскировки AmneziaWG может потребоваться расширение генератора конфигов backend-специфичными параметрами.

## Проверка подключения

После включения туннеля:

```bash
ping 10.8.0.1
```

Если включён интернет-доступ:

```bash
ping 8.8.8.8
curl ifconfig.me
```

На Windows внешний IP можно проверить в браузере:

```text
https://ifconfig.me
```

Если интернет идёт через VPN, внешний IP должен совпадать с публичным IP сервера.

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
- вывод сервера виден на клиенте в реальном времени;
- команды дают рекомендации по дальнейшим действиям;
- `--debug` включает подробный SSH-вывод.

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
```

Потом:

```bash
python vcli-admin.py --host <сервер> status
python vcli-admin.py --host <сервер> health
```

### Пользователю включили интернет через edit

```bash
python vcli-admin.py --host <сервер> edit user1 --internet true
python vcli-admin.py --host <сервер> sync
python vcli-admin.py --host <сервер> config user1
```

Затем импортировать новый конфиг в клиент.

### Пользователь не видит интернет

Проверить:

```bash
python vcli-admin.py --host <сервер> list
python vcli-admin.py --host <сервер> health
```

Возможные причины:

- у пользователя `ИНЕТ: НЕТ`;
- после `edit` не выполнен `sync`;
- клиент использует старый конфиг с `AllowedIPs = 10.8.0.0/24`;
- внешний интерфейс сервера не совпадает с ожидаемым для NAT-правила;
- cloud firewall блокирует UDP `51820`;
- клиент подключён не через AmneziaWG при backend `awg`.

### Конфиг не скачивается

Команда `config` должна работать без прямого доступа пользователя к файлу на сервере. Если ошибка сохраняется, проверить:

```bash
python vcli-admin.py --host <сервер> list
python vcli-admin.py --host <сервер> health
```

Если пользователя нет — создать заново. Если пользователь есть, но конфиг отсутствует — нужно пересоздать конфиг или пользователя.

### Несовпадение версий клиента и сервера

Все серверные команды проверяют совпадение версии клиента и сервера.

Если отличается только patch-версия:

```bash
python vcli-admin.py --host <сервер> patch
```

Если отличается major или minor-версия:

```bash
python vcli-admin.py --host <сервер> init
```

Ручное копирование файлов пользователем не требуется.

### Двойной вывод команды

В версии `0.0.9` дублирование потокового вывода клиентом исправлено. Если дублирование осталось, нужно убедиться, что на клиенте и сервере используются модули одной версии.

## Безопасность

- VPN-ключи пользователей генерируются на сервере.
- Клиентские конфиги хранятся в `/opt/vpn-admin/configs`.
- Конфиги не должны быть доступны всем пользователям системы.
- Команда `config` отдаёт файл через серверный модуль, чтобы не открывать права на чтение обычному SSH-пользователю.
- `sudoers` ограничивается набором команд, необходимых LanFabric.
- Интернет-доступ выдаётся явно.

## Ограничения текущей версии

- Нет web UI.
- Нет API.
- Нет L2/relay-режима.
- Нет полноценной ролевой модели для `admin`.
- Нет автоматического systemd-unit для ручного `awg`-runtime.
- Для AmneziaWG пока используется WireGuard-подобный клиентский конфиг.
- NAT-правила пока завязаны на текущую реализацию iptables и могут потребовать уточнения внешнего интерфейса сервера.

## Версия

Текущая версия файлов:

```text
0.0.9
```

Проверка версии:

```bash
python vcli-admin.py --version
python vsrv-admin.py --version
```

## Направления развития

- Вынести backend-логику в отдельный слой `BackendManager`.
- Добавить backend-специфичную генерацию клиентских конфигов.
- Добавить systemd-unit для автоподъёма `awg` после старта VPS.
- Улучшить определение внешнего интерфейса для NAT.
- Добавить команду регенерации конфигов существующих пользователей.
- Добавить backup/restore БД и конфигов.
- Развить флаг `admin` в полноценную модель прав.
