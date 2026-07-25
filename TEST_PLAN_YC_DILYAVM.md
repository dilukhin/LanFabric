# План тестирования LanFabric на dilyavm

## 1. Назначение

План предназначен для ручной проверки LanFabric `0.0.15` на существующей
виртуальной машине Yandex Cloud. Основной проход проверяет AmneziaWG, SSH/SCP,
`sudo`, systemd, iptables, SQLite, управление пользователями и реальное
VPN-соединение. Разрушающие сценарии вынесены в отдельные этапы и выполняются
только после явного подтверждения.

План не включает периодическое резервное копирование. Для отката используется
одна ручная полная копия Yandex Cloud Backup.

## 2. Зафиксированная конфигурация

| Объект | Значение |
|---|---|
| Каталог YC | `default`, `b1g8ra7o1fcm9p1qfqb6` |
| ВМ | `dilyavm`, `epd42hrnss08t2440g90` |
| Зона | `ru-central1-b` |
| Конфигурация | 2 vCPU, 1 ГиБ RAM, `preemptible` |
| Публичный IPv4 | `158.160.79.193` |
| Загрузочный диск | `epdekd8e2ndkppha9u5p`, network HDD, 10 ГиБ |
| ОС | Ubuntu 24.04 LTS с OS Login |
| SSH-пользователь | `dilukhin` |
| SSH-ключ | `C:\Users\Dima\.ssh\id_yandex_vm` |
| Cloud Backup | `b87c2e4b-b4ee-405c-9b52-e7f39d4eae0b` |
| Тип копии | `FULL` |
| Время копии | `2026-07-25T13:06:50Z` |
| Размер хранения | 1 670 356 992 байта, около 1,56 ГиБ |
| Ожидаемая стоимость | около 7,73 руб. в месяц |
| Агент Cloud Backup | `18.1.41198`, зарегистрирован |
| Политика Backup | не привязана, автоматических запусков нет |

Публичный адрес необходимо перечитать перед каждым проходом: у прерываемой ВМ
он может измениться. В командах ниже используется адрес, актуальный на дату
создания плана.

## 3. Общие правила

1. Каждый этап начинается только после успешного завершения предыдущего.
2. Перед `init`, `trust`, `untrust`, `remove`, `purge`, восстановлением копии и
   изменением облачного firewall требуется отдельное подтверждение оператора.
3. Не удалять резервную копию до завершения всего тестового цикла и принятия
   результата.
4. Не привязывать постоянное расписание Cloud Backup. Для новой ручной копии
   политика привязывается временно и отвязывается сразу после проверки копии.
5. Не считать `health` проверкой внешнего UDP 51820: порт проверяется отдельно
   со стороны клиента.
6. Не использовать `trust` как единственный SSH-доступ. Ключ `id_yandex_vm`
   должен продолжать работать независимо от LanFabric.
7. При неожиданном результате остановить основной сценарий, собрать состояние
   read-only командами и решить: исправлять, продолжать или восстанавливать ВМ.
8. `purge` не входит в обязательный проход.

## 4. Критерии завершения

Обязательный проход считается успешным, если:

- локальные проверки завершились без неожиданных failures/errors;
- `init` завершился без silent fallback с `awg` на `wg`;
- `status` показывает `RUNNING`, а обязательные проверки `health` успешны;
- созданы пользователи без интернета и с интернетом;
- клиент без интернета видит VPN-сеть, но не получает интернет через VPN;
- full-tunnel клиент видит VPN-сеть и выходит в интернет с публичного IP ВМ;
- `block`, `edit`, `sync`, `stop`, `start` и `restart` дают ожидаемый результат;
- после тестов политика Cloud Backup не привязана;
- итоговое состояние ВМ и решение об откате зафиксированы.

Критические причины остановки:

- потерян независимый SSH-доступ по `id_yandex_vm`;
- повреждён или исчез ручной Cloud Backup;
- изменился неизвестный ресурс YC;
- `init` удалил данные, которые не должны были изменяться;
- firewall блокирует SSH после изменений;
- backend, интерфейс и сохранённый runtime расходятся;
- тест затрагивает чужих VPN-пользователей или рабочий трафик.

## 5. Переменные сеанса

Открыть PowerShell в корне репозитория и задать переменные:

```powershell
$Project = "C:\Users\Dima\Projects\LanFabricRoot\LanFabric"
$HostIp = "158.160.79.193"
$VmId = "epd42hrnss08t2440g90"
$Key = "C:\Users\Dima\.ssh\id_yandex_vm"
$BackupId = "b87c2e4b-b4ee-405c-9b52-e7f39d4eae0b"
```

Все артефакты теста складывать вне git-репозитория:

```text
C:\Users\Dima\Projects\LanFabricRoot\temp\lanfabric-e2e\
```

Не сохранять в отчётах приватные ключи, токены, пароли и содержимое
`PrivateKey` из VPN-конфигов.

## 6. Этап 0. Ворота восстановления

### 6.1 Проверить ВМ и копию

```powershell
yc --profile default compute instance get --id $VmId
yc --profile default backup backup get --backup-id $BackupId
yc --profile default backup policy list
yc --profile default backup vm get $VmId
```

Ожидается:

- ВМ существует;
- копия имеет тип `FULL` и относится к `$VmId`;
- `size` больше нуля;
- у ресурса Backup указано `no_policies_applied` либо список применений пуст;
- временной роли `compute.osAdminLogin` нет.

Проверка IAM:

```powershell
yc --profile default resource-manager folder list-access-bindings --id b1g8ra7o1fcm9p1qfqb6
```

### 6.2 Проверить независимый SSH-доступ

Если ключ защищён парольной фразой:

```powershell
ssh-add $Key
```

После запуска ВМ проверить вход отдельно от LanFabric:

```powershell
ssh -F NUL -i $Key -o IdentitiesOnly=yes dilukhin@$HostIp "id; sudo -n true; python3 --version"
```

Ожидается Python 3.12+ и успешный `sudo -n true`. Если SSH или `sudo` не
работает, `init` не выполнять.

## 7. Этап 1. Локальный baseline

```powershell
Set-Location $Project
python tests_local\run_local_checks.py
python vcli-admin.py --version
python vsrv-admin.py --version
git status --short
```

Ожидается:

- `vcli-admin 0.0.15`;
- `vsrv-admin 0.0.15`;
- нет неожиданных failures/errors;
- expected failures фиксируются как известные дефекты, а не как успех функций;
- тест не изменяет рабочие файлы проекта.

Сохранить вывод локальных проверок в отчёт тестового прохода.

## 8. Этап 2. Облачный preflight

### 8.1 Запустить ВМ

Запуск изменяет состояние и тарификацию, поэтому выполняется после
подтверждения:

```powershell
yc --profile default compute instance start --id $VmId
yc --profile default compute instance get --id $VmId
```

Обновить `$HostIp`, если публичный адрес изменился.

### 8.2 Проверить сеть

```powershell
yc --profile default vpc security-group list
yc --profile default vpc subnet get e2lh3chjs1gcl5egfn67
Test-NetConnection -ComputerName $HostIp -Port 22
```

Проверить по фактическим security groups или cloud firewall:

- TCP 22 доступен только из ожидаемых источников;
- UDP 51820 разрешён из источников VPN-клиентов;
- к сетевому интерфейсу ВМ применена ожидаемая группа;
- неизвестных широких правил `0.0.0.0/0` для административных портов нет.

Не менять правила автоматически. Любое исправление firewall оформить отдельным
действием с точным правилом и откатом.

### 8.3 Проверить сервер до init

```powershell
ssh -F NUL -i $Key -o IdentitiesOnly=yes dilukhin@$HostIp "uname -a; cat /etc/os-release; python3 --version; df -h /; free -h"
```

Зафиксировать наличие старого состояния без чтения приватных ключей:

```powershell
ssh -F NUL -i $Key -o IdentitiesOnly=yes dilukhin@$HostIp "sudo test -e /opt/vpn-admin && echo VPN_ADMIN_EXISTS || echo VPN_ADMIN_ABSENT; sudo test -e /etc/wireguard && echo WG_DIR_EXISTS || echo WG_DIR_ABSENT; ip link show wg0 2>/dev/null || true"
```

## 9. Этап 3. Инициализация AmneziaWG

Это первый разрушающий этап: `init` очищает старый runtime, пересоздаёт ключи и
конфигурацию. Перед запуском ещё раз проверить ID резервной копии.

```powershell
Set-Location $Project
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key init
```

Ожидается:

- выбран backend `awg`;
- при невозможности установить или запустить AmneziaWG команда завершается
  ошибкой, а не переключается молча на WireGuard;
- создан `/opt/vpn-admin/backend` со значением `awg`;
- созданы AWG-параметры;
- интерфейс `wg0` поднят;
- включён IPv4 forwarding;
- серверный модуль имеет версию `0.0.15`.

После init:

```powershell
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key status
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key health
```

Если основной целью является WireGuard, отдельный проход `init --no-amnezia`
выполнять только после завершения и фиксации AWG-прохода. Повторный `init`
снова разрушающий.

## 10. Этап 4. Пользователи и конфигурации

Использовать только тестовые имена:

```powershell
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key add alice
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key add bob --internet
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key list
```

Ожидается:

- `alice` создана без доступа в интернет;
- `bob` создан с доступом в интернет;
- адреса уникальны;
- повторный `add` с тем же именем блокируется понятной ошибкой;
- `list` не раскрывает приватные ключи.

Скачать конфиги из каталога артефактов, чтобы не загрязнять репозиторий:

```powershell
New-Item -ItemType Directory -Force "C:\Users\Dima\Projects\LanFabricRoot\temp\lanfabric-e2e"
Set-Location "C:\Users\Dima\Projects\LanFabricRoot\temp\lanfabric-e2e"
python "$Project\vcli-admin.py" --host $HostIp --user dilukhin --auth key --key $Key config alice
python "$Project\vcli-admin.py" --host $HostIp --user dilukhin --auth key --key $Key config bob
```

Проверить без публикации секретов:

- `Endpoint` указывает на актуальный IP и UDP 51820;
- адрес клиента имеет маску `/32`;
- у `alice` нет full-tunnel `AllowedIPs = 0.0.0.0/0`;
- у `bob` есть full-tunnel;
- AWG-конфиги содержат `Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`-`H4`;
- приватные ключи разных пользователей не совпадают.

## 11. Этап 5. Реальное VPN-соединение

Сначала только проверить наличие клиента:

```powershell
Set-Location $Project
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key install-client --check-only
```

Установка клиента и изменение маршрута выполняются отдельно после
подтверждения. Для full-tunnel сохранить исходную таблицу маршрутов:

```powershell
route print
python vcli-admin.py --host $HostIp endpoint-route status
```

### 11.1 Alice без интернета

После импорта `alice.conf`:

- включить туннель;
- проверить `ping 10.8.0.1`;
- проверить недоступность других клиентов, если это ожидается политикой;
- убедиться, что обычный интернет не маршрутизируется через VPN;
- проверить handshake на сервере.

### 11.2 Bob с интернетом

После импорта `bob.conf`:

```powershell
ping 10.8.0.1
ping 8.8.8.8
curl.exe https://ifconfig.me/ip
```

Ожидается:

- доступен VPN-шлюз `10.8.0.1`;
- доступен интернет;
- внешний IP равен актуальному публичному IP ВМ;
- SSH к Endpoint не уходит внутрь ещё не поднятого full-tunnel;
- после выключения туннеля исходная маршрутизация восстанавливается.

Проверить UDP 51820 с внешней стороны по факту успешного handshake. Открытый
локальный сокет в `health` не доказывает доступность порта из интернета.

## 12. Этап 6. Изменение состояния

```powershell
Set-Location $Project
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key edit alice --internet true
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key sync
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key config alice
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key block bob
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key list
```

Ожидается:

- новый конфиг `alice` отражает доступ в интернет;
- старый импортированный конфиг не получает новые права автоматически;
- после `block bob` новый handshake и передача трафика `bob` прекращаются;
- повторный `sync` идемпотентен.

Проверить защиту удаления:

```powershell
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key delete alice WRONG
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key delete alice alice
```

Первый вызов должен быть заблокирован без изменений. Второй удаляет только
тестовую учётную запись `alice` после проверки оператора.

## 13. Этап 7. Runtime и восстановление сервиса

```powershell
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key stop
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key status
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key start
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key health
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key restart
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key health
```

Ожидается:

- после `stop` состояние `STOPPED`, но БД, backend, ключи и конфиги сохранены;
- после `start` пользователи и их адреса восстановлены;
- после `restart` состояние `RUNNING`;
- iptables и порядок FORWARD не накапливают дубликаты;
- `health` не показывает `BROKEN`.

Отдельный сценарий прерывания ВМ:

1. Зафиксировать `status` и список пользователей.
2. Остановить и запустить ВМ средствами YC.
3. Обновить публичный IP при необходимости.
4. Выполнить `start`, `status`, `health`.
5. Убедиться, что сохранённые пользователи восстановлены.

## 14. Этап 8. Версии и patch

При равных версиях:

```powershell
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key patch
```

Ожидается безопасный отказ или no-op с понятным сообщением.

Проверку patch-mismatch проводить только на временной копии исходного файла или
после отдельного коммита с тестовой patch-версией. Не менять версии рабочих
модулей без фиксации в git.

Проверить:

- patch-различие блокирует обычные команды и разрешает `patch`;
- major/minor-различие блокирует `patch` и требует `init`;
- `patch` заменяет только серверный модуль и не пересоздаёт ключи, БД и backend.

## 15. Этап 9. Trust и untrust, необязательный

Выполнять только при сохранённом независимом доступе по `id_yandex_vm`.

Известные риски версии `0.0.15`:

- обычный `untrust` использует два SSH-вызова и может оставить sudoers после
  частичного сбоя;
- повторный `trust` может создать дубликат ключа;
- очистка stale sudoers использует команду вне созданного allowlist;
- клиент использует `StrictHostKeyChecking=no`;
- IPv6 в маркерах требует отдельной проверки.

Минимальный сценарий:

1. Сохранить только строки LanFabric из `authorized_keys` и список
   `/etc/sudoers.d/lanfabric-*`, не копируя чужие ключи в отчёт.
2. Выполнить `trust TRUST` по парольной аутентификации.
3. Проверить доступ через `lanfabric_ed25519`.
4. Выполнить `untrust`.
5. Проверить отсутствие целевого маркера и соответствующего sudoers.
6. Повторно проверить независимый доступ по `id_yandex_vm`.

При остатках не выполнять широкую очистку. Сначала определить точные строки и
файлы, затем согласовать адресное исправление.

## 16. Этап 10. Remove и purge, необязательный

### 16.1 Remove

```powershell
python vcli-admin.py --host $HostIp --user dilukhin --auth key --key $Key remove REMOVE
```

Проверить:

- runtime и VPN-пакеты удалены;
- сохранённые данные в `/opt/vpn-admin` и `/etc/wireguard` соответствуют
  документированному поведению;
- SSH и Cloud Backup agent продолжают работать;
- повторный `init` способен восстановить рабочий сервис.

### 16.2 Purge

`purge PURGE` выполнять только если принято решение уничтожить все данные
LanFabric и затем восстановить baseline из Cloud Backup. Это не обязательный
приёмочный тест.

После purge использовать `check_lanfabric_removed.sh`, учитывая повреждённую
кодировку части русских сообщений в текущей версии скрипта.

## 17. Откат из Cloud Backup

Откат перезаписывает состояние существующей ВМ и требует отдельного
подтверждения. Не запускать его для простой проверки команды.

Предварительные условия:

- Backup ID повторно получен через API;
- тестовые артефакты и журналы сохранены вне ВМ;
- принято решение потерять изменения после `2026-07-25T13:06:50Z`;
- нет активных VPN-клиентов;
- известен рабочий SSH-ключ;
- политика резервного копирования не привязана.

Команда восстановления:

```powershell
yc --profile default backup backup recover --source-backup-id $BackupId --destination-instance-id $VmId
```

Контроль восстановления:

```powershell
yc --profile default backup vm list-tasks $VmId
yc --profile default compute instance get --id $VmId
yc --profile default backup backup get --backup-id $BackupId
```

Дождаться `COMPLETED` и `result_code: OK`. После восстановления проверить:

- ВМ имеет ожидаемый статус;
- SSH по `id_yandex_vm` работает;
- агент Cloud Backup зарегистрирован;
- автоматическая политика не появилась;
- состояние LanFabric соответствует baseline на момент копии;
- временная IAM-роль не появилась.

Если результат восстановления отличается от ожидаемого, не удалять ВМ, диск
или копию и не запускать повторное восстановление до анализа.

## 18. Создание нового ручного baseline

Новый baseline создаётся только после принятия результатов тестов. Использовать
одну из существующих политик как механизм ручного запуска, затем обязательно
отвязать её.

Пример с `Default weekly`:

```powershell
$PolicyId = "cdgczpinwclnk7d66d4k"
yc --profile default backup policy apply $PolicyId --instance-ids $VmId
yc --profile default backup policy execute $PolicyId --instance-id $VmId
yc --profile default backup vm list-tasks $VmId
yc --profile default backup backup list
yc --profile default backup policy revoke $PolicyId --instance-ids $VmId
yc --profile default backup policy list-applications $PolicyId
```

Копия принимается только после `COMPLETED`, `result_code: OK`, ненулевого
`size` и проверки принадлежности к `$VmId`. Пустой вывод
`list-applications` подтверждает отсутствие расписания для ВМ.

Старую копию не удалять автоматически. Решение о её удалении принимается
отдельно после проверки новой копии и расчёта стоимости хранения обеих копий.

## 19. Итоговый отчёт

Для каждого прохода сохранить в `reports/` рабочего пространства отдельный
отчёт со следующими полями:

```text
Дата и время:
Git commit:
Версия клиента:
Версия сервера:
VM ID:
Публичный IP:
Backend:
Backup ID до теста:
Пройденные этапы:
Пропущенные этапы и причины:
Фактические результаты:
Дефекты:
Изменения YC/IAM/firewall:
Состояние политики Cloud Backup:
Итоговый статус ВМ:
Решение: оставить / исправить / откатить:
```

В отчёт не включать приватные ключи, пароли и полные VPN-конфиги.
