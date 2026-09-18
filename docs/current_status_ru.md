# LanFabric — текущий статус

Дата фиксации: 2026-09-18

Этот документ хранит изменяемый operational/E2E status. Долговечные инварианты проекта остаются в `project_baseline_ru.md`, а фактическая реализация определяется текущим GitHub state.

## 1. Текущий релиз

Проверенный runtime release:

```text
0.0.17
```

Release deployment на test VM `dilyavm` выполнен штатным `patch` с `0.0.16` до `0.0.17` без `init`.

Подтверждено:

- remote `vsrv-admin.py` имеет версию `0.0.17`;
- local/remote SHA серверного модуля совпал в deployment gate;
- backend остаётся `awg`;
- users/policies при patch не изменились;
- stale temporary sudoers cleanup path не воспроизвёл прежний client-side `PermissionError`;
- exact temporary sudoers count до/после deployment оставался `0`;
- независимый SSH-доступ по отдельному management key сохранён.

## 2. Закрытые gates

### LF-20260909-03 — deployment `0.0.16 -> 0.0.17`

Статус: `PASS`.

Patch выполнен один раз. После cold boot VM AWG runtime ожидаемо требовал отдельного штатного `vcli start`; это вынесено в следующий gate и не признано regression patch.

### LF-20260916-01 — восстановление AWG runtime

Статус: `PASS`.

Одним штатным `vcli start` подтверждено:

- `status=RUNNING`;
- `health=PASS`;
- `wg0` `UP/LOWER_UP`;
- `awg show wg0` PASS;
- UDP 51820 listening;
- IPv4 forwarding включён;
- users/policies unchanged;
- independent SSH PASS;
- `agent-safe blocked=false`.

### LF-20260916-02 — two-host Windows E2E

Статус: `PASS`.

Одновременно использованы два физических Windows-хоста с разными VPN identities:

```text
DIMA-HP         -> bob-e2e   -> 10.8.0.4 -> internet=ДА, full-tunnel
DESKTOP-M22DPBH -> alice-e2e -> 10.8.0.2 -> internet=НЕТ, split-tunnel
```

Подтверждено:

- оба туннеля одновременно активны;
- оба peers имеют fresh simultaneous handshake;
- оба клиента видят `10.8.0.1`;
- `bob-e2e` выходит в интернет через public IP VM;
- `alice-e2e` сохраняет обычный direct internet и не становится full-tunnel;
- server `status`/`health` остаются PASS при двух одновременных клиентах;
- legacy `bob` остаётся BLOCKED;
- после OFF обычная маршрутизация обоих Windows-хостов восстановлена.

## 3. Management path regression

Ранее критичный Windows full-tunnel сценарий повторно проверен на `0.0.17`.

При включённом `bob-e2e` на DIMA-HP:

- effective full-tunnel routes: `0.0.0.0/1` и `128.0.0.0/1`;
- отдельный Endpoint `/32` route остаётся через обычный LAN gateway;
- TCP 22 к public VM Endpoint доступен;
- strict SSH с `IdentitiesOnly=yes` проходит;
- `sudo -n true` проходит.

Management-path regression не воспроизведён.

## 4. Известные ограничения, не блокирующие текущий PASS

### Windows ICMP на Alice

В two-host E2E:

```text
alice-e2e -> bob-e2e  PASS
bob-e2e   -> alice-e2e ICMP timeout
```

Server-side evidence подтвердил доставку Echo Request на `wg0`; server forwarding разрешён, но Echo Reply от Alice отсутствовал. Причина локализована до Windows Firewall на `DESKTOP-M22DPBH`: tunnel network category `Public`, а найденные inbound ICMP Allow rules применялись только к `Private` profile.

Windows firewall не менялся. Это не считается дефектом server forwarding LanFabric. Если потребуется обязательный двусторонний ICMP как UX/diagnostic contract, изменение конкретного Windows firewall/profile должно быть отдельной задачей.

### AWG после cold boot

Для текущего manual `awg` runtime нет отдельного systemd startup unit. После cold boot VM требуется штатный `vcli start`.

Отдельная задача: issue #12 `Автоматически поднимать AWG runtime после cold boot сервера`.

### Synthetic stale sudoers fixture

Deployment подтвердил исправленный cleanup path без прежнего `PermissionError`, но специально созданный synthetic stale sudoers artifact не использовался. Такой security-sensitive fixture не требуется для уже закрытого deployment gate и должен выполняться только отдельной задачей, если понадобится дополнительный integration proof удаления.

## 5. Текущее состояние стенда

По решению пользователя test VM `dilyavm` оставлена `RUNNING`.

Последнее подтверждённое состояние после two-host E2E:

```text
VM:       RUNNING
backend:  awg
runtime:  RUNNING
health:   PASS
wg0:      UP
clients:  alice-e2e OFF, bob-e2e OFF после E2E
safe:     blocked=false
```

Тарификация VM продолжается; автоматически останавливать VM не нужно.

## 6. Текущий план после независимой инспекции

Пользователь 2026-09-18 принял уточнение порядка работ и поручил включить документы в PR #20 и выполнить слияние. Канонический подробный план: [work_plan_ru.md](work_plan_ru.md).

Ближайший этап остаётся **#12 — AWG после cold boot**, с зависимостями:

1. В диалоге «Архитектурный обзор AWG lifecycle» уточнить контракт по замечаниям C1–C8.
2. Выполнить #17 — строгое чтение данных и проверяемую диагностику.
3. Выполнить #15 — безопасное применение и сериализацию изменения состояния.
4. Выполнить необходимую для root-службы часть #16.
5. Подключить автозапуск #12 к исправленному пути восстановления.
6. Выполнить отдельную приёмку cold boot без ручного start/sync.

После приёмки: #11 Android → оставшиеся части #16 и #18/отдельные проверки безопасности → #19 backend wg → #8 STUN/P2P.

Не требуется сначала закрывать целиком все новые issues. Частично выполненный #16 остаётся открытым до проверки остальных критериев. Номер следующего выпуска и миграция ещё не определены; текущий выпуск **0.0.17** не изменён.

Продолжение — архитектурное уточнение в существующем диалоге AWG, затем небольшие последовательные изменения по этому плану. Сам по себе данный документ не разрешает операции на VM или изменение версии.

## 6.1. Кандидат 0.0.18

После архитектурного review C1–C8 начата реализация кандидата **0.0.18**:

- #17: строгие источники состояния и немутирующая диагностика;
- #15: fail-closed AWG apply и общая сериализация мутаций;
- обязательная часть #16: root-owned state/entrypoint и атомарная установка server module;
- #12: явный `autostart enable|disable|status` и boot-only `lanfabric-awg.service`.

Принятый административный контракт: новый AWG `init` включает autostart после успешного запуска; `patch` не включает его; `start` и `stop` persistent-настройку не меняют; `autostart disable` не останавливает текущий runtime; remove/purge удаляют unit.

Проверенный стендовый release **не изменился**: на `dilyavm` по последнему evidence остаётся 0.0.17. Код 0.0.18 пока нельзя считать развёрнутым или принятым до локального PASS, bounded deployment и отдельного cold-boot E2E. VM/systemd/firewall в ходе Web-разработки не изменялись.

## 7. Tooling follow-up

Во время two-host E2E выявлены межпроектные Windows safety/workflow наблюдения:

- PowerShell interpolation может исказить literal service target с `$` и дать false-negative verifier;
- исполнитель может опереться на устаревшую remembered форму `safe` CLI.

Они вынесены из LanFabric в `dilukhin/agent-toolchain` issue #58. LanFabric runtime менять для этого не требуется.

## 8. Результат независимой инспекции 2026-09-18

[Обзор](reviews/LanFabric_project_inspection_2026-09-18.md) и [замечания к AWG lifecycle](reviews/LanFabric_awg_lifecycle_corrections_2026-09-18.md) подготовлены в PR #20.

Проверенный исходный master: `51df21abd770dbc47655317d870b4f73e080dc35`, runtime 0.0.17. При документировании плана других открытых PR с исправлениями найденных проблем не обнаружено.

- Локальные проверки в Python 3.12.14: **84/84 PASS**, без failures/errors/expected failures/skipped.
- Дополнительные изолированные проверки: **7/7 наблюдений подтверждены**; это воспроизведение проблем, не доказательство исправления.
- Созданы #15 (отказы и гонки), #16 (права/обновление), #17 (данные/диагностика), #18 (SSH/SCP), #19 (восстановление wg).
- Все перечисленные дефекты и #12 остаются открытыми. PR #20 документирует инспекцию и план; runtime-исправлений не содержит.
- Нового E2E/SSH/YC-прохода в инспекции не было. Ранее принятые результаты из раздела 2 сохраняются, фактическое состояние VM заново не измерялось.

До уточнения диагностики 0.0.17 не считать `health exit=0` достаточным критерием PASS: ошибки могут сообщаться только текстом, а при отсутствии БД создаётся пустая база. Для AWG также подтверждён путь генерации утраченных параметров и риск снятия DROP при частичном отказе sync.
