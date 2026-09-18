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

## 6. Утверждённый порядок дальнейших работ

План принят пользователем 2026-09-18. Выполнять пункты последовательно, не переходя к следующему автоматически без review результата предыдущего.

### 1. P1 — сделать AWG устойчивым к cold boot

Issue #12.

Цель: ранее инициализированный `awg` runtime должен штатно подниматься после загрузки Ubuntu без ручного `vcli start`, без повторного `init`, регенерации ключей или silent fallback.

Это наиболее прямое эксплуатационное улучшение после закрытого deployment/E2E цикла.

### 2. P1/P2 — Android как полноценный L3-узел

Issue #11 `Добавить Android как полноценный узел локальной L3-сети LanFabric`.

Цель: получить воспроизводимый Android onboarding с отдельным user/key/address, безопасной доставкой конфигурации и физическим Windows + Android E2E. Android должен видеть VPN gateway и разрешённые политикой узлы, а его internet policy должна проверяться отдельно для split/full-tunnel.

### 3. P2 — дополнительные security/destructive gates из test plan

В `TEST_PLAN_YC_DILYAVM.md` остаются необязательные/отдельно gated сценарии, которые не следует запускать автоматически после успешного E2E:

- `trust/untrust`;
- `remove`;
- `purge`;
- backup restore и иные recovery/destructive проверки.

Каждый такой сценарий требует отдельной bounded task и явного подтверждения.

### 4. Research — direct LAN gaming без центрального data-path

Issue #8: STUN/ICE/NAT traversal/relay research. Это отдельное архитектурное исследование и не должно смешиваться с hardening текущего `wg/awg` runtime.

## 7. Tooling follow-up

Во время two-host E2E выявлены межпроектные Windows safety/workflow наблюдения:

- PowerShell interpolation может исказить literal service target с `$` и дать false-negative verifier;
- исполнитель может опереться на устаревшую remembered форму `safe` CLI.

Они вынесены из LanFabric в `dilukhin/agent-toolchain` issue #58. LanFabric runtime менять для этого не требуется.
