# LanFabric — Yandex Cloud Policy для локального агента

Статус: обязательная policy boundary  
Дата: 2026-08-20

## 1. Цель

Не допустить утечки YC credentials, случайных дорогостоящих или разрушительных операций и обхода пользовательского контроля при работе OpenCode с Yandex Cloud.

## 2. Единственная точка входа

Локальный агент вызывает только:

```text
yc ...
```

из текущего `PATH`.

Запрещено:

- искать реальный `yc.exe`;
- запускать его по абсолютному пути;
- копировать/переименовывать его для обхода guard;
- менять PATH/окружение с целью обхода guard;
- читать YC config/key files напрямую;
- отключать признаки agent-mode;
- обходить approval mechanism.

Guard является обязательным предохранителем, даже если агент считает команду безопасной.

## 3. Секретные команды — hard deny

Агент не выполняет и не просит вывести:

```text
yc config list
yc config profile get ...
yc config get service-account-key
yc iam key ...
yc iam api-key ...
```

Также запрещено читать:

```text
%USERPROFILE%\.config\yandex-cloud\
```

или исходные JSON service-account keys.

Если для задачи нужны сведения о профиле, использовать только конкретные несекретные getters либо рабочие read-only resource commands.

## 4. Классы операций

### Read-only

Допускаются guard-policy без отдельного destructive approval, если task разрешает cloud discovery:

- `get/list/status`;
- безопасная инвентаризация VM/disk/network/backup;
- чтение текущего состояния ресурса;
- проверки, не меняющие IAM/firewall/resource state.

### State mutation

Запуск/остановка VM, backup start, attach/detach и подобные обратимые операции выполняются только если они явно входят в task и guard разрешил/получил требуемое approval.

### High risk

Отдельное явное разрешение пользователя требуется для:

- create/delete VM/disk/snapshot/backup;
- restore;
- resize/смена класса ресурсов;
- public IP/network/firewall изменения;
- IAM role binding;
- service-account/key/API-key operations;
- действий, способных заметно изменить стоимость;
- удаления или замены recovery path.

## 5. Test VM

`dilyavm` — тестовый ресурс, но это не означает unlimited destructive access.

Перед E2E:

- перечитать фактический VM state;
- подтвердить независимый SSH access;
- подтвердить существование recovery/backup, если тест требует rollback;
- проверить актуальный public IP/IDs;
- не считать старый test plan доказательством текущего cloud state.

## 6. Неожиданное состояние

Если:

- resource ID/name не совпал;
- появился неизвестный ресурс;
- backup отсутствует/невалиден;
- SSH recovery path потерян;
- guard классифицировал команду неожиданно;
- command output содержит признаки секрета,

то mutation path прекращается.

Собрать только безопасное read-only evidence и вернуть вопрос ChatGPT Web.

## 7. Отчёты

Нельзя помещать:

- private keys;
- service-account key JSON;
- IAM/OAuth tokens;
- authorization headers;
- VPN `PrivateKey`;
- полный YC config.

Допустимы resource IDs, имена, статусы, размеры, timestamps и безопасные error messages, если они нужны для воспроизведения.
