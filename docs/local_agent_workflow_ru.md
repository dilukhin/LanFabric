# LanFabric — Local Agent Workflow

Статус: действующий workflow для OpenCode  
Дата: 2026-08-20

## 1. Роль агента

OpenCode — bounded local executor, а не основной архитектор проекта.

ChatGPT Web уже должен определить цель, архитектурные решения, границы и критерии готовности.

Агент:

- выполняет только указанную локальную работу;
- не расширяет scope;
- не выбирает самостоятельно новую архитектуру/зависимости;
- не продолжает в «следующий логичный этап»;
- при новой развилке возвращает решение в ChatGPT Web.

## 2. Канонический workspace

```text
C:\Users\Dima\Projects\LanFabricRoot\
├─ AGENTS.md
├─ LanFabric\          # Git worktree: dilukhin/LanFabric
├─ docs\               # локальные Project Settings/Sources helpers
├─ reports\            # итоговые отчёты агента; evidence only
├─ stash\              # пакеты/prompts/exports; non-authoritative
├─ temp\               # временные E2E/test artifacts
├─ trash\              # карантин; не чистить автоматически
└─ .agent-safety\      # safety state/evidence
```

В репозитории дополнительно существуют `.agents`, `.opencode`, `_bmad`, `_bmad-output` и возможная `.agent-safety`.

Не смешивать workspace root и Git repository root.

## 3. Что читать перед работой

Для существенной задачи:

1. workspace `AGENTS.md`;
2. repo `AGENTS.md`;
3. `_bmad-output/project-context.md`;
4. документы, явно указанные в task card.

Не загружать весь BMAD-корпус без необходимости.

## 4. Git

Перед изменением:

```text
git status --short
git branch --show-current
git rev-parse HEAD
```

Правила:

- dirty/unexpected state не уничтожать;
- запрещены convenience `git reset --hard`, `git clean -f/-fd`, force push;
- не удалять неизвестные файлы ради clean tree;
- remote write (`push`, merge, force) по умолчанию не выполнять;
- read-only `fetch` и `ff-only` синхронизация допустимы только если task это требует и worktree безопасен;
- если expected HEAD/ancestry не совпадает — остановиться и отчитаться.

GitHub remote publication по умолчанию выполняет ChatGPT Web через Connector.

## 5. Универсальная безопасность действий

Для каждого non-read-only действия:

1. определить точный target/environment;
2. оценить риск, обратимость и blast radius;
3. определить `expected_state`;
4. при необходимости сохранить checkpoint/rollback;
5. выполнить минимальное атомарное действие;
6. проверить `actual_state`.

Если `actual_state != expected_state` существенно:

- прекратить mutation path;
- перейти к read-only diagnostics;
- не компенсировать delete/reset/overwrite/force/retry-loop;
- сформировать evidence для Web.

## 6. Security-sensitive зоны

Без отдельного task/gate не менять:

- SSH trust / authorized_keys;
- sudoers;
- iptables/firewall;
- systemd;
- SQLite schema;
- генерацию/удаление ключей;
- `init/remove/purge/trust/untrust`;
- Yandex Cloud IAM, service-account keys, firewall, disks, backup restore, resource sizing/cost.

Не выполнять реальные destructive server/cloud действия только потому, что команда технически доступна.

## 7. Yandex Cloud

Применяется `docs/yc_agent_policy_ru.md`.

Критически:

- использовать только команду `yc` из PATH;
- не искать и не запускать «настоящий» `yc.exe` в обход guard;
- не читать `%USERPROFILE%\.config\yandex-cloud`;
- не выполнять `yc config list`, `yc config profile get`, `yc config get service-account-key`;
- не выводить токены/ключи в отчёт;
- approval guard не обходить.

## 8. Таймауты и зависимые операции

SSH, `yc`, package manager, service waits и иные внешние операции не должны висеть бесконечно.

Task должен задавать timeout. Если не задан:

- не запускать потенциально бесконечный loop;
- применять разумный конечный timeout инструмента;
- после timeout собрать read-only evidence и остановить affected step.

Не повторять идентичную неработающую попытку без нового основания.

## 9. Результаты и артефакты

Итоговый отчёт хранить вне Git repo:

```text
C:\Users\Dima\Projects\LanFabricRoot\reports\
```

Временные raw artifacts:

```text
C:\Users\Dima\Projects\LanFabricRoot\temp\
```

Пакеты для обмена Web <-> Agent:

```text
C:\Users\Dima\Projects\LanFabricRoot\stash\
```

Не создавать служебные отчёты внутри repository worktree, если task явно не требует repository documentation.

## 10. Stop conditions

Остановить affected task и вернуть управление Web, если:

- отсутствует обязательный файл/credential/tool;
- branch/HEAD/worktree не соответствует task assumptions;
- нужен новый architecture/security/product decision;
- требуется изменить forbidden scope;
- реальный cloud/server state неожидан;
- потерян независимый SSH-доступ;
- backup/rollback не подтверждён;
- проверка не может быть выполнена;
- после двух ограниченных исправлений одна и та же проверка остаётся красной.

Формат отчёта: `docs/task_report_protocol_ru.md`.
