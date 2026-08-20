# LanFabric — ChatGPT Web Workflow

Статус: действующий workflow  
Дата: 2026-08-20

## 1. Роль ChatGPT Web

ChatGPT Web — основной engineering/reasoning слой проекта.

По возможности в Web выполняются:

- архитектура и design decisions;
- исследование и выбор подхода;
- анализ текущего GitHub state;
- review кода и документации;
- декомпозиция задач;
- подготовка точных изменений;
- GitHub reads/writes через GitHub Connector;
- анализ результатов локальных тестов и E2E;
- решение, закрыт ли gate и что делать дальше.

OpenCode не должен получать неразрешённую архитектурную задачу вида «разберись и сделай следующий этап».

## 2. Загрузка контекста

Начинать с фактического GitHub state.

Для существенной задачи читать только необходимое:

- `README.md` — пользовательский контракт и сценарии;
- `_bmad-output/project-context.md` — implementation constraints;
- `docs/project_baseline_ru.md` — устойчивые инварианты;
- `docs/local_agent_workflow_ru.md` — при делегировании;
- `docs/task_report_protocol_ru.md` — task/report contract;
- `docs/yc_agent_policy_ru.md` — при работе с Yandex Cloud;
- `TEST_PLAN_YC_DILYAVM.md` — при E2E на стенде.

Старые `reports`, `stash`, диалоги и memory используются только как evidence/context и не заменяют проверку текущего HEAD.

## 3. GitHub workflow

Перед GitHub-задачей:

1. Прочитать настроенный `github_project_bootstrap.md` из Project Sources.
2. Через GitHub Connector прочитать runtime bundle из `dilukhin/github-connector-knowledge`.
3. Проверить, что bundle относится к `dilukhin/LanFabric`.
4. Использовать Connector как первичный remote-транспорт.

Правила:

- не пробовать `git`/`gh` как remote «на всякий случай»;
- локальный Git использовать только для подтверждённого checkout, diff/history/tests;
- многофайловый write через Connector: `blob -> tree -> commit -> ref`;
- работать через feature/task branch, не писать прямо в `master`;
- перед `update_ref` перечитать HEAD;
- после write выполнить GitHub-side read-back;
- self-review — `COMMENT`;
- неизвестный новый Connector issue публиковать в knowledge repo отдельным incident PR либо создавать pending incident при реальной невозможности записи.

## 4. Делегирование локальному агенту

Делегировать только локально необходимую часть.

Хороший task содержит:

1. Task ID.
2. Exact workspace/repository path.
3. Expected branch/HEAD или правило синхронизации.
4. Файлы/документы, которые нужно прочитать.
5. Цель.
6. Allowed scope.
7. Forbidden scope.
8. Конкретные требования реализации/действий.
9. Команды и проверки.
10. Timeout/non-interactive policy.
11. Acceptance criteria.
12. Stop conditions.
13. Формат и путь итогового отчёта.

Если задача затрагивает SSH, server state, YC, backup, firewall или destructive action — отдельно указать gate и требуемое подтверждение.

## 5. Цикл Web -> Agent -> Web

```text
ChatGPT Web
  -> решение / branch / bounded task
OpenCode
  -> локальная синхронизация / выполнение / проверки
  -> report + artifacts
ChatGPT Web
  -> review evidence
  -> GitHub write / correction / gate closure / next task
```

Пользователь не должен вручную переносить между моделями архитектурные решения. Пользователю остаются операции, которые действительно требуют его UI/credential/physical approval.

## 6. Review результатов агента

Не принимать фразу «готово» без evidence.

Проверять как минимум:

- стартовые branch/HEAD/status;
- что scope не расширен;
- изменённые файлы;
- executed commands и exit status;
- skipped/blocked checks;
- timeout'ы;
- состояние внешних ресурсов;
- финальные branch/HEAD/status;
- unresolved decisions;
- отсутствие секретов в отчёте.

Если агент встретил unexpected state и импровизировал destructive recovery, результат не принимать автоматически.

## 7. Cloud/E2E

Yandex Cloud — privileged boundary.

- Агент использует только `yc` через guard.
- Web проектирует операцию и определяет допустимый blast radius.
- Read-only discovery отделяется от mutation.
- Восстановление backup, IAM/firewall/resource creation/deletion — отдельные high-risk операции.
- Параметры стенда не считать постоянными; перед прогоном перечитывать фактический cloud state.
