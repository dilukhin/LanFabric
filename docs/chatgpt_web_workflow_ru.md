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
- подготовка ручного/агентского fallback, если нужная Connector-операция недоступна;
- анализ результатов локальных тестов и E2E;
- решение, закрыт ли gate и что делать дальше.

OpenCode не должен получать неразрешённую архитектурную задачу вида «разберись и сделай следующий этап».

BMAD/OpenSpec и project-context относятся прежде всего к уровню проектирования Web. Локальному исполнителю передаётся уже принятое решение и минимально достаточный execution contract.

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
4. Использовать Connector как единственный штатный remote-транспорт ChatGPT Web.

Правила:

- не использовать и не предлагать `git`/`gh` как Web remote fallback;
- наличие shell/`git`/`gh` не считать доказательством доступного и аутентифицированного GitHub remote;
- многофайловый write через Connector: `blob -> tree -> commit -> ref`;
- работать через feature/task branch, не писать прямо в `master`;
- перед `update_ref` перечитать HEAD;
- после write выполнить GitHub-side read-back;
- self-review — `COMMENT`;
- общую GitHub knowledge base заполнять только новым переносимым межпроектным знанием о Connector/API/общем workflow, которого ещё нет в policy/catalog/incidents; project-local рабочие ошибки и недоработки исправлять в самом проекте и не публиковать как knowledge incident;
- квалифицированные knowledge incidents и изменения policy/catalog/schema/profile публиковать в `dilukhin/github-connector-knowledge`, а не в `dilukhin/LanFabric`.

### Если Connector-операция недоступна

Не пытаться заменить её `git`/`gh` внутри Web.

ChatGPT Web должен:

1. Зафиксировать точную недоступную операцию и ошибку.
2. Прекратить соответствующую remote mutation.
3. Подготовить пользователю исполнимый fallback:
   - либо точную ручную инструкцию;
   - либо bounded task card локальному/внешнему агенту.
4. Приложить необходимые файлы или архив, если операция требует подготовленного контента.
5. После выполнения получить evidence/report и выполнить Web-side read-back/review.

Ручная инструкция должна включать repository, branch/expected HEAD, точные команды/операции, проверки результата и stop conditions при необходимости.

Для агентского fallback task card дополнительно должна явно разрешать только нужные `git`/`gh`-операции и содержать repository/workspace, branch/HEAD, allowed/forbidden scope, проверки, timeout, stop conditions и запрет destructive recovery.

## 4. Делегирование локальному агенту

Делегировать только локально необходимую часть.

OpenCode — простой bounded executor, а не второй архитектор и не обязательный BMAD/OpenSpec-агент.

Task должен быть компактным и самодостаточным. Он содержит только необходимые поля:

1. Task ID.
2. Exact workspace/repository path.
3. Expected branch/HEAD или правило синхронизации.
4. Минимальный список файлов/документов для чтения.
5. Цель.
6. Allowed scope.
7. Forbidden scope.
8. Конкретные требования реализации/действий.
9. Команды и проверки.
10. Timeout/non-interactive policy.
11. Acceptance criteria.
12. Stop conditions.
13. Формат и путь итогового отчёта.

Не требовать от агента читать весь `_bmad/`, `.agents/`, `.opencode/` или выполнять BMAD/OpenSpec workflow, если конкретная локальная задача этого не требует.

Если задача затрагивает SSH, server state, YC, backup, firewall, destructive action или GitHub remote fallback — отдельно указать gate и точные разрешённые операции.

## 5. Цикл Web -> Agent/User -> Web

```text
ChatGPT Web
  -> решение / branch / compact bounded task или ручная инструкция
Local Agent / User
  -> выполнение разрешённых локальных/ручных действий
  -> report/evidence + artifacts
ChatGPT Web
  -> review evidence
  -> GitHub read-back / correction / gate closure / next task
```

Пользователь не должен вручную переносить между моделями архитектурные решения. Пользователю остаются операции, которые действительно требуют UI/credential/physical approval или ручного fallback из-за ограничения Connector.

## 6. Review результатов агента/ручного fallback

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
