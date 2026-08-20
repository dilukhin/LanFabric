# LanFabric — Task Card и Agent Report Protocol

Статус: обязательный формат для нетривиальных локальных задач  
Дата: 2026-08-20

Этот документ описывает компактный execution contract для локального агента. Он использует идеи bounded task/BMAD/OpenSpec-lite для предсказуемости, но не требует от OpenCode запускать BMAD/OpenSpec workflow или изучать методологию целиком.

## 1. Task ID

Формат:

```text
LF-YYYYMMDD-NN
```

Пример: `LF-20260820-01`.

Один Task ID соответствует одной bounded-задаче.

## 2. Compact bounded task card

Нетривиальная локальная задача агенту должна содержать только необходимые поля из следующего контракта:

```text
Task ID:
Цель:

Контекст:
- repository:
- workspace:
- expected branch:
- expected HEAD:
- документы/входные файлы для чтения:

Allowed scope:
- ...

Forbidden scope:
- ...

Требования:
1. ...

Проверки:
1. ...

Timeout policy:
- ...

Acceptance criteria:
- ...

Stop conditions:
- ...

Отчёт:
- path:
- обязательные поля:
```

Не включать поля и методологические материалы, которые не нужны конкретному исполнителю.

Если exact HEAD не требуется, task должен явно сказать, какое правило синхронизации допустимо.

Если task является GitHub fallback из-за недоступной Connector-операции, дополнительно обязательно указать:

```text
GitHub fallback:
- причина fallback / недоступная Connector-операция:
- remote repository:
- разрешённые git/gh операции:
- запрещённые remote операции:
- expected remote branch/HEAD:
- файлы/архив, подготовленные Web:
- read-back/evidence, который нужно вернуть:
```

Разрешение `git`/`gh` действует только для перечисленных операций этой task card.

## 3. Перед первым изменением

Агент фиксирует:

- timestamp;
- workspace/repository;
- branch;
- HEAD;
- `git status --short`;
- релевантные tool/runtime versions;
- для внешнего ресурса — его безопасную идентификацию без секретов.

Для GitHub fallback дополнительно зафиксировать безопасное подтверждение, что требуемый remote доступен и аутентифицирован, не выводя credentials.

## 4. Итоговый отчёт

Markdown report:

```text
# <Task ID> — отчёт

## 1. Цель
## 2. Исходное состояние
- branch
- HEAD
- worktree
- external state

## 3. Выполненные действия
- команда/операция
- target
- exit/result
- expected_state
- actual_state

## 4. Изменённые файлы
- path
- краткое изменение

## 5. Проверки
- check
- PASS/FAIL/SKIPPED/BLOCKED
- evidence

## 6. Таймауты/повторы
## 7. Артефакты
## 8. Риски и отклонения
## 9. Нерешённые решения для ChatGPT Web
## 10. Финальное состояние
- branch
- HEAD
- worktree
- external state
```

При GitHub fallback отдельно перечислить выполненные remote операции и данные для Web-side read-back.

## 5. Правила отчёта

- Не вставлять секреты.
- Не вставлять гигантские raw logs в основной report; сохранять отдельно и ссылаться на path.
- Явно писать `SKIPPED`/`BLOCKED`; отсутствие строки не означает PASS.
- Указывать timeout и что именно ожидалось.
- Отдельно фиксировать ручные действия пользователя.
- Не объявлять gate закрытым, если task не дал агенту право принимать такое решение.
- Не расширять разрешённые `git`/`gh`-операции по собственной инициативе.
- Решение о closure архитектурного/security/E2E gate принимает ChatGPT Web после review evidence.

## 6. Артефакты

По умолчанию:

```text
reports\<Task-ID>_report_ru.md
temp\<Task-ID>\...
stash\<Task-ID>\...   # transport package при необходимости
```

Служебные отчёты не коммитить в repository.
