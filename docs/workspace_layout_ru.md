# LanFabric — Workspace Layout

Статус: каноническая локальная раскладка  
Дата: 2026-08-20

По текущему окружению canonical root:

```text
C:\Users\Dima\Projects\LanFabricRoot\
```

## 1. Целевая структура

```text
LanFabricRoot\
├─ AGENTS.md
├─ LanFabric\
│  ├─ AGENTS.md
│  ├─ README.md
│  ├─ docs\
│  ├─ tests_local\
│  ├─ _bmad\
│  ├─ _bmad-output\
│  ├─ .agents\
│  └─ .opencode\
├─ docs\
│  ├─ github_project_bootstrap.md
│  └─ chatgpt_project_instructions_seed_ru.txt
├─ reports\
├─ stash\
├─ temp\
├─ trash\
└─ .agent-safety\
```

## 2. Назначение областей

### `LanFabric\`

Git worktree `dilukhin/LanFabric`.

Только то, что должно путешествовать с репозиторием: runtime code, tests, README, BMAD/project-context, agent config, repository documentation.

### workspace `docs\`

Только локальные helpers для ChatGPT Project:

- настроенный `github_project_bootstrap.md`;
- копия активного Project Instructions seed.

Не создавать здесь вторую authoritative копию repository docs.

### `reports\`

Итоговые отчёты локального агента и E2E. Это evidence, не источник истины.

### `stash\`

Транспортные и временные пакеты: prompts, ZIP, импорт/экспорт между ChatGPT Web и агентом, например `yc-guard`.

Новый файл в stash не становится нормативным автоматически.

### `temp\`

Временные test/E2E данные, expected/rollback snapshots, скачанные промежуточные artifacts.

Не использовать как долгосрочную документацию.

### `trash\`

Карантин/ручная зона восстановления. Агент не очищает её автоматически.

### `.agent-safety\`

Safety audit/evidence/recovery state. Не переносить и не очищать в рамках обычной feature-задачи.

## 3. Существующие legacy-файлы

В текущем workspace уже есть старые документы в root `docs\`, старые `reports`, E2E-данные в `temp`, архивы в `stash`, а также `.agent-safety` и внутри workspace root, и внутри repo.

На этапе настройки workflow:

- ничего из этого не удалять;
- не объединять две `.agent-safety`;
- не удалять `NUL`, `__pycache__`, старые ZIP или старые отчёты автоматически;
- не переносить legacy-документы без отдельного review.

После стабилизации workflow cleanup выполняется отдельной bounded-задачей с перечнем конкретных файлов.

## 4. Source-of-truth

```text
GitHub/repo state -> implementation truth
repo docs         -> durable project/workflow truth
_bmad-output      -> agent implementation constraints
workspace docs    -> ChatGPT Project configuration helpers
reports/stash/temp/trash -> evidence/temporary only
```
