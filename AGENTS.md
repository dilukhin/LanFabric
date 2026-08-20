# LanFabric — правила для AI-агентов

Этот файл — короткий маршрутизатор контекста. Подробные правила не дублируются здесь.

Перед существенной работой прочитать:

1. `_bmad-output/project-context.md` — обязательные implementation constraints.
2. `docs/project_baseline_ru.md` — устойчивые факты и границы проекта.
3. `docs/local_agent_workflow_ru.md` — правила локального агента.
4. `docs/task_report_protocol_ru.md` — формат bounded task и итогового отчёта.
5. Для работы с Yandex Cloud — `docs/yc_agent_policy_ru.md`.
6. Для E2E на тестовой ВМ — `TEST_PLAN_YC_DILYAVM.md`.

Основные правила:

- ChatGPT Web — основной архитектор, reviewer и владелец GitHub-операций.
- Локальный агент — bounded executor: выполняет только явно поставленную локальную задачу.
- Не расширять scope и не принимать архитектурные, security или product-решения самостоятельно.
- До изменений проверить `git status`; грязное или неожиданное состояние не уничтожать и не «лечить» reset/clean/delete.
- Не менять `__version__`, README, public CLI contract, SSH/sudo/iptables/systemd/SQLite trust boundaries без явного задания.
- Runtime: Python 3.12+, только стандартная библиотека.
- Комментарии, help, сообщения и отчёты — на русском.
- Для GitHub remote writes по умолчанию используется ChatGPT Web через GitHub Connector. Локальный агент не push/merge/force-push без отдельного явного задания.
- Для Yandex Cloud локальный агент вызывает только `yc` из PATH. Запрещено искать/запускать настоящий `yc.exe` в обход guard, читать конфигурацию YC и выводить секреты.
- Любое неожиданное состояние: остановить mutation path, собрать read-only evidence, сформировать отчёт для ChatGPT Web.
