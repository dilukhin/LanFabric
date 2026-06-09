# LOCAL_TEST_REPORT — LanFabric v0.0.15

**Дата:** 2026-06-09
**Версия клиента:** 0.0.15
**Версия сервера:** 0.0.15
**Python:** 3.14.2 (Windows)
**Реальные SSH/SCP/sudo/systemd/iptables/WG/AWG:** не проверялись

---

## 1. Выполненные проверки

### 1.1 Статические проверки (py_compile)
- vcli-admin.py — синтаксис OK
- vsrv-admin.py — синтаксис OK

### 1.2 Версии
- vcli-admin --version: `vcli-admin 0.0.15`
- vsrv-admin --version: `vsrv-admin 0.0.15`

### 1.3 Help
- --help (main) — 45 строк, команды trust/untrust видны, help на русском
- trust --help, untrust --help, init --help, config --help — все работают
- argparse оставляет английские служебные строки: `usage:`, `positional arguments:`, `options:`, `show this help message and exit` — это штатное поведение argparse, локализация не настроена

### 1.4 Unit/smoke тесты (40 тестов)

| Группа | Тестов | Статус |
|--------|--------|--------|
| A. client_id и marker | 6 | пройдено |
| B. authorized_keys filtering | 8 | пройдено |
| C. SSH command construction | 5 | пройдено |
| D. temporary password session | 4 | пройдено |
| E. sudoers rule | 4 | пройдено |
| F. Known defects (expected failures) | 3 | ожидаемо не пройдены |
| Version parsing | 6 | пройдено |
| Additional checks | 4 | пройдено |

---

## 2. Подтверждённые дефекты (expected failures)

### Дефект 1: ordinary untrust — два SSH-вызова
- **Файл:** vcli-admin.py:900-919
- **Суть:** `cmd_untrust` сначала удаляет authorized_keys marker через `remove_authorized_key_by_marker` (SSH #1), затем отдельным SSH-вызовом вызывает `cleanup_permanent_sudo_trust` (SSH #2).
- **Риск:** Если SSH #1 прошёл, а SSH #2 упал (сетевой сбой, таймаут), SSH-trust уже удалён, а sudo-trust остаётся. Клиент теряет SSH-доступ к управлению, но sudo-правило LanFabric остаётся висеть.
- **Предлагаемое исправление:** Объединить оба вызова в один SSH-сеанс: scp-скрипт, который атомарно удаляет authorized_keys и sudoers, или выполнять cleanup в обратном порядке (сначала sudo, потом authorized_keys).

### Дефект 2: cleanup_stale_temporary_sudo_trust вне sudoers allowlist
- **Файл:** vcli-admin.py:649-693, :591-601
- **Суть:** `cleanup_stale_temporary_sudo_trust` выполняет на сервере `sudo python3 -c "..."`. Правило `sudoers_rule_for_user` разрешает только `/usr/bin/python3 /opt/vpn-admin/vsrv-admin.py *`. Команда `python3 -c` не входит в allowlist.
- **Риск:** Автоматическая очистка просроченных временных sudoers-файлов будет отклонена sudo, так как код выполняется не через `/opt/vpn-admin/vsrv-admin.py`, а через `python3 -c`.
- **Предлагаемое исправление:** Добавить `/usr/bin/python3 -c *` в sudoers rule, либо заменить inline `python3 -c` на вызов `vsrv-admin.py` с отдельной командой очистки.

### Дефект 3: split(':') в inline-скриптах ломает парсинг created-времени
- **Файл:** vcli-admin.py:557, 664, 742
- **Суть:** inline-скрипты разбирают маркер через `marker.split(':')`. Значение `created` содержит время в формате ISO 8601 (напр. `22:10:19Z`) с двоеточиями. При split поле created обрезается до часа (напр. `2026-06-09T22`), минуты и секунды теряются.
- **Риск:** Неверный расчёт TTL-expiry. На машинах с часовым поясом не UTC создаётся дополнительная путаница: обрезанное время парсится `fromisoformat` как local time без timezone. Может привести к преждевременному или запоздалому удалению временных ключей.
- **Предлагаемое исправление:** Заменить `split(':')` на парсинг через регулярное выражение, которое ищет поля вида `key=value`, не ломаясь на двоеточиях внутри value. Например: `re.findall(r'(\w+)=([^:]+)', marker)`.

---

## 3. Задокументированные риски (не expected failures)

### Риск A: StrictHostKeyChecking=no
- **Файл:** vcli-admin.py:91
- `build_ssh_cmd` добавляет `-o StrictHostKeyChecking=no`. Это отключает проверку host key SSH.
- В контексте временных ключей для автоматизации это распространённая практика, но создаёт поверхность для MITM-атаки на этапе trust.

### Риск B: Повторный trust создаёт дубликат ключа
- **Файл:** vcli-admin.py:494-498
- `add_authorized_key_line` использует `grep -Fxq` для проверки существования строки. Поскольку каждый trust генерирует уникальный nonce в маркере, grep не находит существующую строку (она с другим nonce) и добавляет дубликат.
- Это не приводит к немедленной ошибке, но раздувает authorized_keys и может маскировать отзыв старого ключа.

### Риск C: Корреляция очистки stale через ttl > 0
- inline-скрипты проверяют `ttl > 0 and now > created + ttl`. Если поле ttl отсутствует (или равно 0), то `ttl > 0` — False, и проверка created/proverka не выполняется.
- Маркер без ttl не будет удалён автоматически, даже если created непарсибелен.

---

## 4. Что не проверено (требует реальной VPS)

- `add_authorized_key_line` — реальное добавление ключа на сервер через SSH
- `remove_authorized_key_by_marker` — реальное удаление с сервера
- `ensure_local_keypair` — генерация SSH-ключей через ssh-keygen
- `cmd_trust` — полный цикл trust
- `cmd_untrust` — полный цикл untrust
- `setup_temporary_sudo_trust` / `cleanup_temporary_sudo_trust` — sudoers через SSH
- `exec_remote` / `build_ssh_cmd` — реальное SSH-подключение
- `write_sudoers_file` / `visudo` — создание sudoers на сервере
- `cleanup_stale_temporary_sudo_trust` — проверка, что sudo отклонит `python3 -c`

---

## 5. Итог

- Все статические проверки пройдены.
- Все unit/smoke тесты пройдены (40 из 40, включая 3 expected failures, фиксирующих известные дефекты).
- Три дефекта confirmed: untrust через два SSH-вызова, cleanup stale sudoers вне allowlist, split(':') ломает парсинг created.
- Дополнительно задокументированы риски: StrictHostKeyChecking=no, дубликат при повторном trust, некорреляция очистки без ttl.
- Рекомендация на следующий этап: исправить три подтверждённых дефекта; заменить `split(':')` парсинг маркеров на regex; объединить SSH-вызовы в untrust; добавить `python3 -c` в sudoers allowlist.

---

## 6. Подтверждение неизменности

Файлы `vcli-admin.py`, `vsrv-admin.py`, `README.md` **не изменялись** в рамках данной проверки.
