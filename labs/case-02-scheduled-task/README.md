# LAB-02 — Scheduled Task Persistence

## Общие сведения

**Статус:** Завершён.

При выполнении теста **Atomic Red Team T1053.005-1 — Scheduled Task Startup Script** созданы задачи `T1053_005_OnLogon` и `T1053_005_OnStartup` с командой `cmd.exe /c calc.exe`. Создание процессов `schtasks.exe` подтверждено Sysmon Event ID 1, регистрация обеих задач — TaskScheduler Event ID 106.

При первом запуске события регистрации задач не поступали в Wazuh, поскольку сбор журнала TaskScheduler не был настроен. После устранения пробела в телеметрии события стали поступать в Wazuh и обнаруживаться встроенным правилом `67014`. Разработка собственного правила не потребовалась.

**Вердикт:** True Positive — Authorized Attack Simulation. **Критичность:** Low.

## Лабораторная среда

- Windows 11, агент `WIN11-LAB`;
- Sysmon;
- Wazuh Agent и Wazuh SIEM;
- Atomic Red Team.

## Дерево процессов

Оба процесса `schtasks.exe` запущены одним родительским `cmd.exe`:

```text
cmd.exe PID 5984
├── schtasks.exe PID 7380
│   └── Создание T1053_005_OnLogon
└── schtasks.exe PID 6432
    └── Создание T1053_005_OnStartup
```

Строки создания задач обозначают выполняемые команды, а не дочерние процессы. PID взяты из полей `data.win.eventdata.processId` и `parentProcessId` событий Sysmon; у обоих процессов совпадает `parentProcessGuid`.

## Хронология событий

Дата событий — 14.10.2026.

| Время (UTC) | Источник / Event ID | Подтверждённое событие |
| --- | --- | --- |
| 11:16:51.598 | Sysmon Event ID 1 | Создан `schtasks.exe` PID 7380 для OnLogon, Parent PID 5984 |
| 11:16:51.641 | TaskScheduler Event ID 106 | Зарегистрирована задача `T1053_005_OnLogon` |
| 11:16:51.648 | Sysmon Event ID 1 | Создан `schtasks.exe` PID 6432 для OnStartup, Parent PID 5984 |
| 11:16:51.688 | TaskScheduler Event ID 106 | Зарегистрирована задача `T1053_005_OnStartup` |

## Анализ команд и задач

Команды создания задач из событий Sysmon:

```text
schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"
```

| Задача | Триггер | Команда | Учётная запись выполнения |
| --- | --- | --- | --- |
| `T1053_005_OnLogon` | Вход пользователя (`/sc onlogon`) | `cmd.exe /c calc.exe` | `soc` |
| `T1053_005_OnStartup` | Запуск Windows (`/sc onstart`) | `cmd.exe /c calc.exe` | `SYSTEM` (`/ru system`) |

Учётная запись выполнения OnLogon указана по результату `schtasks /query`; вывод этой проверки в Evidence не приложен.

Создание двух запланированных задач подтверждено событиями регистрации. Задача OnLogon запускается при входе пользователя, а OnStartup настроена на запуск при старте Windows с правами `SYSTEM`. Такой механизм может использоваться для закрепления в системе и автоматического выполнения команд. Фактический запуск задач и `calc.exe` в телеметрии не наблюдался.

### Обнаружение Wazuh

Все четыре JSON экспортированы из `wazuh-alerts-4.x-2026.10.14`.

| Источник | Правило | Level | Description |
| --- | --- | --- | --- |
| Sysmon Event ID 1, оба процесса `schtasks.exe` | `92032` | 3 | `Suspicious Windows cmd shell execution` |
| TaskScheduler Event ID 106, обе регистрации | `67014` | 3 | `Task Scheduler: .` |

## Индикаторы атаки (IOA)

1. Создание задач через `schtasks /create` с триггерами `/sc onlogon` и `/sc onstart`.
2. Настройка запуска `cmd.exe /c calc.exe` через `/tr`.
3. Указание `/ru system` для задачи `T1053_005_OnStartup`.
4. Регистрация обеих задач, подтверждённая TaskScheduler Event ID 106.

Признаки описывают наблюдаемую активность; в данном случае она относится к санкционированной симуляции.

## Сопоставление с MITRE ATT&CK

| Поле | Значение |
| --- | --- |
| Техника | T1053.005 — Scheduled Task/Job: Scheduled Task |
| Фокус расследования | Persistence — создание задач с триггерами входа и запуска Windows |
| Тактики в оповещении правила `67014` | Execution, Persistence, Privilege Escalation |

Из признаков, связанных с Privilege Escalation, в кейсе зафиксирована только настройка выполнения задачи от `SYSTEM`; фактическое повышение привилегий не наблюдалось.

## Вердикт

**Вердикт:** True Positive — Authorized Attack Simulation.

**Критичность:** Low — санкционированная учебная симуляция.

Создание и регистрация задач подтверждены событиями Sysmon и TaskScheduler. Активность сгенерирована в рамках санкционированного теста Atomic Red Team. Настройка задачи от `SYSTEM` требует внимания при анализе аналогичной активности вне лаборатории, но здесь не является признаком компрометации. Level 3 — уровень сработавших правил Wazuh; итоговую критичность он не определяет.

## Пробел в телеметрии

Первоначально журнал `Microsoft-Windows-TaskScheduler/Operational` был отключён (`enabled: false`), а в локальной конфигурации Wazuh Agent не было его сбора, поэтому регистрация задач в SIEM не отображалась.

Выполненные шаги:

1. Включён журнал TaskScheduler/Operational.
2. В `ossec.conf` добавлен сбор этого канала с `log_format=eventchannel`.
3. Перезапущен Wazuh Agent.
4. Тест Atomic Red Team выполнен повторно.
5. Проверено поступление Event ID 106 и срабатывание встроенного правила `67014` для обеих задач.

Пробел в телеметрии был вызван отсутствием сбора событий TaskScheduler, а не отсутствием правила обнаружения. Снимки конфигурации не приложены; результат настройки подтверждают JSON 03–04 и скриншот.

## Исходные материалы

### JSON-события

- [01-schtasks-onlogon.json](evidence/01-schtasks-onlogon.json) — Sysmon Event ID 1: `schtasks.exe` PID 7380, команда создания OnLogon, правило `92032`, Level 3.
- [02-schtasks-onstartup.json](evidence/02-schtasks-onstartup.json) — Sysmon Event ID 1: `schtasks.exe` PID 6432, команда создания OnStartup с `/ru system`, правило `92032`, Level 3.
- [03-task-registered-onlogon.json](evidence/03-task-registered-onlogon.json) — TaskScheduler Event ID 106: регистрация OnLogon, правило `67014`, Level 3.
- [04-task-registered-onstartup.json](evidence/04-task-registered-onstartup.json) — TaskScheduler Event ID 106: регистрация OnStartup, правило `67014`, Level 3.

### Скриншоты

- [01-scheduled-task-alerts.png](screenshots/01-scheduled-task-alerts.png) — две записи регистрации задач Event ID 106 для `WIN11-LAB` в Wazuh Dashboard.
