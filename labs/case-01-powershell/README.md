# LAB-01 — Анализ подозрительного PowerShell

## Общие сведения

**Статус:** Завершён.

При выполнении теста **Atomic Red Team T1059.001-17 — PowerShell Command Execution** подтверждена цепочка запуска PowerShell через `cmd.exe` с Base64-кодированной командой (EncodedCommand). В событиях PowerShell Event ID 4104 зарегистрированы обфусцированный ScriptBlock и раскрытая команда `Write-Host 'Hello, from PowerShell!'`.

Wazuh сопоставил события создания процессов со встроенными правилами `92057` (Level 12) и `92032` (Level 3). Для событий PowerShell 4104 (ScriptBlock) оповещения не формировались. Для устранения выявленного пробела в обнаружении разработано собственное правило `100110`.

**Вердикт:** True Positive — Authorized Attack Simulation. **Критичность:** Low.

## Лабораторная среда

Расследование выполнено в изолированной домашней лаборатории:

- Windows 11;
- Wazuh Agent;
- Sysmon;
- PowerShell Script Block Logging;
- Wazuh SIEM.

## Дерево процессов

Подтверждённая цепочка процессов:

```text
powershell.exe PID 3084
└── cmd.exe PID 6516, Parent PID 3084
    └── powershell.exe PID 10128, Parent PID 6516
```

`powershell.exe PID 3084` — сессия PowerShell, из которой запускался тест Atomic Red Team; в событиях у этого процесса только командная строка `powershell.exe` без аргументов, связь с тестом известна из его условий.
Основная эмулируемая подозрительная цепочка: `cmd.exe PID 6516 → powershell.exe PID 10128 -EncodedCommand`.

Командная строка второго PowerShell:

```text
powershell.exe -e <Base64>
```

Полное значение `<Base64>`:

```text
JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA==
```

Декодирование Base64 как UTF-16LE даёт обфусцированный ScriptBlock, приведённый в разделе «Анализ ScriptBlock». Он совпадает с текстом события 4104 в файле 03.

## Хронология событий

Дата событий — 12.10.2026.

| Время (UTC) | Источник / Event ID | Подтверждённое событие | Правило Wazuh |
| --- | --- | --- | --- |
| 12:38:36.896 | Sysmon Event ID 1 | Создан `cmd.exe`, PID 6516, Parent PID 3084 | `92057`, Level 12 |
| 12:38:36.952 | Sysmon Event ID 1 | Создан `powershell.exe`, PID 10128, Parent PID 6516 | `92032`, Level 3 |
| 12:38:39.277 | PowerShell Event ID 4104 | PID 10128 — обфусцированный ScriptBlock | — |
| 12:38:39.352 | PowerShell Event ID 4104 | PID 10128 — ScriptBlock `Write-Host 'Hello, from PowerShell!'` | — |

## Анализ ScriptBlock

Обфусцированный ScriptBlock:

```powershell
& (gcm ('ie{0}' -f 'x')) ("Wr"+"it"+"e-H"+"ost 'H"+"el"+"lo, fr"+"om P"+"ow"+"erS"+"h"+"ell!'")
```

Деобфускация:

| Элемент | Раскрытое значение |
| --- | --- |
| `gcm` | `Get-Command` |
| `'ie{0}' -f 'x'` | `iex` |
| `iex` | `Invoke-Expression` |
| `"Wr"+"it"+"e-H"+"ost"` | `Write-Host` |

Конкатенация строк восстанавливает текст команды, передаваемой в `Invoke-Expression`:

```powershell
Write-Host 'Hello, from PowerShell!'
```

Этот текст зарегистрирован отдельным событием 4104 в том же процессе PID 10128 в 12:38:39.352 UTC, через 75 мс после обфусцированного блока. Event ID 4104 фиксирует ScriptBlock, переданный движку PowerShell; появление раскрытого блока согласуется с тем, что `Invoke-Expression` получил собранную команду. Вывода команды в материалах нет.

## Индикаторы атаки (IOA)

1. `cmd.exe → powershell.exe -EncodedCommand` — в зафиксированной командной строке использована сокращённая форма `-e`.
2. Использование PowerShell -EncodedCommand с Base64-кодированным содержимым.
3. Обфусцированный PowerShell ScriptBlock.
4. `Invoke-Expression`.

## Сопоставление с MITRE ATT&CK

| Поле | Значение |
| --- | --- |
| Техника | T1059.001 — Command and Scripting Interpreter: PowerShell |
| Тактика | Execution |

## Вердикт

**Вердикт:** True Positive — Authorized Attack Simulation.

**Критичность:** Low.

Запуск `cmd.exe` и `powershell.exe -e` подтверждён Sysmon, обфусцированный и раскрытый ScriptBlock — событиями PowerShell 4104. Активность сгенерирована санкционированным тестом Atomic Red Team в изолированной домашней лаборатории. Реального воздействия нет: раскрытая команда `Write-Host 'Hello, from PowerShell!'` выводит строку в консоль. Level 12 у правила `92057` и Level 8 у `100110` — уровни правил Wazuh, они не определяют итоговую критичность.

## Пробел в обнаружении

**Обнаружение.** Wazuh сформировал оповещения по событиям создания процессов (правила `92057` и `92032`). События PowerShell `4104` сохранились в архиве, но не вызвали оповещений — выявлен пробел в обнаружении обфусцированных команд.

**Устранение пробела.** Разработано [собственное правило Wazuh `100110`](detection/custom_powershell_rules.xml) (Level 8). Его срабатывание подтверждено повторным тестом Atomic Red Team `T1059.001-17` от 14.10.2026. Правило проверено на этом варианте обфускации и не является универсальной защитой от всех её способов.

## Исходные материалы

### Правило обнаружения

- [custom_powershell_rules.xml](detection/custom_powershell_rules.xml) — собственное правило Wazuh `100110`, Level 8, с родительским правилом `91802` для анализа PowerShell ScriptBlock.

### JSON-события

- [01-cmd-process.json](evidence/01-cmd-process.json) — Sysmon Event ID 1 — создание cmd.exe, правило `92057`, Level 12.
- [02-powershell-encodedcommand.json](evidence/02-powershell-encodedcommand.json) — Sysmon Event ID 1 — запуск powershell.exe с EncodedCommand, правило `92032`, Level 3.
- [03-obfuscated-scriptblock-4104.json](evidence/03-obfuscated-scriptblock-4104.json) — PowerShell Event ID 4104 — обфусцированный ScriptBlock.
- [04-executed-scriptblock-4104.json](evidence/04-executed-scriptblock-4104.json) — PowerShell Event ID 4104 — раскрытая команда `Write-Host`.
- [05-custom-rule-alert.json](evidence/05-custom-rule-alert.json) — оповещение повторного теста: правило `100110`, Level 8 и обфусцированный ScriptBlock.
- [06-rule-92057-alert.json](evidence/06-rule-92057-alert.json) — оповещение правила `92057`, Level 12, из `wazuh-alerts-4.x-2026.10.12` для создания cmd.exe PID 6516.

### Скриншоты

- [01-timeline.png](screenshots/01-timeline.png) — хронология событий в Wazuh Dashboard (время Dashboard — UTC+3).
- [02-powershell-process.png](screenshots/02-powershell-process.png) — Sysmon Process Creation для powershell.exe PID 10128.
- [03-scriptblock-4104.png](screenshots/03-scriptblock-4104.png) — PowerShell Event ID 4104 с ScriptBlock.
- [04-custom-rule-alert.png](screenshots/04-custom-rule-alert.png) — срабатывание правила `100110`, Level 8, в Wazuh Dashboard.
- [05-custom-rule-scriptblock.png](screenshots/05-custom-rule-scriptblock.png) — Event ID `4104` и обфусцированный ScriptBlock в новом оповещении.
