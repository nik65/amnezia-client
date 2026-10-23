# Python в Amnezia: состояние переноса на C++

Состояние исходников: 21 октября 2026. Переносятся рабочие компоненты;
сборочные инструменты, тесты и рецепты Conan остаются на Python. Изменения
исходников и отдельные тесты не означают обновление серверов или приёмку выпуска.

## Где используется Python

Windows/Android-клиент написан на C++/Qt (Android также использует Kotlin).
Серверные Python-компоненты доставляются через существующий self-hosted поток.
Поддерживающие инструменты не являются зависимостью работающего GUI-клиента.

| Компонент | Исходники | Статус |
| --- | --- | --- |
| Сборщик логов | `client/server_scripts/client_logs/native/` | Native source wiring готов; без bundle остаётся Python |
| Маршрут сборщика | `client/server_scripts/client_logs/native_route/` | Native source wiring: host route ExecStart, PID / loaded SHA; доставка не активирована |
| AWG | `client/server_scripts/awg_migration/native/` | Реализованы HTTP feed, config parser, planner/catalog, policy, attestation, journal core и control service; серверный runtime не переключён |
| Headless provisioning | `deploy/headless/native/`, `deploy/headless/install_headless.sh` | После аутентификации helper реально выбираются native FS-операции и журнал; preauth/legacy-пути остаются Python |

Исходный снимок отслеживаемых собственных файлов содержал 159 Python-файлов,
48 127 строк: 11 серверных файлов, 21 рецепт Conan, 7 сборочных инструментов,
42 лабораторных и 78 тестовых файлов. Это историческая граница инвентаризации,
а не текущий подсчёт после новых тестов. Встроенные скрипты учитывались отдельно;
third party, generated, `dist` и исторический `Testing` исключены.

## Headless

`amnezia-headless-fs` выполняет FS-проверки, fsync и операции журнала транзакции.
Installer выбирает native journal после проверки подлинности помощника в приватной
копии пакета. После выбора ошибка native-пути завершает операцию без скрытого
возврата к Python. До аутентификации и для legacy-пакетов/восстановления сохраняются
предусмотренные Python-пути; криптопроверка и архивные операции перенесены не полностью.

Сохранён контракт пакета из девяти файлов: прежние восемь плюс явно объявленный
`nativeHelper: amnezia-headless-fs` с точным именем, режимом 0755 и SHA256SUMS.
Старый восьмифайловый контракт остаётся совместимым. Помощник зависит от QtCore;
упаковка должна доставлять и проверять эту зависимость. Неподписанный входной
помощник не запускается. Это включение в исходный installer, а не доказательство
обновления уже установленного сервера.

## AWG native core

C++17-модули используют json-c для типизированного JSON, RapidJSON для разбора
канонизируемых control-документов, OpenSSL для криптографии и SQLite для control
state. Зависимости входят в будущий контракт сборки и доставки; самодельный
JSON-парсер или криптографическая замена не вводятся.

| Модуль | Реализовано | Что остаётся для рабочего переключения |
| --- | --- | --- |
| Feed/config | Ограниченный HTTP runtime и typed config parser | Source wiring native feed готов; static bundle и guest acceptance остаются |
| Planner/catalog | UDP inventory, выбор порта, reuse, pinned catalog и bounded process/sandbox adapter | Native planning/inventory/port/catalog подключены; orchestration и delivery остаются |
| Policy | Typed policy, FS и ограниченный JSON/process adapter | Native prepare/preflight подключены; maintenance и проверка целевого окружения остаются |
| Attestation | Config, peer/engine/epoch и bounded process adapter | New prepare подключён; existing-generation/recovery и delivery остаются |
| Journal core | Транзакционный файловый журнал с блокировками и durability-проверками | Интеграция prepare/maintenance и совместимость восстановления |
| Control service | Все5операций подключены через private C++ bridge; прежняя SQLite/аутентификация сохранены | HTTP/PID1 пока Python; delivery и контейнерная приёмка остаются |

Native AWG остаётся staged: существующие Python resource bundle, runtime recipes
и работающие поколения не заменены. Остались `prepare`, `maintenance`, control
recipe, PID1, HTTP target adapters и их доставка/откат. Нельзя переименовать ELF
в `.py`, переиспользовать старый hash Python-рецепта или создать второй журнал,
новое поколение, peer либо signer при ошибке переключения.

## Source integration optional native bundle

`client/cmake/serverNativeBundle.cmake` принимает optional
`AMNEZIA_SERVER_NATIVE_BUNDLE_DIR`, проверяет manifest SHA, пути и размеры,
после чего генерирует QRC. Разрешён reviewed static ELF64 ET_EXEC x86_64/aarch64
без PT_INTERP, PT_DYNAMIC и PIE. `serverNativeBundle.h` повторяет проверки.
Отсутствие bundle сохраняет legacy; предъявленный invalid bundle, отсутствующая
архитектура или роль отклоняются без fallback.

`exportController` выбирает native collector/route по роли и архитектуре:
реальный native entrypoint, host route ExecStart, PID и loaded SHA проверки.
`installController` передаёт native feed через prepare capture и validation,
сохраняя тот же generation journal. Бинарник монтируется read-only и использует
`--serve`; native `--check-feed` проверяет SHA с лимитом 1 MiB и 5 секунд.
Feed и route теперь также зависят от OpenSSL Crypto для SHA-проверок.

Реальный static bundle ещё не собран и не предоставлен. Source wiring завершён,
но доставка и production activation не выполнены; текущая ordinary release по
умолчанию остаётся Python. Existing native generation/reuse требует будущей
maintenance/PID1 attestation; prepare, maintenance и control остаются Python.

Headless preauth verifier проверяет Qt-библиотеки, нужные для запуска helper;
дальнейшее удаление Python блокируется этим trust boundary. Ослаблять его нельзя.
QtCore dependency и nine-file contract сохранены.

Дополнительные source wiring receipts: generic 62 checks + maintained CMake import / 2 CTest; CMake 21
Windows / 24 Linux; collector route 40, Qt 6 и guard 8; feed regressions 65 и
HTTP 8. Доказательства: `dist/diagnostics/python-native-wiring-20261020`.
Это contract tests, а не конечная приёмка. App/release build, bump версии,
публикация, серверные изменения и host VPN controls не выполнялись.

## Проверки и ограничения

Общий актуальный standalone AWG CTest: **58/58** (source-config checkpoint ниже). Проверки используют собственные
временные файлы, fake process/Docker/proc-ответы и отдельные loopback HTTP fixtures.
Проверяются в том числе NUL/DEL в control-канонизации, единый лимит journal
save/read 4 MiB и безопасные FS-границы policy. Differential Python-инструменты
остаются тестовой проверкой совместимости. Отдельные компоненты имеют намеренно
более строгие входные ограничения; это не утверждение побайтового совпадения
всех недопустимых входов с историческим Python.

Исправлены source/fixture-подтверждённые дефекты: feed `.run` и MIME query handling,
FIFO-чтение planner journal и привязка request generation к каноническому каталогу.
Эти находки не приписываются production-инциденту без runtime-доказательства.

Далее необходимы проверенная доставка exact binary/dependencies, явный native
recipe, единый журнал/БД, fault/recovery tests и приёмка в принадлежащих лаборатории
гостях. Полное удаление Python из серверного runtime и конечная приёмка не завершены.
Работающий VPN, приложение и службы Windows-хоста не проверялись управляющими
операциями; серверное развёртывание в рамках этих изменений не выполнялось.

## Продолжение подключения: 21 октября

Native-путь `exportController` теперь выполняет `--publication-preflight`
проверенным C++ route-helper до изменения данных/контейнеров. Python ROUTE_GUARD
в этом пути удалён; legacy-путь сохранён. Проверка принимает прежний collector
с отсутствующим/пустым/null Labels только при точном legacy identity. Bind/reconcile
сохраняют строгие требования. Существующий native collector требует loaded SHA.

`prepare.py` при выборе native feed вызывает его `--policy-json` для snapshot,
firewall и epoch; MTU доступен через тот же адаптер. Выполняются точные захваченные
ELF-байты через sealed memfd, а не повторно открываемый mutable staging path.
Команды Docker ограничены read-only allowlist, argv, сроками и объёмом вывода.
Ошибки native не приводят к скрытому Python fallback. Python orchestration,
maintenance и control по-прежнему остаются: полного удаления Python нет.

Исправления аудита проверяются отдельными actual-function/unit fixtures:
ограничение save/read профилей 16 MiB, время жизни загрузок Qt, потоковый разбор
большого списка токенов, URL сайта/папки логов, отклонение пустого и повреждённого
Xray JSON, уведомления NewsModel и выбор Visual Studio. Это source-дефекты;
причина production-инцидента без runtime-логов им не приписывается.

Текущие доказательства и точные ограничения:
`dist/diagnostics/python-native-resume-20261021/`. Инвентаризация 1295 файлов
не означает их полный аудит. Изолированный Linux RSS-тест сборщика не заменяет
приёмку суммарной памяти контейнера. Windows-ветка URL проверялась с WSL Qt;
это не native Windows runtime acceptance.

Независимое повторное ревью дополнило исправления: ошибки URI возвращают
ImportInvalidConfigError (проверяется настоящий default NoError), Trojan отклоняет
неверный URL/пустой host. TLS, порт и пароль при этом не переопределялись.
Рекурсивные regex нового policy adapter заменены линейными валидаторами после
воспроизведения SIGSEGV на допустимом по размеру входе 200 000 символов.
Также исправлены имя Windows ARM64-пакета, раскрытие пароля notarization в обоих
потоках вывода и итоговый статус обязательных операций Linux post-install, включая
восстановление SteamOS readonly. Проверялись только инертные fixtures, реальные
установщики, службы, notarization и упаковка не запускались.

## Native config и подтверждённые исправления: 21 октября

В native-режиме `prepare.py` и preflight разбирают исходную конфигурацию через
существующий C++ `parseConfig`, вызываемый командой `--config-json` захваченного
helper. Все четыре места разбора в prepare выбирают один adapter; legacy-режим
сохраняет Python. Проверки реального C++ helper охватывают Unicode, opaque NUL,
порядок peers, JSON-расширение больше прежнего 1 MiB output cap и отказ без fallback.
Raw config ограничен 1 MiB, JSON — 8 MiB; данные/ключи передаются только через
приватные stdin/stdout. Orchestration и maintenance по-прежнему остаются Python.
Existing native generation/recovery сохраняет прежний запрет до maintenance;
на этапе parser ready attestation и журнал ещё не подключались.

Исправлены воспроизведённые source-дефекты: отказ зеркала APK на manifest URL с
`android9%2B...apk` (Python и C++ теперь принимают literal `+` после одного decode),
классификация IPv6 host с NUL и необработанные TypeError/UnicodeDecodeError при
повреждённом ответе helper. Причина production-инцидента этими тестами не доказана.

После объединения изменений общий standalone CTest прошёл 22/22. Дополнительные
510 parser differential и 6 native HTTP сценариев прошли; две root-owned capture
проверки выполнены в собственных временных каталогах. Это не сборка приложения,
static bundle, выпуск или проверка установленного VPN. Доказательства:
`dist/diagnostics/python-native-config-20261021/`.

Bootstrap memory defect и journal integration, остановленные проверкой модели,
не изменялись. Контроль/PID1, planner/target adapters, maintenance и полное удаление
Python остаются незавершёнными. Новая версия не собиралась и не публиковалась;
VPN на ПК и production-серверы не управлялись.


## Native readiness для нового поколения: 21 октября

`prepare.py` при явном native-выборе вызывает C++ `validateReadyTarget` через
`--ready-json` захваченного sealed ELF. Проверяются исходные ID/name/image/owner,
Running/StartedAt до и после наблюдений, полный набор20 параметров, порт, peers
и engine proof; команды read-only и используют pinned ID. Python fallback нет.
Legacy-ветка теперь также вызывает полный прежний validator вместо сокращённой
проверки. Ready проверяется при запуске, перед активацией source endpoint и перед
сохранением результата; targetEpoch берётся из исходного pin.

Исправлены воспроизведённые ошибки: принятие неверных port/Jc/RandomTrailers и
IndexError на коротких строках dump в new prepare; трактовка сбоя Docker inspect
как свободного имени; принятие C++-проверкой невалидного UTF-8 в игнорируемых полях;
продолжение дочернего exec после ошибки fcntl/open/dup2. Это source/fixture findings,
а не доказанные причины production-инцидентов. В fault-тестах реальных exec нет.

Лимит60s/20attempts ограничивает начало очередной проверки; активный native вызов
может завершиться позднее (его cap45s). Первоначальный parent pin и legacy команды
сохраняют прежний timeout180s на процесс. Общий wall-clock cap105s не заявляется.
Existing generation/recovery HOLD и прежний журнал сохранены. Prepare orchestration,
maintenance, control/PID1, planner/target adapters и доставка остаются незавершёнными.
Обычная конфигурация без проверенного static bundle по-прежнему использует Python.

Доказательства и финальные результаты: `dist/diagnostics/python-native-ready-20261021/`.
Whole-flow tests подменяют внешние действия; cleanup requested не означает проверку
реального rollback. Новая версия/static bundle не собирались и не публиковались;
VPN на ПК не затрагивался. Bootstrap/journal, остановленные проверкой модели,
в этой независимой ветке не менялись.


## Native automatic planner/inventory/port probe: 21 октября

В явном native-режиме automatic prepare обе инвентаризации UDP, выбор/reuse плана
и последняя проверка свободного порта теперь вызывают C++ через `--automatic-json`.
Использованы существующие cores occupiedUdpPorts/automaticPlan/verifyAutomaticPort,
тот же captured sealed helper и строгий приватный JSON-контракт без Python fallback.
Trusted-image resolution с pull/sandbox, orchestration, запись/восстановление
транзакций и control/PID1 остаются Python/незавершёнными. Existing-native generation
по-прежнему HOLD до maintenance. Реальная доставка не активирована.

Fixed read-only ss/Docker inventory использует прежний bounded process transport:
3s/1MiB, фиксированные executable/argv и прежний FD/lifecycle cleanup. Port probe
держит оба V4/V6-only UDP дескриптора до завершения вызова, затем закрывает их,
включая ошибки. Это best-effort, а не постоянное резервирование порта. JSON frame
ограничен8MiB/5s, raw config1MiB; hash сохраняет Unicode и opaqueNUL. Метаданные и
response types ограничены отдельно; malformed/helper failures не запускают fallback.

До подключения исправлены два воспроизведённых source-дефекта: C++ plannerJson
принимал duplicate decodedkeys и NaN/Infinity; readonly reader мог вернуть старые
байты после подмены journal path при EOF. Теперь выполняются строгий grammar/key
разбор и pre/post lstat/fstat/count. Заблокированный transaction-journal/FLOCK
write bridge и bootstrap не менялись. Production-причинами эти находки не объявлены.

Общий standalone CTest34/34 PASS. В нём automatic bridge9 методов, readiness13,
planner unit33/differential44+2 strict NUL/stability4; дополнительный CLI15 PASS. Процессы,
сокеты и внешние prepare-эффекты в fixtures подменены; реальные Docker/ss и UDP bind
не выполняются. Cleanup request не доказывает реальный rollback. Доказательства:
`dist/diagnostics/python-native-planner-20261021/`.

Новая версия, app/release/static-delivery bundle не собирались и не публиковались;
VPN и приложение ПК не управлялись, production и Android не затрагивались.
Перенос Python и полный аудит остаются незавершёнными; решение о сборке — за пользователем.


Независимое follow-up исправило третью ошибку: raw substring-проверка принимала
буквальный backslash-u0000 за настоящий decoded NUL и отвергала допустимый Docker
inspect JSON. Теперь SAX проверяет декодированные String/Key; literal-текст проходит,
настоящий NUL и прежние invalid JSON случаи отклоняются. Полный captured-helper
fixture содержит этот допустимый opaque Env. Финальный повтор:34/34 и CLI15/15 PASS.


## Native trusted-image catalog: 21 октября

В native-ветке automatic prepare проверка доверенного образа теперь вызывает
существующий C++ resolveTrustedImage через приватный --trusted-image-json.
Точный {op:resolve} не принимает image/tag/architecture/command/budget; input4096/5s.
Сохраняются pinned digest/config-ID/descriptor, Linux/amd64, точные SHA/версия/tools
и изолированный sandbox argv. Python fallback отсутствует; legacy и константы
каталога сохраняются. Отказ останавливает путь до planning/journal/target create.

Metadata10s/pull180s/probe30s дают максимум300s отдельных command budgets; только
этот helper имеет parentcap330s. Остальные helper45s и прежние Docker/ss3s не
увеличены. Retryable только реальные ошибки pull Exit/Timeout/OS; ошибка доверия
не становится временной. Это не общий timeout всего prepare.

Исправлены подтверждённые audit findings: Unicode.strip совместим с Python через
RapidJSON decoder и эмпирические29 пробельных codepoints; EOF больше не создаёт
busy-spin ожидания child. Owned300ms probe:306675→16 poll, CPU0.300→0.000293s.
Невалидный UTF-8 и прежние FD/lifecycle guards сохранены. Это source/fixture errors,
не установленные причины production-инцидентов.

Общий standalone CTest42/42 PASS: catalog unit37, core70, differential171+2strictNUL,
catalog bridge6 и прежние planner/ready/FD/lifecycle suites; дополнительный CLI16.
Действительные Docker/pull/run во всех valid catalog fixtures подменены. Отдельно
проверена регистрация шести transport cases после исправления CMake interpolation.
Daemon-side cleanup --rm контейнера после обрыва CLI не доказан; это отдельный
пробел runtime acceptance, не обещание полного rollback.

Остаются orchestration, запись/восстановление транзакций, maintenance/control/PID1,
доставка и гостевая приёмка. Existing-native generation HOLD, blocked journal и
bootstrap не менялись. Обычная конфигурация без reviewed static bundle остаётся
Python. App/release/static-delivery новая версия не собиралась и не публиковалась;
VPN/приложение ПК и production не управлялись. Доказательства:
`dist/diagnostics/python-native-image-20261021/`.


## Native target config generation: 21 октября

В native prepare генерация quick/UAPI конфигураций и нового HeaderProtectionKey
переведена в C++ и подключена через приватный --generate-config-json captured helper.
Используется существующий C++ parser; сохраняются source PrivateKey/Address, значения
и порядок peers, прежние20 параметров. Исходные hooks отбрасываются. OpenSSL
RAND_priv_bytes обязан успешно вернуть32байта; CLI не принимает seed, ошибка не
запускает Python fallback. Без reviewed bundle сохраняется legacy Python-путь.

Схема запроса точная: source:string,port:int1024..65535,mtu:int576..9000. Проверяются
UTF-8, duplicate decoded keys, types/depth/extra fields. Frame8MiB/5s, source1MiB,
каждый результат1MiB и JSON16MiB ограничены отдельно: две escaped конфигурации
могут превышать8MiB. Непрозрачные peer values с NUL сохраняются по длине; parent
проверяет map types/20параметров/24interfacefields/HPK/размеры и source identity до
записи UTF-8 файлов0600. Доверие к телу ответа основано на captured проверенном helper.

Подтверждён прежний дефект native-selected пути: допустимый source1MiB после
Python-генерации становился больше1MiB и отвергался native readiness. Теперь отказ
происходит до записи/создания контейнера; реальный inert prepare тест это проверяет.
Чистый legacy путь собственного readiness лимита1MiB не имеет, его ошибка не заявляется.
Это source/fixture finding, не доказанная причина production разрывов.

Проверки: общий standalone CTest44/44; generator unit57 checks, generation bridge12/12,
отдельные CLI30/30 с теми же финальными байтами helper. Есть реальный OpenSSL RNG,
test-only отказ RNG без fallback/частичного успеха,5s noEOF, output>8MiB и отказ
oversize до filewrite/create. Внешние prepare/Docker/network эффекты подменены.
Первый compile нового unit упал на неиспользуемом json-c include; header удалён,
финальная компонентная сборка и тесты прошли. Доказательства:
dist/diagnostics/python-native-generation-20261021/.

Полный перенос и аудит незавершены: orchestration, transaction write/recovery,
maintenance/control/PID1, доставка и приёмка остаются. Existing-native generation
HOLD, заблокированные model check ветки journal/bootstrap и пробел sandbox cleanup
не менялись. App/new version/release/static-delivery не собирались и не публиковались,
VPN/приложение/службы/сеть ПК и production не управлялись. Решение о сборке — за пользователем.


## Подключение C++ control service: 21 октября

В новом native prepare все5операций migration-control выполняет C++ ControlService
через приватный --control-json. Python пока обслуживает HTTP/PID1 и исходный
authenticate callback; обычный запуск без reviewed bundle остаётся legacy Python.
Production directory фиксирован /migration, frame256KiB/5s, body16KiB, output16MiB.
Подставить directory/clock/seed через протокол нельзя.

Первый проход откладывает auth исключением в callback и откатывает SQLite. Parent
вызывает исходную проверку единожды и повторяет запрос с verified client ID; None
сохраняет уже отправленную HTTP ошибку. Максимум2прохода, ни token/PEM, ни Python
business fallback. Общая grants.sqlite3 сохраняется. Захваченные static ELF bytes
удерживаются sealed memfd; expected SHA и read-only bind одинаковы у двух control
контейнеров. Capability до подготовки/старта отклоняет устаревший helper. Pre-ready
proof связывает Python PID1/processStart, source pair и фактический sealed FD/SHA.

Исправлен подтверждённый state cap bug:6000 peers source522911B/quick553255B дают
ready1245098B; ранее native403 при Python200. Только ready read/parse увеличен до
8MiB, +1отклоняется без нового grant. HTTP/canonical/signer/handshakes caps сохранены.
В maintenance добавлен отсутствовавший явный HOLD native-поколений до recipe/runner
операций. Во время интеграции пойман и устранён Windows import fcntl regression:
он теперь импортируется только при explicit Linux capture, legacy22теста проходят.

Финальный standalone CTest47/47, runtime unit53checks, native bridge8/8, wiring10/10,
CLI26/26, Windows legacy22/22, отдельные maintenance24/24. Реальные ephemeral Ed25519
и SQLite проверяют пять операций/replay/единственный commit/rollback при auth;
Docker/prepare/proc остаются инертными. Static capture не исполнялся, business fixture
dynamic/manualsealed и test-only. Container PID1/listener/FD acceptance ещё требуется.

Перенос не завершён: HTTP/PID1, orchestration, transaction write/recovery, maintenance,
доставка и гостевая приёмка остаются. Заблокированные model check journal/FLOCK и
collector bootstrap не менялись и не обходились. Новая версия/app/release/static
bundle не собирались; установка, публикация, production и VPN/приложение/сеть ПК
не управлялись. Доказательства:dist/diagnostics/python-native-control-20261021/.


## Независимый аудит C++ import data: 21 октября

После model check native HTTP/PID1/auth оставлен без реализации; зависимая работа
отменена до инструментов/правок. Заблокированные journal/FLOCK и bootstrap не
обходились. Независимый аудит исправил C++ QR и обработку конфигураций/API:
bounded streaming zlib16MiB вместо шести qUncompress путей, различение raw text и
compressed envelope, QR frame validation/max255, stored-zlib level0 decode order,
raw/encoded caps и NoError на invalid/empty subscription JSON. Main file import
теперь передаёт bounded read limit; Android acquired FD имеет scope guard без
device validation. Zlib уже существовал в Conan, source/CMake wiring добавлены.

Standalone QtCore/QtTest CTest5/5: codec27, QRframes7, actualQRstate27,
data integration62, actual file reader39 checks. Есть явные semantic
seams в extracted fixtures; это не app/Windows/Android/runtime acceptance.
Текущая стадия не уменьшает Python orchestration; полный перенос и аудит ещё идут.
Raw source/HEAD/index/flags сохранены. Новая версия/app/release/static bundle не
собирались, установка/публикация, production, VPN/приложение/сеть ПК и ADB не выполнялись.
Доказательства:dist/diagnostics/python-native-data-audit-20261021/REPORT.md,RECEIPT.json.


## Native network topology parsing: 21 октября

В explicit native prepare/preflight разбор наблюдаемой сетевой схемы перенесён
из Python source_network_options в C++ network_topology. Python собирает прежние
read-only наблюдения и передаёт их captured sealed helper через --network-json.
Два запроса: networks возвращает только bridge/optional amnezia-dns-net, validate
проверяет Docker version≥28, bridge/IPAM/IPv4, один default route, интерфейсы и
network identity; возвращает прежние options/binding. Parent проверяет схему
результата до изменения binding. Native error не вызывает Python fallback.

Все native checks source/target до/после network-start и main preflight получают
тот же выбор; orchestration/изменяющие команды не переносились и не запускались.
Legacy body сохранён как legacy_source_network_options, без bundle он остаётся
default. Pure core не выполняет команды/сокеты. Runtime: frame8MiB, observation1MiB,
output16KiB, EOF5s; parent45s на helper. Это не общий timeout prepare. Aggregate
frame может отклонить комбинацию нескольких сильно escaped per-observation caps;
Python observation capture по-прежнему использует прежний runner и cap после capture.

Финальный standalone CTest52/52: pure81checks, differential147 (102compat+45strict),
captured bridge9/9, CLI4/4 с exact frame/observation bounds и real5s noEOF;
legacy prepare15/15. Все102compat совпали,22 malformed cases, принятых legacy,
native отклоняет намеренно. Два прежних test harness обновили inert topology seam
под новую factory; actual topology отдельно проверен real captured helper и AST
prepare/preflight. Dynamic test helper не является verified static delivery.

Новых подтверждённых production-причин не установлено; новые логи не читались.
Полный перенос остаётся открыт: Python orchestration/HTTP/PID1/auth, transaction
write/recovery, maintenance, доставка и live/guest acceptance. Model-blocked
HTTP/PID1/auth, journal/FLOCK, collectorbootstrap не обходились. Existing-native
generation HOLD и cleanup gap сохранены. Новая версия/app/release/staticdelivery
не собирались/не публиковались; production и VPN/приложение/сеть ПК не управлялись.
Доказательства:dist/diagnostics/python-native-topology-20261021/REPORT.md,RECEIPT.json.


## Native stopped-target metadata: 21 октября

Из start_target_networks вынесен Python-разбор состояния созданного, ещё не
запущенного target. Explicit native использует pure C++ validateStoppedNetworkTopology
через --network-json op=stopped; literal result:true обязателен, fallback отсутствует.
Проверяются identity, created/Pid int0/Running boolfalse/zero StartedAt, bridge mode,
binding/interfaces/default, DriverOpts/GwPriority, network IDs и отсутствие assigned
endpoint/IP fields. Проверка относится только к Docker JSON, не к /proc/PID1/auth.
Read-only наблюдения и прежние journal.record/network-connect/start остаются Python;
эти команды не менялись и реально не выполнялись. Source-binding guard и свежие
проверки после старта сохранены. Без bundle default остаётся прежний legacy parser.

Standalone54/54: pure259checks (81original+178stopped), старый147 и новый147-case
corpus (66compat+81strict), stopped bridge10/10, прежние CLI/prepare suites проходят.
В66compat результаты совпали;60malformed случаев, принимавшихся legacy, native
отклоняет намеренно. Actual orchestration проверена fake journal/командами; это
не Docker/VPN/static-delivery acceptance. Первый compile выявил json-c foreach
hidden-variable name collision; root исправил уникальным именем, финальный build0.

Физически сверены2095 исходников; prior work/HEAD/index/flags сохранены. Model-blocked
HTTP/PID1/auth, journal/FLOCK, collectorbootstrap, existing-generation HOLD и cleanup
gap не менялись. Полный перенос Python и аудит ещё идут. Новая версия/app/release/
delivery не собирались и не публиковались; production и VPN/приложение/сеть ПК
не управлялись. Доказательства:dist/diagnostics/python-native-stopped-topology-20261021/.


## Native bounded network observer: 21 октября

В explicit native-пути C++ теперь собирает наблюдения Docker для исходного и
остановленного target-контейнера. Python передаёт snapshot/stopped-snapshot,
не вызывает свой runner и проверяет результат до изменения binding. Старые pure
операции сохранены. Разрешены только фиксированные read-only argv; IP читается по
полному ID из inspect, входные имена и binding проверяются до соответствующих
команд. Новый capability проверяется до cleanup/journal/mutation, без fallback.

Подтверждён resource-дефект предыдущего native bridge: существующий Python run
получил32МиБ synthetic stdout до проверки1МиБ. Теперь C++ ограничивает stdout во
время чтения1МиБ/команду, deadline3с; превышение может занять один read-chunk8192B
до отказа. Это исправляет explicit native, обычный legacy capture остаётся Python.
Это не доказанная причина прежних разрывов VPN. Snapshot не атомарен, повторная
проверка имени/daemon-side completion не обещаются; parent45с и EOF5с отдельно.

Тестовый observer fixture использует настоящий bounded fork/pipe transport, но
перехватывает execve: реальный Docker недоступен. JSON production не принимает
fixture controls. Полный перенос, source orchestration и runtime/guest/static
приёмка остаются открыты. Заблокированные моделью HTTP/PID1/auth, journal/FLOCK,
collectorbootstrap не обходились. Новая версия/app/release/delivery не собирались,
установка/публикация и VPN/приложение/сеть ПК не выполнялись. Доказательства:
dist/diagnostics/python-native-network-observer-20261021/REPORT.md,RECEIPT.json.

Финальный standalone CTest55/55: observer81checks, прежние259pure и147+147corpus,
network/stopped bridge11/11 каждый,36 fault cases с9 настоящими3с timeouts.
Физическая сверка2097 файлов:2087 без изменений,10 ожидаемых изменений+4new;
HEAD/index/assume-unchanged/skip-worktree сохранены.


## Native source-config capture: 21 октября

Все4чтения source raw (automatic/manual/finalunchanged/mainpreflight) подключены
к C++ source_config_runtime в explicit native. Fixed sourceinspect128B -> cat по
pinned64ID/fixedsourcepath1MiB -> parseConfig -> repeatinspect sameID.3с/команду,
8KiBinput/8MiBoutput/EOF5с/parent45с. RawUnicode/CRLF/opaqueNUL сохраняется; ошибки
фиксированы, Pythonrunner/fallback отсутствует. Capability до preparecleanup;
CLI ROOTmkdir/lock всё ещё раньше неё. Это per-read pinning, не атомарный epoch.

Подтверждено: прежний manualread/run/parserguard получил32МиБ synthetic stdout до
отказа1МиБ. Native теперь ограничивает чтение; legacy/default остаётся Python.
Standalone58/58: sourceunit73, bridge13/13, actualCLI3/3,12faultcases/3timeouts.
Сохранены старые259+81pure,147+147corpus/bridge/legacy. Первый56/57 выявил старые
parser-testseams; их поправили, полный повтор58/58 прошёл. Это component tests,
не static-delivery/live/guest acceptance. Физически2101baseline:2092unchanged,
9expected+5new, HEAD/index/flags и прежниеLF/CRLF сохранены. Полный перенос/аудит
остаётся активным; blockedHTTP/PID1auth/journal/bootstrap не обходились. Новая
версия/app/release/delivery не собирались, публикация, production и VPN/сеть ПК
не управлялись. Evidence: dist/diagnostics/python-native-source-config-20261021/.


## Независимый аудит C++ и остатка Python: 21 октября

Инвентаризация23файлов подтверждает11рабочих standalonePython-файлов/3201строку,
плюс встроенные collector/headless блоки. Крупные независимые готовые native cores
подключены. Оставшиеся wholecomponents требуют blocked journal/recovery,
HTTP/PID1/auth, collectorbootstrap или проверенной доставки. Узкие независимые
кандидаты: routedpolicyepoch клиентскийHTTPprobe и legacymaintenance validation;
это не завершение полного переноса. Полный goal остаётся активным.

Исправлены подтверждённые C++ дефекты: WG/AWG equality теперь учитывает CIDR,
OpenVPN — CIDR+маску (старый contract дал11отказов). Sharedlogger защищает файл,
жизненный цикл и snapshots recursive mutex; нормальный consoleflush внеfilelock.
Qt6.10 oldlogger дал4missing/3duplicates из512; после исправления512/512 целых.
Gatewayupdater игнорирует устаревшее поколение до/после delayedrequest. Manifest и
legacy metadata имеют streaming1MiB bound/RAII, replyownership и cleanup pending
set. Bootstrapcompletion не обращается к эмиттеру, удалённому из publishFinished.

Standalone проверки: updater22/22 ASAN/LSAN (RED14/22, heapUAF и32793B leak),
modelcontract1/1, logger1/1+прежнийloggingcoverage, downloadlifetime11/11ASAN.
Все updater/publication/installer действия в fixtures инертные; приложение и
релиз не собирались. Это component tests, не Windows/Android/runtime acceptance.
Непроверенная гипотеза: reentrant delete из updateFound/releasePolicyChanged;
текущий updater fixture не покрывает эти части/реальную signedmanifest business.
Новые серверные логи не читались, production/VPN/сеть ПК не управлялись.
Evidence:dist/diagnostics/python-native-client-review-20261021/REPORT.md,RECEIPT.json.


## 21 October: native routed policy epoch observation

The explicit native prepare path no longer starts Python urllib in its collector
namespace to verify the routed policy epoch. It executes the mounted C++ helper
against the same fixed172.29.172.253:17864/rules.json endpoint and compares the
same expected revision/content hash. It cannot substitute host filesystem data,
localhost readiness or a body digest that would change when DNS materializes.
Native input/HTTP response validation and absolute5s/1MiB limits are stricter;
ordinary legacy behavior stays available. Early captured-ELF capability rejects
an old helper before prepare journal/recovery operations. This source wiring
removes one actual Python subprocess in the selected path, not an entire runtime
component: prepare/control orchestration and supported default delivery remain
Python, and no bundle was built or activated.

Actual checks and scope are recorded in the stage receipt. Test-only syscall
wrappers exercise the production client with a real steady-clock slow drip;
they do not establish live TCP, container, VPN or application acceptance. No
production or Android actions belong to this source stage. The earlier narrowly
authorized server routing-list correction is a separate completed operation.

A new updater reentrancy audit was rejected by the model's cybersecurity check.
It was not retried or reassigned. Its own two unfinished test-file edits were
preserved in diagnostic artifacts and restored byte-for-byte to the stage
baseline; production updater files remain unchanged. That hypothesis and older
blocked control/PID1/auth, journal/FLOCK and collector bootstrap work remain
unresolved. Full migration and repository-wide audit remain active/incomplete.


## 21 октября: native-карта peers и аудит моделей

В explicit native prepare расчёт карты peers теперь выполняет C++ через
существующий --generate-config-json. Native parser проверяет конфигурацию;
clientAddress сохраняет исходную запись AllowedIPs, IP берётся из проверенного
IPv4 host, clientId равен SHA256(scope + TAB + PublicKey). Проверка новой
capability предшествует recovery/mutation внутри prepare. Ошибка не возвращает
этот путь к Python; журнал, state и порядок записи сохраняются. CLI ROOT mkdir/
lock по-прежнему предшествуют prepare. Full standalone CTest64/64 PASS; live
операции, приложение и static delivery этим не проверялись и не собирались.

Это ещё один реально подключённый расчёт, а не удаление всего orchestrator.
В прежнем охвате остаются11 рабочих Python-файлов/3264строки плюс embedded-код;
число выросло на34строки проверяемого bridge. Default/legacy delivery остаётся
Python. Existing-generation maintenance HOLD и прежние заблокированные ветки
не ослаблены. Полный перенос и аудит остаются незавершёнными.

Отдельный аудит моделей воспроизвёл два дефекта: неинициализированный int port
в AwgClientConfig/WireGuardClientConfig и signed overflow при сложении размеров
AWG-пакетов. Добавлены port=0 и расширение до qint64 перед четырьмя сложениями.
До исправления оба standalone теста падали; после —2/2 PASS с UBSAN и10000
сочетаний границ int; существующие AWG regression suites4/4 PASS (Qt6.4),
новый model fixture использует Qt6.10.1. Defaults проверяются явным сравнением
представления int, переполнение — UBSAN. Связь с incident-разрывами не доказана.
Evidence: dist/diagnostics/cpp-config-file-audit-20261021/.


## 21 октября: ошибки восстановления Android-сеанса

В исходниках исправлены ErrorCode0 после неподтверждённого native cleanup и
зависание Preparing при отказе нового подключения из-за recovery latch.
Причина704 передаётся до Error; активный cleanup возвращает Disconnecting
без преждевременного Error и ожидает существующий bounded receipt. Latch,
context, nonce, epoch и запрет второго туннеля сохраняются. Actual-source
standalone11/11 PASS под ASAN+UBSAN/LSAN, baseline9/11 RED; независимыйreview
проверил отсутствие нового разрешения retry. Это source-исправление, не
обновление установленного телефона. Потеря native session binding ещё
не исправлена: нужен atomic challenged STATUS. Приложение не собиралось.
Evidence: dist/diagnostics/android-restored-session-20261021/patch/REPORT.md.

## 21 октября: native-вычисление serverPublicKey

В explicit native prepare удалён Docker shell-вызов awg/wg pubkey для вычисления
serverPublicKey: существующий C++ config runtime получает исходную конфигурацию
и использует OpenSSL EVP X25519. Отдельный server-key-capability проверяется
до recovery/изменений внутри prepare; внешний Python CLI всё ещё создаёт ROOT
и берёт lock раньше prepare. peerMappingVersion capability не изменена.

Сохранены parser/source identity, лимит исходника1MiB и прежний порядок journal
и записей. Неканонические padding bits private key отклоняются только новой
операцией server-key в соответствии с vendored awg/wg decoder; общий parser
не ужесточён. Ошибка native не переключает на Python/Docker pubkey. Default
и legacy-ветка, orchestration, control HTTP/PID1/auth и journal остаются Python.

Standalone66/66 PASS за93.55s; RFC7748 Alice/Bob, OpenSSL scalar clamping,
некорректные ключи, ранний отказ capability и inert prepare с derived key
в readiness/ready.json проверены. Pure production CLI smoke3/3 PASS без сети,
Docker и listener. Это source/standalone-проверки, не live-приёмка. Новая версия,
static delivery и публикация не выполнялись. Evidence:
dist/diagnostics/python-native-server-key-20261021/.


## 21 октября: текущая Android-цепочка и повторный аудит policy

Позднейшие source-checkpoint native-status-binding и android-service-discovery
исправляют описанный выше пробел native session binding и начальный выбор службы
из запаздывающего VpnStateStore. Challenged identity/nonce/epoch adoption и строгая
cleanup receipt сохранены; Activity использует собственный service inventory,
пассивную привязку и одноразовый C++/Kotlin допуск. Исправлены потеря сохранённого
состояния при отмене coroutine и лишняя аллокация Android-протокола. Это проверенные
исходники и отдельные fixtures; полный Android/JNI build и приёмка новых исходников
на телефоне остаются pending. Отчёт: dist/diagnostics/android-service-discovery-20261021/.

Следующий независимый аудит pure native policy воспроизвёл усечение JSON-ключей
и адресов с NUL и принятие raw NUL после JSON. Epoch теперь выбирает точные имена
из length-aware дерева с сохранением Python last-wins и неизвестных полей; полный
EOF проверяется, исходные ограничения глубины/UTF-8/int64 сохранены. Проверка
host/mask перед C-string API не меняет семантику непрозрачного IPv6 scope. Адресный
пример — дефект pure API: внешний runtime accessor уже отклонял такой NUL. Новая
находка не объявляется причиной сетевого инцидента. Актуальные хеши, RED/GREEN,
регрессии и границы: dist/diagnostics/native-calculation-audit-20261021/REPORT.md.

Рабочий Python всё ещё остаётся в orchestration, legacy/default, control HTTP/PID1,
журналировании, maintenance и других ранее перечисленных entrypoints. Эти source
исправления не устраняют все interpreter-процессы. Прежние model-blocked ветки не
повторялись и не обходились. Новая версия, installer/APK, release/delivery-пакеты,
установка и публикация не выполнялись; production и VPN ПК не управлялись.
