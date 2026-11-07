# Исправления до сборок — 7 ноября 2026

Продолжение после разрешения локальных сборок:
[LOCAL_VALIDATION_2026-11-07.md](LOCAL_VALIDATION_2026-11-07.md).
Ниже сохранён исходный checkpoint этапа «до сборок».

Продолжение после `f95fd01843c8b6d9c7ebdff0dedb61878e6a1610` по указанию
«продолжай исправлять всё, что можно, до сборок».

**Новый C++ не собирался. Production/runtime acceptance не выполнялась.**
Результаты сборок из предыдущего integration-отчёта относятся к его checkpoint,
а не к изменённым здесь файлам. Релиз остаётся NOT READY.

## Что изменено

### CURRENT authority

Добавлен `client/core/utils/awgControlAuthorityStore.h` и подключены реальные
PREPARE/operator maintenance call sites:

- Scope включает serverId, SSH endpoint/port/user/host-key fingerprint и source;
  пароль не сохраняется в identity.
- Перед запуском native PREPARE сохраняется `pendingPrepare` с SHA проверенного
  bundled feed. После строгого receipt и generation-validation записывается CURRENT.
  Ни receipt, ни unsigned server journal не выбирают доверенный digest.
- Maintenance сохраняет `pendingMaintenance` с old/new, generation, ожидаемым
  journal hash, operationId и точным recovery-каталогом до control mutation.
- Только проверенный native receipt переводит CURRENT на replacement. Commit
  локальной authority происходит до cleanup: ошибка удаления уже не оставляет
  старый CURRENT после успешной серверной замены.
- Оператор может опустить `currentControlSha256` при явном
  `nativeControlVariant: "native-control-http-v1"`: pin берётся из locked local
  current state с совпадающей generation. Явный pin закрепляет отсутствующее
  состояние либо должен совпасть с существующим; pending он не перезаписывает.
- Потерянный/невалидный ответ сохраняет pending и запрещает обычный повтор.
  Никакого автоматического доверия journal/replacement при восстановлении нет.

Linux использует отдельные domain-separated записи encrypted secret store.
Windows/macOS получают namespace `-ControlAuthority`; Android — фиксированный
`control-authority.ini`. Keychain key/IV tags также отделены от Application.
Authority не импортируется из обычных settings/backup, требует atomic sync и
fresh read вместо кэша. Linux lock отдельный для identity; на остальных платформах
lock покрывает общий settings backend, его key creation и teardown.
Worker сам владеет settings и закрывает их в своём потоке до освобождения lock.

### Прочие исправления

- Maintenance сохраняет первую device/inode identity каталога и отказывает,
  если повторная проверка обнаружила замену. Cleanup не принимает новую identity.
- Legacy maintenance и PREPARE независимо проверяют удаления файлов и каталогов;
  успешный `rmdir` больше не маскирует неуспешный `rm`. Primary error сохраняется.
- Ошибка operator maintenance возвращает только безопасные `reason` и точный
  `retainedDirectory` с recovery/cleanup flags, вместо потери пути либо отражения
  произвольного SSH output/секретов.
- Linux secret store открывает файлы с `O_NONBLOCK`, чтобы FIFO не блокировал
  чтение до проверки типа; ограничивает чтение, перепроверяет размер/identity/
  timestamps и отклоняет special mode bits. Запись и создание ключа проверяют
  fsync файла/родительского каталога; частичный ключ не заменяется новым.
- Native provisioning verifier выдаёт helper role только после успешной
  аутентификации metadata. Installer принимает ровно одну каноническую role record
  и не запускает Python для чтения роли на native-пути. Ошибка/отсутствие record
  приводит к отказу без legacy fallback. Старый verifier без record не подходит
  новому installer; эти компоненты потребуется собирать и проверять совместно.

## Проверки этого этапа

Команда из корня checkout:

```bash
PYTHONDONTWRITEBYTECODE=1 /workspace/.setup/venv/bin/python -B -m unittest \
  client.tests.awg_control_authority.test_authority_source_contract \
  client.tests.awg_control_maintenance.test_native_maintenance_source_contract \
  deploy.headless.test_installer_native_role \
  client.tests.awg_migration.test_active_migration_paths
bash -n deploy/headless/install_headless.sh deploy/headless/build_headless_release.sh
```

Результат: **33 теста PASS** (14 authority source contracts, 6 maintenance source
contracts, 9 inert shell fragment tests, 4 active-path source checks), shell syntax
PASS. Эти тесты не исполняют C++ store, SSH, установщик целиком или VM.
Локальные hashes/команда/exit сохранены в
`/workspace/.setup/prebuild-20261107/source-only-result.json`.

Добавлены/расширены будущие native-тесты: pendingPrepare/pendingMaintenance reload,
old/new transitions, conflict/corruption/independent-process locks, FIFO watchdog,
size/mode/key integrity, selector и безопасный error JSON. Targets
`awg_control_authority` и `awg_control_maintenance` включены в focused suite.
**Компиляция и выполнение этих новых native-тестов: NOT RUN.**

## Что остаётся до выпуска

1. Скомпилировать изменённые client/headless/native verifier и выполнить native
   tests, включая Windows/Android keychain/storage. Source contracts этого не доказывают.
2. Реализовать и принять trusted recovery/reconciliation pending-состояний.
   Сейчас они намеренно блокируют обычную работу; API выбора известного old/new
   не подключён к автоматическому recovery. Existing remote generations не
   закрепляются автоматически. Полный automatic maintenance/recovery lifecycle
   **не объявляется завершённым**.
3. Удалить оставшийся production Python только после native bootstrap/journal/
   recovery parity. Начальная проверка команд installer и legacy-ветви всё ещё
   требуют Python; удаление одного reader не закрывает весь критерий.
4. Закрыть Conan/toolchain/resource/signing prerequisites, затем final builds и
   отдельную byte-bound приёмку устройств/106 сценариев из integration-отчёта.

Сборки, installers, VPN, VM, телефонные операции и публикация на этом этапе
не запускались. Настройки опубликованной облачной среды не менялись.
