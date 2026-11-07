# Разработка Amnezia поставлена на паузу — 7 ноября 2026

**Статус: PAUSED по прямому указанию пользователя. Самостоятельно не продолжать разработку, сборки, гостевые или телефонные тесты и выпуск.** Возобновление — только после нового указания пользователя.

Цель, которая осталась незавершённой: проверенный выпуск **5.0.3.18 / Android versionCode 2204** с интеграцией upstream **5.1.0.6**. Этот checkpoint — сохранение незавершённой работы, **не релиз и не подтверждение готовности**.

```text
allFunctionsPass = false
releasePass     = false
published       = false
```

## 1. Где находится работа

Существуют два разных рабочих дерева; они сохраняются отдельно, без подмены одного другим:

| Дерево | Назначение | Ветка сохранения на GitHub |
|---|---|---|
| Windows `C:/Users/ivano/PycharmProjects/amnezia-client`, исходная ветка `dev` | Предсуществующие локальные изменения, Android/DNS, платформенные исправления, тесты и release-lab | `wip/windows-50318-pause-20261107` |
| Linux `/home/ivano/codex-amnezia-upstream-20261104`, исходная ветка `codex/upstream-5.1.0.6-20261104` | Единственный интеграционный ProductD candidate с upstream и последними native/headless изменениями | `wip/upstream-5106-pause-20261107` |

Общий исходный HEAD до сохранения: `483445232658da1e782f25e2dfb379b95a673db3`.
Upstream MERGE_HEAD candidate: `ac175c8a8147cfe56f98c8372ec17ea2ba00bb02`; неразрешённых конфликтов перед паузой не было. Candidate сохраняется merge-checkpoint с обоими родителями. `dev` и незавершённый локальный merge не переписываются; исходные индексы и assume-unchanged/skip-worktree флаги сохраняются. Поэтому локальные рабочие деревья могут по-прежнему показывать изменения: их содержимое сохранено в отдельных WIP-коммитах, а не очищено или переключено.

На момент паузы физический source manifest candidate содержит **2635 объявленных обычных файлов**:

- `dist/diagnostics/upstream-5106-continuation-a/final-build-readiness-q/native-headless-installer-integration-parent/MATERIALIZED_PRODUCT_SOURCE_MANIFEST.json`
- SHA-256: `63bf398cc97d98d986f9cc99d2a07e1f49aa0f642b8540ab981c26e1259eeec9`.

Это hash manifest-файла и привязка перечисленного исходного кода, а не hash готового приложения или всего неотслеживаемого дерева. Дополнительные документы checkpoint не входят в этот прежний source freeze.

## 2. Что сделано

### Интеграция исходников

- Upstream 5.1.0.6 интегрирован в единственный Linux candidate, с сохранением отдельного Windows-дерева и истории. До checkpoint merge оставался незакоммиченным, но без unmerged entries.
- В candidate сохранены native C++ реализации server/control orchestration: prepare, maintenance, journal, capture/collector, HTTP/PID1/loaded-FD проверки и связанные клиентские вызовы. Это **не означает**, что вся production Python-цепочка уже удалена или все реальные сценарии приняты.
- Интегрированы клиентский native PREPARE, клиентский maintenance/backend handoff, проверки authority и исправления cleanup. Сохранены fail-closed проверки владения, identity/epoch, ролей, хэшей, лимитов и recovery.
- Для headless интегрированы native verifier, stage/metadata обработчики, фактический CMake target и optional `nativeVerifier` role. Canonical manifest producer и C++ потребители поддерживают точные наборы 8 / 9-helper / 9-verifier / 10 файлов.
- Исправлены воспроизведённые ошибки: принятие изменённых bytes после предварительного хэширования; маскирование special mode bits, допускавшее verifier `4755`; неизвестный native wait status, ошибочно трактуемый как успех; blocking-open риск для FIFO; ошибочное утверждение успешного cleanup при реальном остатке файлов.
- Последняя интеграция затронула ровно два shell-файла: `deploy/headless/install_headless.sh` и `deploy/headless/build_headless_release.sh`. Остальные 2633 строки прежнего source manifest и исходные индексы были проверены как неизменённые.
- Native host probe получает аутентифицированный staged **raw `runtime-dependencies.json`**, а не metadata JSON. Необязательное расширение `--package-metadata` из эксперимента X не интегрировалось.

### Реальные сборки и ограниченные проверки

- Собран статический x86_64 verifier: **7 769 672 bytes**, SHA-256 `9e11222529593f8276a5202e4e8569e54ca8383a84152aa438eea5c38171792a`; ELF EXEC без INTERP/DYNAMIC. Этот CMake artifact **не запускался**. Его исходная build-привязка — manifest `0830d940...722`; поздние shell-изменения не меняли C++/CMake/dependencies/link inputs, что проверено отдельно. Он не объявлен свежей final release-сборкой.
- Actual canonical builder создал TEST provisioning package с текущими verifier bytes и текущим installer: **2 937 269 bytes**, SHA-256 `fbf2b36c1e49b654e62ef2841eb0b4b980bf51d265213ff043e74639a963728a`.
- При отсутствии optional verifier role legacy archive совпал byte-for-byte с контрольным producer при одинаковом installer: SHA-256 `976e05e2dd6231d227ec66c398782244e0bf1a93ea43fe7aed1d78bb53de9e9c`.
- Важно: daemon/CLI в этих package-тестах — явно обозначенные **TEST DATA**, полученные через моделируемую CMake-границу. Это не сборка готового headless приложения.
- Проверены actual canonical signer/verifier, archive → receipt → native stage/metadata → фактические shell-guards и rawruntime handoff. Проверены неверные pins, подмена bytes, special modes, отсутствие fallback после native refusal.
- Последний независимый integration gate: **exit 0**; реальное намеренно неуспешное тело → **outer exit 23, componentPass=false**; **3197 входов** сохранили hashes. Проверены `bash -n` обоих интегрированных shell-файлов и сохранность обоих Git-индексов.
- Часть тестов использовала отдельно скомпилированный **inert test main** с точечной моделью UID0 для одного owned каталога и pure worker вместо dpkg. Реальный процесс оставался UID1000. Это **не root-FS, OS dependency, service или release runtime acceptance**.
- Подготовлен согласованный NDK 27.2.12479018 / Clang 18 / Qt 6.10.1 / API28; два реальных Android JNI translation units скомпилированы в AArch64 objects. Полный APK/link/sign/device gate не закрыт.
- Исторические owned Linux component прогоны Docker/native container/native-route сохранены с отдельными capture/cleanup/RAM доказательствами. Их nonce/permit/receipt уже закрыты или spent; они не переиспользуются как свежая финальная приёмка.

### Что не было принято за успех

- AA не реализовал независимый долговременный CURRENT authority producer. Его runner фактически вернул `0` после реального failing work `23` и RESULT `FAILED`; независимая проверка это воспроизвела. Его GREEN не принят как закрытие функции.
- Уточнено: автоматический initial PREPARE уже передаёт доверенный bundled feed hash; whole maintenance допускает строгий same-byte no-op. Не нужно «исправлять» эти существующие свойства на основании слишком широких выводов AA.
- Z предоставил тот же installer `b19da99c...`, который уже был интегрирован. Нового product delta нет. Его baseline отказал из-за асимметричной UID-модели; дополнительное чтение четырёх bytes `TEST` не исполнило существующую ELF-проверку. Эти пункты не засчитаны как закрытие root/runtime.
- Ответ/приёмка BB для headless component extension в существующем release-lab не были подтверждены к моменту паузы. Никаких новых тестов или интеграции BB в рамках сохранения не выполняется.

## 3. Что НЕ сделано

- [ ] Независимая аутентифицированная долговременная CURRENT-привязка для последующего automatic maintenance, replacement, rollback/recovery и повторного закрепления. Нельзя подставлять replacement SHA, unsigned journal или self-receipt загружаемого control.
- [ ] Полное удаление production Python из bootstrap/controller/maintenance/recovery путей. В installer, в частности, остаётся Python-чтение `NATIVE_HELPER_KIND`; recovery/bootstrap зависимости нельзя скрывать в runtime metadata.
- [ ] Полный фактический initial installer path, настоящие root-owned private directories, существующие ELF/runtime checks, installed-root activation и trusted persisted recovery.
- [ ] Приёмка actual headless verifier в свежем proven-owned Linux guest через существующий release-lab. Последняя подготовка: **NOT_ADMITTED / NOT_RUN**, гостевая VM для неё не запускалась.
- [ ] Финальные статические collector / collector-route / awg-feed для **x86_64 и aarch64** как единый завершённый набор из шести бинарников; окончательное встраивание, importer/resource graph и target runtime. Отдельные ранее собранные компоненты не заменяют этот gate.
- [ ] Финальные Windows, Linux GUI, headless и Android APK builds/signatures/update graph с точными final bytes.
- [ ] Все **94 исходных + 12 дополнительных = 106** применимых сценариев со свежими byte-bound доказательствами. В том числе реальное client-driven self-hosted provisioning, все протоколы, peer CRUD/export/import/connect/revoke/delete, persistence и data plane.
- [ ] Свежая four-platform acceptance: Windows/Linux GUI/headless в owned guests и физический USB Android с проверенным serial и сохранением пользовательских данных.
- [ ] Полная self-hosted fixture acceptance: client native exit, complete capture, HTTP hashes, упорядоченные phases, durable archive, cleanup и RAM coverage на финальных artifacts.
- [ ] Production publication и её точное чтение обратно. Публикация разрешена **только** через self-hosted client, вручную запускаемый пользователем после полной приёмки.

## 4. Доказательства и локальные данные

В `docs/development/pause-2026-11-07/` сохранены выбранные source manifests, отчёты и verification source для продолжения. Оригиналы и неуспешные попытки не удалялись.

Основные локальные ссылки:

- `dist/diagnostics/upstream-5106-continuation-a/CURRENT_STATE.md` — состояние до паузы и ссылки на историю.
- `.../final-build-readiness-q/PARENT_NATIVE_HEADLESS_INSTALLER_INTEGRATION_Q.json`, SHA-256 `97008bcd00b222752b5a39c6a579e453f40237cd1fadbb6313a1e00a3de497a8`.
- `.../final-build-readiness-q/PARENT_NATIVE_CURRENT_AUTHORITY_AA_DISPOSITION_Q.json`, SHA-256 `f7d9ffe0c898556713c8da8b6ebea55121117b5ba79ae62b920533cfa28858eb`.
- `.../final-build-readiness-q/PARENT_NATIVE_HEADLESS_INITIAL_Z_DISPOSITION_Q.json`, SHA-256 `4940f95fc8a6b77424f1be84297827b1bfa1737b4526c5d02ffcef3af332cf30`.
- Linux evidence root: `/home/ivano/amnezia-product-50318-q/`.

В Git сохраняются исходники, тесты, безопасная конфигурация и отчётные документы. **Не отправляются** credential/key-файлы, `.env`, raw captures, дампы, build/cache каталоги, installers/APK/VM-диски и большие диагностические деревья `dist/`, `outputs/`, `work/`, `.component-tests/`. Они остаются локально без удаления. Только перечисленных неотслеживаемых локальных исключений Windows на инвентаризации — около **20.95 GiB**; ignored данные в эту оценку не входят. Это source checkpoint, не резервная копия всех локальных binary/evidence bytes.

## 5. Условия безопасного продолжения

1. Требуется новое прямое указание пользователя на возобновление. Этот список не является командой продолжать автоматически.
2. Восстановить именно candidate WIP snapshot, проверить remotes/HEAD, source hashes, submodule commits и сохранённые оригинальные evidence paths. Windows snapshot — отдельное дерево, а не замена candidate.
3. Не считать старые source/model GREEN доказательством root/runtime или final release; не переиспользовать expired/spent receipts/permits.
4. Не нарушать `AGENTS.md`: никаких действий с Amnezia/VPN/installer/updater/службами/сетью Windows host; Android — только разрешённый физический USB телефон без wipe/root/clear/uninstall и повторной успешной установки.
5. Сначала закрыть перечисленные реальные границы и только затем final freeze/build/106 acceptance/manual publication. На момент этой записи **выпуск не готов**.
