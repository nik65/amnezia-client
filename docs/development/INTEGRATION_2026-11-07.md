# Объединение dev и подготовка 5.0.3.18 — 7 ноября 2026

Продолжение до сборок: [PREBUILD_FIXES_2026-11-07.md](PREBUILD_FIXES_2026-11-07.md).
Ниже сохранены результаты исходного integration checkpoint; они не подтверждают
сборку последующих изменений C++.

Разработка возобновлена по запросу пользователя. Отчёт
`DEVELOPMENT_PAUSE_2026-11-07.md` сохранён как исторический checkpoint.
Проверка Windows/Linux на устройствах и физического Android выполняется
пользователем отдельно; облачные component-тесты её не заменяют.

**Состояние: интеграция исходников выполнена; production release NOT READY.**
`allFunctionsPass=false`, `releasePass=false`, `published=false`.

## Что объединено

Все перечисленные удалённые ветки включены в историю `dev` с сохранением родителей:

| Ветка | Включённый tip |
|---|---|
| `wip/upstream-5106-pause-20261107` | `2d5958bbc83bb26c91290a526abd97d069a1911b` |
| `wip/windows-50318-pause-20261107` | `a308f25ecab887cd0b04d0ea50893c2a49893d60` |
| `build/windows-ipv6-fix` | `def42202b037a5cc735d3f1ff05f975d945b89c2` |
| `build/windows-ipv6-fix-v2` | `342466ee6f2986057386df235a81f4cb75f9767e` |
| `build-status/windows-ipv6-fix` | `ad620dbe3a83284fe5c6e0ac86d9894628f28140` |

Основа `dev`: `483445232658da1e782f25e2dfb379b95a673db3`.
Checkpoint исправленного кода и тестов: `aef34e4d3e23f5f07339e44818a526947e1a3495`.
Upstream 5.1.0.6 входит через второй родитель candidate
`ac175c8a8147cfe56f98c8372ec17ea2ba00bb02`.
Проверка: `git merge-base --is-ancestor <tip> dev` для каждой строки.

267 из 275 конфликтов двух WIP-снимков оказались различиями CRLF/LF.
Оставшиеся разрешены в пользу upstream-aware API: централизованный XHTTP
generator, остановка протоколов, signal handlers и единственная DNS transport
регистрация. Не восстановлены устаревшие одноразовые Windows CI workflow/trigger:
продуктовое исправление IPv6 уже присутствовало в `dev`.

Исходные Windows/Linux рабочие деревья, локальные merge/index flags, ключи и
сырые артефакты из отчёта о паузе в этой облачной машине отсутствуют и не менялись.

## Исправления после объединения

- Sanitizer больше не вызывает `QByteArray::first(limit)` на коротком блоке:
  `left(limit)` сохраняет обработку границы секретов без assertion/выхода.
  Добавлен регрессионный тест разделённого ключа и короткого суффикса.
- Восстановлена ранняя проверка выбранного gateway RSA public key перед
  upstream update check. Self-hosted channel сохраняет свой путь; upstream
  `isAvailable()` остаётся проверкой инициализации, а не формата ключа.
- `cmake/version.cmake` задаёт общий default `5.0.3.18` для GUI и standalone
  headless; явные `HEADLESS_BUILD_VERSION`/`AMNEZIAVPN_VERSION` сохраняют приоритет.
  Устранён standalone default `5.0.1.37`. Android versionCode остаётся `2204`.
- В standalone C++ discovery-тест добавлен include-root для новых transitive headers.
- Routing fixture обслуживает VPN-внутренний URL через локальный HTTP proxy,
  без IP прежнего компьютера и без настоящих route/VPN изменений.
- Unsafe-parent fixture явно создаёт небезопасные права, не полагаясь на `TMPDIR`.
- Source contracts приведены к текущим API: captured protocol cleanup, diagnostic
  return wrapper, Swift bridge, extracted share sheet, private bootstrap helpers,
  checksum array и единый владелец `protocolError`. Добавлена fixture версии .18.
  Тесты больше не требуют приватного ignored `dist/selfhosted-release-env.ps1`.

## Что фактически проверено

Облако: Debian 13, GCC 14, CMake 3.31.6, Ninja 1.11.1, Qt 6.8.2, OpenSSL 3.5.7.
Это developer-сборка, не Ubuntu release artifact.

| Проверка | Результат |
|---|---|
| Headless Debug build + CTest | PASS, 11/11 targets; внутри native FS один root-only skip |
| Sanitizer standalone | PASS, включая короткий boundary и большой corpus |
| Фактическое тело gateway RSA validator + production CryptoUtils | PASS, 10 проверок формата ключей и выбора prod/dev; не полная GUI-сборка |
| Daemon/CLI | `--version` = 5.0.3.18; `status` disconnected и `list-profiles` пустой, оба `ok:true` |
| Явные version overrides | Проверены отдельные configure graphs для обоих параметров |
| XHTTP / DNS fallback / Linux gateway ownership | PASS, 1 + 1 + 2 CTest entries |
| Protocol error / Android restored session / C++ discovery | PASS, host-side tests; это не APK/device acceptance |
| Native bundle, provisioning, migration, update policy, IPC, gateway context | PASS, 13 CTest entries в 9 модулях |
| Route reconcile, DNS convergence, rule matcher, health probe, UAPI, bounded reply, payload codec | PASS, 10 CTest entries в 7 модулях |
| Python contracts | OK, 231 tests: 219 pass, 12 skip из-за отсутствия Windows PowerShell/WSL; 201.592 с |
| Release acceptance contracts | PASS, 51 tests + 8 subtests; синтетические artifacts/mocks, не guest acceptance |
| Resource graph | Все 616 tracked QRC file entries существуют |
| Полный GUI configure | BLOCKED: Conan registry CONNECT 403 |
| Release-lab preflight | BLOCKED, exit 2; никаких guest/installer/VPN запусков |

Первоначальные failures сохранены отдельно от исправленных прогонов в
`/workspace/.setup/`: `headless-merged-tests-final.log`, `sanitizer-merged-tests.log`,
`merge-xray/`, `runtime-focused-review/`, `merge-python/`, `release-preflight.json`,
`desktop-configure.log`. Это локальные логи, их наличие в будущем checkout не
гарантируется. Никакие старые receipts не объявлены свежей приёмкой.

Минимальный повторяемый headless gate из корня checkout (Qt/CMake уже установлены):

```bash
export PATH=/workspace/.setup/venv/bin:$PATH
mkdir -p /workspace/.setup/tmp
chmod 700 /workspace/.setup/tmp
export TMPDIR=/workspace/.setup/tmp
cmake -S headless -B /workspace/.setup/build-headless-merged -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON \
  -DCMAKE_PREFIX_PATH=/workspace/.setup/sysroot/usr
cmake --build /workspace/.setup/build-headless-merged --parallel 4
ctest --test-dir /workspace/.setup/build-headless-merged --output-on-failure --parallel 2
```

Для остальных native модулей используется тот же configure/build/ctest с
`-S client/tests/<module>` и отдельным `-B`. Python contracts требуют `patch-ng`;
Windows/privileged checks могут явно пропускаться на Linux/UID1000. Пропуск не PASS.

Повтор Python-gate из корня checkout:

```bash
python3 -m venv /workspace/.setup/venv
/workspace/.setup/venv/bin/pip install patch-ng==1.18.1 pytest==9.2.0 cryptography==50.0.2
PYTHONDONTWRITEBYTECODE=1 /workspace/.setup/venv/bin/python -m unittest \
  deploy.selfhosted_updates.test_selfhosted_updates \
  client.core.controllers.selfhosted.test_client_logs_collector \
  client.tests.privileged_ipc_security.test_security_source_contracts \
  deploy.headless.test_native_helper_bundle \
  deploy.headless.test_awg_migration_wire_contract \
  deploy.headless.test_cli_native_bundle
PYTHONDONTWRITEBYTECODE=1 /workspace/.setup/venv/bin/python -m pytest -q \
  deploy/release_lab/test_coordinated_release_acceptance.py \
  deploy/release_lab/test_coordinated_release_acceptance_integration.py \
  deploy/release_lab/test_trusted_acceptance_handoff.py \
  deploy/release_lab/test_headless_native_acceptance.py
```

## Незакрытые требования до выпуска

1. **Durable CURRENT authority:** текущий maintenance правильно требует внешний
   доверенный pin, но независимый producer/store/lifecycle после PREPARE,
   replacement, rollback/recovery не завершён. Сейчас pin задаётся явным
   операторским JSON. Нельзя заменить его новым bundled SHA или unsigned journal.
2. **Native-only production path из pause-report не завершён:** installer всё ещё
   требует Python для bootstrap/recovery и выбора helper; legacy controller
   prepare/maintenance остаются Python. Частичный перенос не закрывает это требование.
3. **Полные финальные сборки и resource graph:** нужны Conan-доступ к
   `center2.conan.io` и `artifactory.amnezia.org` (оба запрещены прокси), полный Qt
   kit, платформенные toolchains, pinned AWG3 resource/Go и signing inputs.
   Шесть финальных static server binaries и полный APK/signing gate не выполнены.
4. **Ubuntu ABI:** финальный headless builder объявляет Ubuntu 24.04/noble;
   Debian13 dev-бинарники не принимаются как проверенные release bytes.
5. **Свежая приёмка:** 106 сценариев, Windows/Linux GUI/headless owned guests,
   физический Android и self-hosted fixture/data-plane/capture/cleanup. В облаке
   нет `/dev/kvm`, QEMU/swtpm, sealed goldens/readiness, lab identity или телефона.
   Пользователь выбрал отдельную проверку устройств.
6. После исправления code blockers: freeze -> final builds -> byte-bound acceptance.
   Публикация только после полного gate, через вручную запущенный self-hosted client
   согласно `AGENTS.md`. В этом задании релиз не публиковался.
