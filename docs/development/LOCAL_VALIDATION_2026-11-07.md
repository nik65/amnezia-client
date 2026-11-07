# Локальные сборки и recovery — 7 ноября 2026

Текущий кандидат — единственное дерево `dev`; базовый checkpoint
`8e5935794c4a44bbe9e5097897ec17777de9d6a1`. Этот документ продолжает
[PREBUILD_FIXES_2026-11-07.md](PREBUILD_FIXES_2026-11-07.md).
Пользователь разрешил все доступные локальные сборки и тесты. Установщики,
VPN/host networking и публикация не запускались. Приёмка на устройствах остаётся
отдельным этапом пользователя.

## Текущее состояние

| Направление | Состояние |
|---|---|
| Durable authority / pending recovery | Store, независимые pins, nonce, live verification, retirement history, probe и PREPARE cleanup реализованы; native/component gates PASS, live SSH/data-plane acceptance не выполнялась |
| Native AWG | Final standalone Debug gate 86/86 PASS, 0 skips, 83.98 с; не guest acceptance |
| Qt Store / receipt | Actual Qt Debug Store/receipt/locator/retry и independent PREPARE sidecar delta PASS |
| Linux GUI | Полный Debug build GUI + service + всех 31 legacy test executable PASS; 66/66 focused + 5/5 safe legacy + actual Xray gate PASS |
| Core models/settings | Все 8 дополнительных suites PASS: 5 на host, 3 с autostart side effects только в owned offline containers; 68 Qt rows, без failures/skips |
| Android | ARM64 OSS + Play Debug APK build PASS; подпись/ZIP/117 native entries/16KiB/423 JNI checks PASS; физическое устройство NOT RUN |
| Headless verifier | Реальная static Release-сборка после strip 8 043 792 B; signed-role/FIFO delta PASS, не Ubuntu release acceptance |
| Headless recovery anchor | 14/14 headless и 2/2 verifier CTest PASS; отдельный UID0 container gate helper 8/8 + CLI 8/8 + anchor 24 + journal 24 + shell 16 PASS, без skips |
| Combined Python / release contracts | 281 PASS + 12 ожидаемых Windows/WSL skips; отдельно 51 pytest PASS + 8 subtests, без skips |
| Server native resources | Все 6 static ELF собраны на Ubuntu 24.04, strict importer PASS; x86 offline parser tests PASS, aarch64 compile/ELF only |
| Xray config compatibility | Точный Core 26.7.28 из текущего pinned dependency graph: 368 Qt cases PASS, без failures/skips; только version/TLS fixture/config `-test` |
| AWG union | Реальные Go 1.26 host tests: 10 tests + 6 subtests PASS, отдельно `-race` PASS; только in-memory TUN и owned loopback |
| Windows / Linux guests / physical Android | NOT RUN: отдельная приёмка пользователя |
| Production release | NOT READY, `releasePass=false`, `published=false` |

Доступный локальный critical path завершён: product builds, исправления
обнаруженных ошибок, source freeze и final gates. Следующий этап — production
configuration/signing, финальные release bytes и отдельная приёмка устройств.
Неизвестные remote journals и отсутствие journal после потери SSH не разрешают
сбрасывать pending intent или подменять доверенный pin.

Локальные логи и verified toolchains находятся в `/workspace/.setup/`;
исторические неуспешные попытки сохраняются отдельно от последующих результатов.
Они не являются переносимыми release receipts.

## Исправления и проверенные границы

- PREPARE записывает независимый bundled pin и случайный operation UUID до
  первого mutating control command. CURRENT не выводится из unsigned remote
  journal. Status не завершает pending intent; verify/recover требуют отдельного
  доказательства готового live-состояния и точного исходного nonce.
- Незавершённый native PREPARE сначала получает read-only inspection. Abort
  разрешён только для точно связанного partial intent и подтверждённого удаления
  его собственных компонентов/правил. Retirement сохраняет journal hash и nonce;
  следующая попытка использует новый UUID и большее поколение. Неизвестные
  поколения, чужие компоненты и неполная очистка блокируют продолжение.
- История максимум из 32 отменённых поколений передаётся как canonical JSON/base64.
  Native journal удерживает общий lock через проверку предшественников и создание
  следующего поколения. Повторная проверка перед side effects обнаруживает
  изменение predecessor. Locator учитывает только локально сохранённую историю;
  remote discovery не создаёт доверенный executable pin.
- UI не сообщает о готовом endpoint после retirement. Повтор требует полного
  проверенного abort receipt, неизменных credentials/source/endpoint и отсутствия
  cleanup failure; отдельный лимит — три попытки, и `cancel()` не восстанавливает
  исчерпанный лимит.
- Maintenance/recovery probe cleanup сохраняет точные root inode/device и фиксированные пути до upload
  и exec. Начало maintenance атомарно переносит этот overlay в необходимые recovery
  inputs. Неопределённая запись authority сохраняет эти inputs; cleanup оригинала
  не выполняется до подтверждённого восстановления. Cleanup acknowledgement
  допускает уже отсутствующий exact root, но не заменяет сохранённую inode authority.
- У PREPARE отдельный cleanup sidecar, который работает и до создания main
  authority record. Он сохраняет обе точные директории до upload/preflight,
  переживает restart и не превращает неудачный preflight в pending operation.
  Ошибка основной операции сохраняется вместе с cleanup hints; ledger удаляется
  только после проверки отсутствия обеих директорий. Native prepare и прямые
  operator maintenance/recovery сначала завершают прежнюю cleanup obligation.
- Private migration store отказывает для FIFO/symlink/неверных прав и размера,
  не зависает на special files и не заменяет частично записанный ключ. Qt storage
  authority отделён от обычных application settings; Android не переключает
  расположение хранилища в зависимости от текущей доступности каталога.
- Docker inspect failure сам по себе не доказывает отсутствие контейнера. Native
  production adapters требуют успешной полной и строго разобранной inventory;
  ошибочная, усечённая или содержащая нужный ID/name inventory блокирует cleanup.
- JSON topology adapter сохраняет валидный Unicode, включая non-BMP, после
  строгой исходной проверки. Исправлена несовместимость json-c 0.18 с raw UTF-8
  при strict parsing; malformed UTF-8, duplicate keys и NUL остаются отказами.
- Headless installer проверяет ранее сохранённый root-owned native anchor через
  независимый PIN до первого exec; поздний producer использует authenticated
  checksum row. CURRENT/PIN/protocol сравниваются побайтово, включая NUL/LF.
  Canonical package с native verifier + CLI не требует runtime Python; legacy
  recovery и legacy packages явно проверяют эту зависимость.
- Focused и legacy CMake tests можно включать вместе без повторной регистрации.
  Configure dependencies нормализованы, поэтому Ninja больше не получает две
  phony rules для одного исходника. Исправлены три устаревших конструктора в
  legacy tests и anonymous enum в публичном результате ImportController.
- Изолированные daemon/log fixtures сохраняют собственный compile context при
  включении в GUI build. Generation `production_methods.inc` отделена от AUTOMOC,
  поэтому повторный build не образует Ninja dependency cycle. Windows source
  contracts проверяют конкретные guards/postconditions вместо общего счётчика строк.
- Importer не перезаписывает неизменный `serverNativeBundle.qrc` при каждом
  configure. Отрицательная проверка воспроизводит прежний mtime defect, 27 importer
  cases PASS. Финальные configure/build/no-op сохранили SHA и mtime QRC, generated
  C++, resource object, GUI и service: повторной компиляции большого resource нет.
- AWG Android recipe клонирует pinned source в пустой временный checkout и только
  после проверки root/submodule pins переносит его рядом с exported overlay.
  Проверки collision и relocation не позволяют частично заменить exported files.
  Реальный clean Conan source regression и последующая NDK/Go сборка прошли.
- DNSTT PIE получает роль executable при Qt packaging, исключающую startup
  `System.load`. Реальный `androiddeployqt --aux-mode` подтвердил копирование тех
  же проверенных bytes. RED воспроизводит опасное поведение стандартного Qt
  template; текущий product `libs.xml` уже исключал `INSERT_EXTRA_LIBS` и тем самым
  подавлял autoload. Это исправление роли и защита от template regression,
  а не доказанное падение текущего продукта или запуск DNS transport на телефоне.

## Evidence этого этапа

Все пути ниже локальны для текущего облака. Непройденные первые попытки сохранены.

| Gate | Evidence в `/workspace/.setup/` |
|---|---|
| Native 86/86, exact 149 source hashes | `native-recovery-validation/predecessors-run.json` |
| Store/probe/receipt delta | `recovery-validation/authority-probe-cleanup/`, `recovery-validation/qt-partial-abort/` |
| PREPARE independent sidecar | `recovery-validation/authority-prepare-sidecar/`, `current-audit/prepare-cleanup-*` |
| Locator / bounded retry | `current-audit/prepare-locator-*.log`, `retirement-retry-validation/` |
| Headless host + genuine UID0 delta | `native-anchor-validation/`, `native-anchor-root-container/RESULT.json` |
| Final combined Python | `combined-final-python/summary.json` |
| Full Linux build + final 66/5/Core gates | `desktop-gui-final-validation/RESULT.json`, `desktop-gui-final-validation/EVIDENCE-SHA256.json` |
| Additional Core model suites | `core-model-final-validation/results.json`, `core-model-container-validation/SUMMARY.json` |
| Six-role server bundle + provenance | `server-native-final-bundle/provenance.json`, `server-native-final-bundle/bundle/manifest.json` |
| Android final APKs + exact source/build-metadata impact | `android-host-validation/apk-build-attempt1/frozen-summary.json` |
| DNSTT exact product/default template comparison | `android-host-validation/dnstt-packaging-final-results.json` |
| AWG real Conan source regression | `android-host-validation/awg-source-regression/` |
| Exact pinned Xray Core | `xray-core-compat/provenance.json` |

Повторяемая подготовка server resources описана в
[SERVER_NATIVE_BUNDLE.md](SERVER_NATIVE_BUNDLE.md). Manifest SHA256:
`f9890fdfc08c99ef2f9c1727ecc0d1bf88a9eb8a26af0e8ff5e928be9f3280b2`.
Source snapshot включает новые headers и совпадает с native 86/86 gate.
Независимая повторная сборка x86 collector дала идентичные stripped bytes.

Для локального GUI configure и последующего build используется один и тот же
environment, включая `CONAN_HOME`, Qt prefix и (при staged system dependencies)
`PKG_CONFIG_SYSROOT_DIR` / `PKG_CONFIG_LIBDIR` и `LIBRARY_PATH`. Runtime tests
используют соответствующие Qt/Conan/sysroot library paths. Ninja вправе автоматически
перезапустить CMake. Потеря этих переменных при build привела к отдельной
остановленной попытке с другим Conan cache; она не считается успешной сборкой.
Текущая команда закреплена в `.setup/build-desktop-recovery.sh` вне Git.

Весь legacy test code компилируется, но live VPN/SSH/provisioning и export с
реальными credentials не запускаются на облачном host. Для безопасного local gate
выбраны focused tests и пять legacy tests:
`XrayServerInboundTest`, `XrayGeneratorMatrixTest`, `XrayConfigModelTest`,
`OpenSSLLibraryTest`, `LogsControllerTest`. HOME остаётся исходным; временный
XDG_DATA_HOME располагается в приватном каталоге внутри реального HOME.
Оставшиеся legacy integration tests не получают вымышленный PASS. Восемь
дополнительных Core model/settings suites проверены отдельно: безопасные пять
на host, три пишущих `HOME/.config/autostart` — только в disposable offline
containers с настоящим default HOME=/root, private tmpfs и read-only runtime
snapshot. Ни host HOME, ни исходники/бинарники не менялись; containers удалены.

## Полученные developer artifacts

Это Debug-сборки для локальной проверки, не финальные release bytes. Встроенный
Git label относится к исходному build checkpoint; точная текущая source binding
записана отдельными hashes в evidence. Production endpoint/public-key inputs
не подставлялись. Gradle Debug signing не заменяет production signing.

| Artifact | Bytes | SHA256 |
|---|---:|---|
| Linux GUI Debug, Debian 13 / GCC 14 | 184376536 | `3cd3eec29987ed7eeeebeef8ad84d556769e38b34ff60ca9f503bc8b3d1bfab4` |
| Android OSS ARM64 Debug APK | 119131632 | `a637e1da619e506fbcc7a422e98dad16040a10384e596b3229a9f2877eb7c417` |
| Android Play ARM64 Debug APK | 119746707 | `fae2bcb6da330eb14569a72bdfd2cd5c03a77b0aa55edefdb2e093d758532368` |

Android: `org.amnezia.vpn`, versionName `5.0.3.18`, versionCode `2204`, targetSdk
`36`, `debuggable=true`, `extractNativeLibs=true`. У обоих APK проверены zipalign
`-P16`, CRC, Debug certificate signature, PT_LOAD alignment всех 117 native entries,
416 OpenVPN + 7 AWG JNI declarations/exports и точные DNSTT bytes.

Изменение importer во время Gradle явно учтено как build metadata delta:
fresh importer генерирует идентичный XML, все 7 resource payload bindings и
byte-identical RCC C++. После freeze native incremental build сообщил no work;
staged main/Qt libraries совпадают с упакованными. Изменения docs/test graph
не требуют повторной сборки неизменных APK bytes.

## Что не подтверждено этим этапом

Полные Windows/Linux GUI/headless guest-сценарии, реальный SSH/data plane,
установленная Ubuntu ABI/runtime compatibility, platform keychain/storage на
Windows/Android и физический Android остаются отдельными gates. Container UID0
filesystem fixtures не заменяют release-lab guest acceptance. AArch64 binaries
не запускались. Production signing inputs и endpoint/public-key configuration
для финального выпуска не создавались и не подменялись тестовыми. Debug APK
может использовать стандартную тестовую подпись; она не является release signing.

Если SSH потерян до появления remote journal, pending PREPARE сохраняется.
Отсутствие файла не доказывает, что исходная операция никогда не начнётся;
автоматического reset/повторного запуска в этом неоднозначном случае нет.

## Подготовка Windows release-кандидата на физическом ПК

Исправлены три подтверждённых препятствия: выбор `vswhere` теперь требует
установленный C++ toolchain; release wrappers передают явный N-1 outer installer
в лабораторию; удалены семь случайных Debian control metadata из каталога с
именем `\`, из-за которого обычный Windows Git checkout завершался ошибкой.
Эти metadata остаются в Git history; Android sandbox implementation не менялся.

На Windows проверены реальный CMD selector (четыре случая, включая старый
selector как negative control) и PowerShell 5.1: syntax обоих wrappers,
передача путей с пробелом/апострофом, независимость `LabLane off` и отказ до
backend при отсутствующем baseline outer. Полные release scripts, установщики
и VM для этих smoke tests не запускались. Локальная объединённая дельта:
7 PASS, 1 Windows-only SKIP, 10 subtests PASS; Windows-only consumer отдельно PASS.

SDK и кэши готовятся в отдельном owned workspace аккаунта `codexbuild`.
Paused Windows worktree и работающий VPN хоста не изменялись. Это подготовка
сборки, не результат установленной Release-приёмки: production configuration,
подписанные финальные bytes, Windows/Linux guests и физический USB Android
ещё требуют собственных проверок.
