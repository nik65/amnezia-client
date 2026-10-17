# Проверка AWG 3.1 — 17.10.2026

Версия 5.0.3.11 / Android 2197: четыре production-сборки и статическая проверка шести пакетов завершены. Windows installer matrix 6/6 и отдельный UI/UAC прошли в принадлежащих запуску Hyper-V гостях, очистка подтверждена. Это не приёмка AWG-миграции или причины managed-route разрывов. Linux runtime заблокирован KVM ENODEV; Android ожидает реального телефона. Публикация и общий release PASS отсутствуют.

Product commit `68dd9e29a1d608730252bb0db709314570c078d4`; source manifest `ca7ff892bc034d7a5e77fc9fafaab2625af92fcecb91cabebac4dbd50bd33ee8`: 2 436 физических файлов и 7 исторических Git blobs повторно сверены без изменений. Подписанный release manifest `02a8f3aec68c2dfde8606909db7f0f7adfc094d1710de62d71d428bba69d37f0`. Основная офлайн-квитанция: `dist/release-candidate-5.0.3.11-20261017/source-freeze/build-logs/FINAL_OFFLINE_BUILD_CLOSURE.json`.

| Файл | Байт | SHA256 |
|---|---:|---|
| AmneziaHeadless_5.0.3.11_linux_x64.tar.gz | 6472155 | `e29ea6bbb809d7e0a4f295773f0615c8cdf20fb6bdebd89f46e4e9d59d0cc1dd` |
| AmneziaHeadless_5.0.3.11_linux_x64_provisioning.tar.gz | 6489762 | `0372f21147718cc5180010594b8f18a5c6fa33ec2221d898479c310cd1f93eaa` |
| AmneziaVPN_5.0.3.11_android9+_arm64-v8a.apk | 77986927 | `66311e5376f4da8fed36842b3106f41d60f3b3ecad1ee88d2d10ccd248037e69` |
| AmneziaVPN_5.0.3.11_linux_x64.run | 122949638 | `4e260181c9bcb87af2ef19e5ba8bdd880dce13b253b86c3cee8425fca82e96e0` |
| AmneziaVPN_5.0.3.11_windows_x64.exe | 90126872 | `c37d031c8850aaed21a5359c8f2d6a59c84bac3a5aa2fb4d7d6983e67b8ef0e6` |
| AmneziaVPN_5.0.3.11_windows_x64_selfhosted.exe | 335501308 | `4f64701352b8b79c89560782d79d7f1d3624e8e17526fc6ef01ec03fee8b5db5` |

Статическая QA подтверждает Windows PE metadata/payload/AWG3 и восемь серверных скриптов, Linux установленный payload/ELF resources, Headless ABI/provisioning/engine, Android JNI build chain, V3-подпись, 2197, экспорты и union DEX. Эти проверки не доказывают работу на реальном устройстве.

## Windows и лаборатория

Run `awg311-win-20261017-final182d`: исполнитель runtime `d74d2ee08d606aaa000b540de5b834e9d6202977ba0f2a616a4caaa8497e194f`; суффикс 182d исторический. Шесть сценариев thin/outer clean, upgrade и reinstall подтверждают точные c37d/4f647 пакеты, установленную 5.0.3.11 и работающую службу. Каждый child удалён, parent `8ded92f7c7a2f522dd6609f6afbb9e023515055ac3cd3db1309df9214e7275cb` неизменён. UI/UAC подтверждён отдельной гостевой квитанцией origin=guest, injected=false, interactive_verified=true. Часы гостя смещены; хронология определяется контроллером.

Supported collect завершён после узкой проверенной поправки агрегации: collector `b29226e77847ddff3f3d6695174cf7291f9b09f29d1f58fa6be414892f7ba223`, без повторного гостевого запуска. `windowsb292-collected.json` SHA256 `95474edef86362f6e621e9cc2f776d430c8a3fcfc526ac66e2bec978ec1d2786`; integrity `53e64e4165beadafc58c454ae1f9a4f9efff8157b0d8833cdd23ae2fd740a162` подтверждает неизменность исходных steps/case/UI/cleanup. Все эти квитанции находятся в `dist/diagnostics/awg31-migration-20261017/`.

Linux KVM действительно возвращает ENODEV при существующем `/dev/kvm`; final readiness корректно ready=false. Неудавшийся owned run очищен, логи сохранены. Полная GUI AWG-миграция технически не воспроизводится текущим Hyper-V транспортом: NIC none и фиксированный relay не обеспечивают произвольный server/UDP trial. Это транспортная граница, не отсутствие разрешения пользователя. Общая миграционная приёмка остаётся pending.

## Проверки кода и Android

CTest контроллера 4/4; шесть production-controller сценариев плюс init/cleanup 8/8, настоящая криптография, примитивные storage/network doubles. Полный Linux routing suite 80/80, CTest 1/1; fake commands не проверяют реальное ядро/watchdog. Windows routing harness имеет 68 успешных/13 ошибочных результатов как до, так и после патча и не называется PASS. Очистка 1 217 правил в контролируемом production-code тесте ускорена 44 003 → 202 мс; это не доказательство исторической причины разрывов.

Android production NetworkState JVM, текущие Go race/loopback union и Kotlin config тесты успешны. APK minSDK28 допускает Android9, но объединённый AWG/WG included-app/site OR требует Android10/API29: API28 отказывается до TUN. Сервис передаёт точную причину, Activity→Qt оставляет generic serviceError; ясное требование в UI не подтверждено. JNI/телефонная приёмка остаётся pending. Named evidence: `android-owner/api28-union-limitation-receipt.json`, `union-native-current-receipt.json`, `config-routing-current-receipt.json` в каталоге расследования.

## Логи и серверные исправления

Сохранены отдельные исторические снимки: 1 235 uploaded logs, первая дельта 38, финальная 184; это не одновременное состояние сервера. Финальные 184 файла: 5 805 строк, 650 800 байт, хеши сверены. В 18:16:15.008 повторился Windows managed-route reconnect; connected route base через 8,877 с, затем ConfigurationRejected. Интернет-восстановление и точная rejecting branch не измерены; Windows-версии в дельте неизвестны.

Полный финальный journal: 40 419 записей, все 31 289 binary MESSAGE массивов декодированы. Подтверждены OSConfig no-token, SSH preauth ошибки, direct timeout/unreachable, ICMP capability warnings и proxy timeout/bad-FD симптомы. Отсутствие protocol-specific error labels не является health proof. Базовый journal полностью просмотрен offline: 976 649 строк с 39 сохранёнными continuation. Источники: `server-owner/final-delta-20261017T183206Z/{FINAL_DELTA_SUMMARY,DISPOSITION}.md`, `service-correlation/BASELINE_ALL_APPS_SEMANTIC.md`.

TC fix canonical 93a3 применён около 17:59 UTC; 18:02 — последующая независимая приёмка. IFB/qdisc/filter/redirect сохраняются при обновлении скоростей, намеренная потеря 10% сохранена. Два естественных timer tick 18:04:55Z и 18:11:56Z — успешные no-op, шесть protected identities/pins неизменны. Реальный peer-трафик не измерен; Windows 18:16 episode не устранён и не доказывает причинную связь с tc.

Fallback: 84 решения 16 октября 17:54:21.889542–18:15:23.047513 UTC, raw lines 450293–512676, отражают один degradation window. Canonical branch намеренно возвращает 1 до переключения, когда здоровых кандидатов нет. Паритет historical deployed code/config неизвестен; shared probe endpoint — гипотеза. Функциональный fallback patch не обоснован. Источник: `server-owner/FALLBACK_UNAVAILABLE_OFFLINE_TRIAGE.md`.

Итоговый серверный статус, отдельно от Amnezia release: proxy 6ecba529327616047d91e72490be2a7fad514b17 развёрнут и проверен независимым свежим снимком 19:30:29.831616 UTC — 14/14 checks PASS. Canonical/remote clean, 18 support и 48 guarded app файлов точны; ожидаемый LF proxy 42ae загружен новыми listener-процессами в двух VPN netns. Защищённые process lifetimes, routes/rules и контейнеры неизменны. Естественный runner invocation 07248d1bce044532947ba1fb7c2b1c7d завершён success0 с exact HEAD/no action; timer active/enabled, HOLD отсутствует. Квитанция server-owner/narrow-provenance/proxy-transaction/PROXY_INDEPENDENT_LIVE_ACCEPTANCE_RECEIPT.json, SHA256 09b7147f189886768e099b3c58b6edb91d03e83a5d2b44ff59e534aef8e57daf. Это обновляет прежний промежуточный HOLD; исходные датированные квитанции сохранены. Реальный peer/Internet traffic не проверялся, историческая причинность proxy ошибок остаётся недоказанной. Root повторно прочитал все шесть release-артефактов после Windows: хеши совпали; публикация по-прежнему не выполнялась.

Публикация HOLD: selfhosted flow технически способен публиковать без lab gate; успешная сборка/installer matrix не даёт основания его запускать. Открыты AWG/native managed-route приёмка, Linux runtime, Android phone/JNI и историческая причинность. Общий PASS не заявляется.

