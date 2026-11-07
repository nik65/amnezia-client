# Z: фактический начальный native-consumer установщика

Статус: narrow derivative принят фактической цепочкой GREEN; release/runtime/root не заявлены.
Компонент: `componentPass=true`; релиз: `false`.

## Что сделано
- Производный скрипт Z: `src/install_headless.sh`, SHA256 `b19da99c...25d4b` — это Y-исходник без изменений поверх parent corrected U prefix `aea83553...8251`. Продуктовый код не расширялся; тестовые root/stage override не добавлены.
- Закрыта фактическая цепочка (source-only извлечение точных блоков продукта, установщик целиком не исполнялся):
  `--stage-inputs` (реальный inert main из текущих canonical N/W исходников, HEAD `4834452`) -> буквальное переназначение путей после stage -> `--validate-package` (stdout `validated package metadata (host probes deferred): 1.0.0.42`) -> `--probe-host` по authenticated staged `package/runtime-dependencies.json`.
- `probe-host` вернул `hostProbesPassed:true`, `releaseAccepted:false`; 15 dpkg-вызовов отображены на owned pure worker, реальный dpkg не запускался.
- Legacy fallback (Python stage/metadata/receipt heredoc) сохранён; отказ declared-role шага = exit 3 без fallback и без продолжения мутаций.
- Модель: только lstat uid/gid точного dev/ino-pinned owned private dir = 0; реальный процесс uid 1000, реальные copy/hash/checksum/receipt проверки.

## Доказательства
- GREEN: `green-20261107T145542Z`, outer exit 0, componentPass true. Реально исполнены actual `--stage-inputs` (9 файлов), `--validate-package`, `--probe-host`; после цепочки статически прочитаны первые 4 байта staged `amneziad` = `TEST`.
- RED: тот же attempt, базовый selected-a legacy stage block реально исполнен `/usr/bin/python3` -> exit 3, native modes не вызваны. RED = отсутствие native consumer у базового caller, не только отсутствие функций.
- FAILEDWORK: `failedwork-20261107T145542Z`, outer exit 23, componentPass false. Реальное nonzero тело: actual `--stage-inputs` отказал `package checksums fingerprint does not match the trusted release receipt`, consumer exit 3, fallback нет.
- Пины: binary `17b4c76c...be8`, worker `0b4e5d1a...380`, runtime manifest `27617c7e...815`, receipt `995813c1...55e`, key `9e164776...356`, product-source manifest `0830d940...722` (совпадает с текущим). Входы after не изменялись.

## Остаточная граница
- Root activation/uid0 persistent private root и runtime/service не исполнялись — это parent.
- Persisted trusted recovery activation остаётся OPEN.
- `ldd` и `amneziad|amnezia-cli --version` намеренно не исполнялись (запрет запуска продукта); существующие ELF/version проверки достигнуты по коду, но не пройдены реальным запуском.
- Схемы не расширялись: probe получает raw `runtime-dependencies.json` schema 2, metadata JSON не подаётся.
