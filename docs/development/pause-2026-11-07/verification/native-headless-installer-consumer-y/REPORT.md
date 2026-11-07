# Proposal Y: начальный consumer-cutover нативного установщика

Статус: узкий производный скрипт + поведенческие тесты GREEN; реальный скомпилированный
verifier не запускался. rootFS/runtime/release не заявлены. Recovery-активация OPEN.

## Что изменено
- `src/install_headless.sh` (SHA256 b19da99c6a8e79c0a28c73162e8fac790426c8fc0f689e7c28d183e27ea25d4b):
  над parent-reviewed `native-headless-delivery-parent/selected-a` (`aea8355300ff2f4f8f216724db886765fe13d4ec6252f6b23e534407d51c8251`)
  добавлены только `y_stage_inputs`, `y_consume_stage_inputs`, `y_validate_package`,
  `y_probe_host`, `y_consume_metadata` и три guard-точки вызова (+77 строк).
- Условие declared-role: непустой `BOOTSTRAP_VERIFIER` после уже проверенного U-префикса
  (приватный SHA256SUMS snapshot, `EXPECTED_CHECKSUMS_SHA256`, `readelf -h/-l`,
  ELF64 AMD64 EXEC без INTERP/DYNAMIC). Подписи, лимиты байт, deadlines и порядок
  не менялись, test-root/stage override в продукт не добавлены.
- Реальные argv: `--stage-inputs` (source/private/public-key/receipt + 4 expected),
  `--validate-package` (package/receipt/public-key/ubuntu-id/version-id/codename + 4 expected),
  `--probe-host` (runtime-manifest/version-id/codename). Версия пакета берётся из
  фактической строки `validated package metadata (host probes deferred): X`; probe
  принимается только при `hostProbesPassed:true` и `releaseAccepted:false`.
- Legacy no-role: три Python heredoc (stage / metadata+probe / receipt) сохранены без
  изменений. Отказ declared-role нативного шага = exit 3, без Python-fallback и без
  продолжения мутаций.

## Тесты
- `tests/run_y.py` (SHA256 1ab886453a3ef0d2a01d3ab623ad74b5fee47b02541e05d88c6e2b5c7c66bc54): извлекает фактические блоки функций из продукта,
  source-ит только их в свежем bash-child; PATH = один typed stub
  `amnezia-verify-provisioning-native`, который пишет реально переданный argv и
  возвращает управляемый exit/output. Сам install-скрипт не исполняется/source-ится.
- RED: base selected-a -> `a4e05ac136eae6be67fde353c1570c047e8605303da475f0c332ededd4d452ed`, exit 23, 10/11 fail (поведение отсутствует).
- GREEN: Proposal Y -> `a3440316478f9c226da2612b3eba7473943cbe07aae4cb01be70201d54319548`, exit 0, 0/11 fail: точный argv stage/validate/probe,
  отказ без fallback, stop-before-probe, отказ false-success, отказ невалидной версии,
  denied PATH (python3/dpkg/sha256sum недоступны до Bash-child).
- Статическая привязка call-site проверена; `bash -n` = 0.

## Остаточная граница
- Declared role с отсутствующим членом verifier по-прежнему отказывает через legacy
  Python stage; нативная попытка не выполняется.
- `NATIVE_HELPER_KIND` (одна строка чтения manifest) остаётся Python в declared-role
  пути; это не один из трёх нативных режимов.
- Receipt/metadata отказ теперь возникает в `--validate-package` до shell
  `sha256sum --check`; проверки сохранены, порядок отличается.
- Trusted persisted recovery activation и root-owned persistent authority — OPEN;
  unsigned journal/selfauth не добавлены.
