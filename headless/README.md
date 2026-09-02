# AmneziaVPN headless client для Ubuntu

`headless/` — отдельный native Linux target без QML, GUI и system tray. Он состоит из:

- `amneziad` — долгоживущий daemon на `QCoreApplication`;
- `amnezia-cli` — короткоживущий CLI-клиент;
- versioned JSON-lines IPC поверх `QLocalServer`/`QLocalSocket`;
- атомарного profile store, содержащего только безопасные метаданные профилей.

Профиль с `autoConnect: true` поднимается daemon-ом после старта systemd-сервиса;
одновременно автоматически подключается не более одного такого профиля. Для VPN-only
имён профиль может задать `dnsServers` и route-only `dnsDomains` (например,
`["10.8.1.0"]` и `["~local"]`); daemon назначает их только на VPN-интерфейс и
снимает при отключении.

## Сборка

Зависимости: Ubuntu/Linux, CMake 3.25+, C++17 и Qt 6 modules `Core`, `Network`.
Модуль `Test` нужен только при `-DBUILD_TESTING=ON`; release-сборка принудительно
использует `-DBUILD_TESTING=OFF`.

Standalone-сборка target:

```bash
cmake -S headless -B build-headless -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build build-headless --target amneziad amnezia-cli
```

При пакетировании ключ доверия provision-ится отдельным deployment-шагом, например
`cmake -S headless -B build-headless -DAMNEZIA_HEADLESS_UPDATE_PUBLIC_KEY=/secure/update-public-key.pem`.
Установочный пакет копирует его в `/etc/amnezia/update-public-key.pem`; update tarball
не имеет права заменять этот файл. Пакет также должен создать system group `amnezia`,
установить `amneziad.service` и выполнить `systemctl daemon-reload`/`enable --now` с
явным административным подтверждением.

Для release-артефакта Ubuntu используется `deploy/headless/build_headless_release.sh`.
Он создаёт tar.gz только с `amneziad` и `amnezia-cli`; затем
`deploy/headless/make_headless_manifest.py` публикует подписанный
`linux-headless-x64`-манифест. Обычный `linux-x64` GUI `.run` намеренно не считается
подходящим headless-обновлением. Скрипт также создаёт отдельный provisioning bundle
с unit-файлом, trust-anchor input, `runtime-dependencies.txt` и `SHA256SUMS`;
`install_headless.sh` принимает путь и SHA-256 receipt trust anchor, проверяет команды,
динамические библиотеки, целостность bundle, Ed25519 trust anchor, socket/health и только
затем включает systemd unit: `sudo ./install_headless.sh /secure/update-public-key.pem <sha256>`.
В общий self-hosted manifest headless публикуется только при `--payload-schema 1`:
schema 2 содержит `releasePolicy`, которую этот daemon пока не потребляет.

В составе основного проекта target включается явно:

```bash
cmake -S . -B build -DAMNEZIAVPN_BUILD_HEADLESS=ON
cmake --build build --target amneziad amnezia-cli
```

На Windows, macOS, Android и iOS этот target намеренно не включается: Ubuntu headless-режим требует native Linux build.

## Запуск

По умолчанию daemon использует `$XDG_RUNTIME_DIR/amneziad.sock` и профильное хранилище в
`$XDG_STATE_HOME/amnezia/profiles.json` (fallback — `~/.local/state/amnezia/profiles.json`).
На машине без `XDG_RUNTIME_DIR` fallback для socket — временный каталог Qt; для production следует использовать private runtime directory.

```bash
amneziad \
  --socket "$XDG_RUNTIME_DIR/amneziad.sock" \
  --store "$HOME/.local/state/amnezia/profiles.json" \
  --config-root "$HOME/.config/amnezia/profiles" \
  --staging-root "$XDG_RUNTIME_DIR"
```

CLI подключается к тому же socket:

```bash
amnezia-cli status
amnezia-cli list-profiles
amnezia-cli doctor --json
amnezia-cli import ./profile.json
amnezia-cli export <profile-id> --output ./profile-export.json
amnezia-cli connect <profile-id>
amnezia-cli disconnect
amnezia-cli update-rollback
```

`--json` печатает полный JSON-ответ. `connect` запускает adapter выбранного профиля:
WireGuard через `wg-quick`, AmneziaWG через `awg-quick`/`amneziawg-quick`, OpenVPN через
`openvpn`, XRay и Shadowsocks-over-XRay через `xray`. Если нужный Linux executable не установлен,
daemon возвращает `backend_unavailable` и не объявляет туннель активным. В system service
конфигурации дополнительно разрешены только доверенные файлы из `/etc/amnezia/profiles`.

## systemd system service

Реальные `wg-quick`, OpenVPN и XRay-сессии требуют привилегий Linux. Поэтому устанавливаемый
unit является **system service**, а не user service. Он запускается как `root:amnezia`, использует
`/run/amnezia/amneziad.sock` и `/var/lib/amnezia/profiles.json`, а директории ограничены unit-ом.
Для `all-except` временная VPN-конфигурация создаётся в отдельном writable staging root
(`/run/amnezia` в установленном unit), потому что `/tmp` может быть закрыт `ProtectSystem`/sandboxing.
Пакетирование должно создать системную группу и добавить в неё разрешённых операторов:

```bash
sudo groupadd --system amnezia
sudo usermod --append --groups amnezia "$USER"
# перелогиниться после изменения группы
sudo systemctl daemon-reload
sudo systemctl enable --now amneziad.service
sudo systemctl status amneziad.service
```

CLI подключается к system socket явно:

```bash
amnezia-cli --socket /run/amnezia/amneziad.sock status
amnezia-cli --socket /run/amnezia/amneziad.sock doctor --json
```

Доступ к socket получает только root и группа `amnezia`; не публикуйте его через TCP и не меняйте
права на world-writable. `status`, `doctor`, `connect` и `disconnect` доступны группе, но
импорт профиля и rollback обновления требуют подтверждённого Linux `SO_PEERCRED` с UID 0.
Хранилище ограничено 128 профилями и 16 MiB. Установка unit-а и любые привилегированные сетевые операции остаются
отдельным явным deployment-шагом.

## IPC-контракт

Каждый запрос и ответ — один JSON object на строку. В запросе используются поля `protocol`,
`id`, `command`, `params`; максимальный размер кадра — 64 KiB. Поддерживаемые команды текущего
среза: `status`, `list-profiles`, `doctor`, `import`, `export`, `connect`, `disconnect`, `update-rollback`.

Unix socket — локальный control plane. На Unix daemon выставляет права socket в `0660`, а
основной systemd deployment использует private `/run/amnezia` (`RuntimeDirectoryMode=0750`).
HTTPS control plane
пока не является частью target.

## Что покрывают тесты

- protocol encoding/validation;
- daemon lifecycle и bounded malformed/oversized frame errors;
- atomic profile store и persistence;
- dependency-injected adapters для `wg-quick`, `awg-quick`/`amneziawg-quick`, OpenVPN и XRay;
- CLI ↔ daemon IPC smoke-flow для status/list/doctor/import/export;
- реальный `connect` не меняет state на `connected`, если executable или конфигурация недоступны;
- server-managed whitelist: bounded JSON policy, DNS fallback с fail-closed поведением,
  LKG refresh и транзакционное добавление/удаление только принадлежащих daemon маршрутов;
- `routingMode: "all-except"`: full-tunnel policy table для IPv4/IPv6, server-managed
  whitelist через `ip rule ... lookup main`, а также защищённые маршруты до policy URL,
  DNS и VPN endpoint;
- подписанный headless update envelope: Ed25519, размер/SHA-256, отдельная платформа
  `linux-headless-x64`, безопасное содержимое tar и атомарная замена бинарей с rollback receipt;
- native Linux configure/build и полный CTest-набор должны быть выполнены в Linux/WSL
  release job; локальная Windows-среда этот receipt не заменяет.

Публикация на ServerX, установка на свежий Ubuntu и live-приёмка маршрутов/DNS не
считаются доказанными без отдельного операционного receipt.

## Ограничения паритета с Windows-клиентом

Это рабочий headless control-plane и process-adapter, но не полный replacement
Windows-клиента. Пока отсутствуют и не должны считаться реализованными:

- интеграция с существующим privileged Linux daemon и его UAPI/Qt Remote Objects;
- полноценная настройка интерфейсов и kill-switch;
  native WireGuard, AmneziaWG и OpenVPN поддерживают `only-forward` и `all-except`,
  а XRay/SS-XRay остаются proxy-режимом;
- управление self-hosted серверами, Docker-контейнерами и пользователями;
- диагностика протокольных backend-ов и journald integration;
- automatic update требует опубликованного артефакта `linux-headless-x64` и root-owned ключ
  строго `/etc/amnezia/update-public-key.pem`; HTTPS manifest обязателен, кроме буквального
  private/VPN-internal IPv4 HTTP endpoint, содержащегося в `forwardRoutes`; поле ключа в профиле
  сохраняется для совместимости, но не может выбрать другой trust anchor;
- HTTPS remote API;
- автоматическая или zero-touch миграция AWG 2.0 → 3.1.

Дальнейший implementation slice — связать этот control plane с существующими
Linux `Daemon`/`WireguardUtilsLinux`/firewall компонентами через отдельный
privileged adapter и kill-switch; текущий full-tunnel слой использует только
проверяемые `ip route`/`ip rule` операции.
Импорт/экспорт сохраняет только безопасные метаданные, включая whitelist/update URL и путь
к публичному ключу; private keys, tokens, passwords и прочие secrets в store и логи не записываются.

### Update и policy transport hardening

Updater принимает HTTPS manifest/artifact (либо узкий pinned internal HTTP transport) с Ed25519-подписью и проверяет canonical
containment, отсутствие symlink, root ownership и запрет group/world-write для trust anchor,
устанавливаемых бинарей и rollback evidence. Перед заменой создаётся durable journal с фазами
`prepared`, `replaced`, `restart_pending`; после перезапуска daemon подтверждает здоровье пары
бинарей и только затем помечает транзакцию `acknowledged`. Rollback использует копии, сохраняет
оригинальную evidence до следующего health acknowledgement и проходит фазы
`rollback_restart_pending`/`rolled_back`. Смешанное состояние или ошибка
восстановления переводит daemon в `recovery_required`; rollback выполняется только по
проверенным SHA-256 и не скрывает ошибки.

Политика маршрутизации требует HTTPS с буквальным IP endpoint. Единственное исключение — буквальный IPv4 по HTTP,
который должен быть VPN-internal и содержаться в `forwardRoutes` (например, текущий ServerX
`10.8.1.253:17864` при `10.8.1.0/24`). Внешний/plain HTTP, reserved hostnames и unsafe
private endpoint отвергаются до сетевого запроса; redirects запрещены. Full-tunnel staging
добавляет `Table = off`, чтобы только reconciler владел таблицей `51821` и его правилами.

## Безопасность разработки

Тесты headless target не поднимают интерфейсы, не меняют routes/DNS/firewall, не трогают Docker
и не требуют изменения live-сервера. Установка исправленного артефакта и любые привилегированные
операции должны выполняться отдельным явным deployment-шагом после проверки backend-а.
