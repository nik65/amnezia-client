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

Зависимости: Ubuntu/Linux, CMake 3.25+, C++17 и Qt 6 modules `Core`, `Network`, `Test`.

Standalone-сборка target:

```bash
cmake -S headless -B build-headless -DCMAKE_BUILD_TYPE=Release
cmake --build build-headless --target amneziad amnezia-cli
ctest --test-dir build-headless --output-on-failure
```

Для release-артефакта Ubuntu используется `deploy/headless/build_headless_release.sh`.
Он создаёт tar.gz только с `amneziad` и `amnezia-cli`; затем
`deploy/headless/make_headless_manifest.py` публикует подписанный
`linux-headless-x64`-манифест. Обычный `linux-x64` GUI `.run` намеренно не считается
подходящим headless-обновлением.

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
  --config-root "$HOME/.config/amnezia/profiles"
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
права на world-writable. Установка unit-а и любые привилегированные сетевые операции остаются
отдельным явным deployment-шагом.

## IPC-контракт

Каждый запрос и ответ — один JSON object на строку. В запросе используются поля `protocol`,
`id`, `command`, `params`; максимальный размер кадра — 64 KiB. Поддерживаемые команды текущего
среза: `status`, `list-profiles`, `doctor`, `import`, `export`, `connect`, `disconnect`, `update-rollback`.

Unix socket — локальный control plane. На Unix daemon выставляет права socket в `0660`, а
основной systemd deployment использует private `/run/amnezia` (`RuntimeDirectoryMode=0750`).
HTTPS control plane
пока не является частью target.

## Что уже проверено

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
- Linux Release-сборка и полный CTest-набор в Ubuntu/WSL.

## Ограничения паритета с Windows-клиентом

Это рабочий headless control-plane и process-adapter, но не полный replacement
Windows-клиента. Пока отсутствуют и не должны считаться реализованными:

- интеграция с существующим privileged Linux daemon и его UAPI/Qt Remote Objects;
- полноценная настройка интерфейсов и kill-switch;
  native WireGuard, AmneziaWG и OpenVPN поддерживают `only-forward` и `all-except`,
  а XRay/SS-XRay остаются proxy-режимом;
- управление self-hosted серверами, Docker-контейнерами и пользователями;
- диагностика протокольных backend-ов и journald integration;
- automatic update требует опубликованного артефакта `linux-headless-x64` и доверенного
  public key в профиле;
- HTTPS remote API;
- автоматическая или zero-touch миграция AWG 2.0 → 3.1.

Дальнейший implementation slice — связать этот control plane с существующими
Linux `Daemon`/`WireguardUtilsLinux`/firewall компонентами через отдельный
privileged adapter и kill-switch; текущий full-tunnel слой использует только
проверяемые `ip route`/`ip rule` операции.
Импорт/экспорт сохраняет только безопасные метаданные, включая whitelist/update URL и путь
к публичному ключу; private keys, tokens, passwords и прочие secrets в store и логи не записываются.

## Безопасность разработки

Тесты headless target не поднимают интерфейсы, не меняют routes/DNS/firewall, не трогают Docker
и не требуют изменения live-сервера. Установка исправленного артефакта и любые привилегированные
операции должны выполняться отдельным явным deployment-шагом после проверки backend-а.
