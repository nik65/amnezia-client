# Amnezia VPN

### _Лучший клиент для создания VPN на собственном сервере_

[![Build Status](https://github.com/amnezia-vpn/amnezia-client/actions/workflows/deploy.yml/badge.svg?branch=dev)](https://github.com/amnezia-vpn/amnezia-client/actions/workflows/deploy.yml?query=branch:dev)
[![Gitpod ready-to-code](https://img.shields.io/badge/Gitpod-ready--to--code-blue?logo=gitpod)](https://gitpod.io/#https://github.com/amnezia-vpn/amnezia-client)

### [English](https://github.com/amnezia-vpn/amnezia-client/blob/dev/README.md) | Русский
[AmneziaVPN](https://amnezia.org?utm_source=github&utm_campaign=amnezia_website-readme-ru) — это open source VPN-клиент, ключевая особенность которого заключается в возможности развернуть собственный VPN на вашем сервере.

[![Image](https://github.com/amnezia-vpn/amnezia-client/blob/dev/metadata/img-readme/uipic4.png)](https://amnezia.org)

### [Сайт](https://amnezia.org?utm_source=github&utm_campaign=amnezia_website-readme-ru) | [Зеркало сайта](https://storage.googleapis.com/amnezia/amnezia.org?utm_source=github&utm_campaign=amnezia_website-readme-ru-mirror) | [Документация](https://docs.amnezia.org) | [Решение проблем](https://docs.amnezia.org/troubleshooting)

> [!TIP]
> Если [сайт Amnezia](https://amnezia.org?utm_source=github&utm_campaign=amnezia_website-readme-ru) заблокирован в вашем регионе, вы можете воспользоваться [ссылкой на зеркало](https://storage.googleapis.com/amnezia/amnezia.org?utm_source=github&utm_campaign=amnezia_website-readme-ru-mirror).

<a href="https://storage.googleapis.com/amnezia/amnezia.org?m-path=/ru/downloads&utm_source=github&utm_campaign=amnezia_button-readme-ru-mirror"><img src="https://github.com/amnezia-vpn/amnezia-client/blob/dev/metadata/img-readme/download-website-ru.svg" width="150" style="max-width: 100%; margin-right: 10px"></a>


[Все релизы](https://github.com/amnezia-vpn/amnezia-client/releases)

<br/>

<a href="https://www.testiny.io"><img src="https://github.com/amnezia-vpn/amnezia-client/blob/dev/metadata/img-readme/testiny.png" height="28px"></a>

## Особенности

- Простой в использовании — введите IP-адрес, SSH-логин и пароль, и Amnezia автоматически установит VPN-контейнеры Docker на ваш сервер и подключится к VPN.
- Классические VPN-протоколы: OpenVPN, WireGuard и IKEv2.
- Протоколы с маскировкой трафика (обфускацией): OpenVPN с плагином [Cloak](https://github.com/cbeuw/Cloak), Shadowsocks (OpenVPN over Shadowsocks), [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) и XRay.
- Поддержка Split Tunneling — добавляйте любые сайты или приложения в список, чтобы включить VPN только для них.
- Поддерживает платформы: Windows, macOS, Linux, Android, iOS.
- Поддержка конфигурации протокола AmneziaWG на [бета-прошивке Keenetic](https://docs.keenetic.com/ua/air/kn-1611/en/6319-latest-development-release.html#UUID-186c4108-5afd-c10b-f38a-cdff6c17fab3_section-idm33192196168192-improved).

## Ссылки

- [https://amnezia.org](https://amnezia.org/?utm_source=github&utm_campaign=amnezia_website-read) - Веб-сайт проекта | [Альтернативная ссылка (зеркало)](https://storage.googleapis.com/amnezia/amnezia.org?utm_source=github&utm_campaign=amnezia_website-read)
- [https://docs.amnezia.org](https://docs.amnezia.org/?utm_source=github&utm_campaign=amnezia_website-read) - Документация | [Альтернативная ссылка (зеркало)](https://storage.googleapis.com/amnezia/docs?utm_source=github&utm_campaign=amnezia_website-read)
- [https://www.reddit.com/r/AmneziaVPN](https://www.reddit.com/r/AmneziaVPN) - Reddit  
- [https://telegram.me/amnezia_vpn_en](https://telegram.me/amnezia_vpn_en) - Канал поддержки в Telegram (Английский)
- [https://telegram.me/amnezia_vpn_ir](https://telegram.me/amnezia_vpn_ir) - Канал поддержки в Telegram (Фарси)
- [https://telegram.me/amnezia_vpn_mm](https://telegram.me/amnezia_vpn_mm) - Канал поддержки в Telegram (Мьянма)
- [https://telegram.me/amnezia_vpn](https://telegram.me/amnezia_vpn) - Канал поддержки в Telegram  (Русский)
- [Оформите Premium на 6 или 12 месяцев](https://storage.googleapis.com/amnezia/pay?utm_source=github&utm_campaign=ampay-read)

## Технологии

AmneziaVPN использует несколько проектов с открытым исходным кодом:

- [OpenSSL](https://www.openssl.org/)
- [OpenVPN](https://openvpn.net/)
- [Qt](https://www.qt.io/)
- [LibSsh](https://libssh.org)
- [WireGuard](https://www.wireguard.com/)
- [Xray-core](https://xtls.github.io/en/)
- [Conan](https://conan.io/)
- и другие...

## Предрелизная песочница

Перед выпуском self-hosted релиза используется отдельная лаборатория в Ubuntu
24 WSL с четырьмя продуктовыми направлениями: Windows x64 и Linux через
QEMU/KVM, Android arm64-v8a через отдельный защищённый эмуляторный адаптер.
Изолированный server-router используется как вспомогательный consumer-fixture.
Инсталляция, обновление и проверка сервиса выполняются только внутри
одноразовых гостевых overlay-дисков через QGA/QMP или Android-адаптер. План
лаборатории и команды описаны в
[`deploy/release_lab/README.md`](deploy/release_lab/README.md). По умолчанию
release-обёртка останавливается на preflight, если обязательное направление
не готово.

Состояние на 08.09.2026 разделяет готовность ОС и продуктовые доказательства.
Linux headless v2 и Linux GUI v9 имеют готовые OS/QGA golden; строгая сессия
GNOME/X11 для GUI подтверждена. Свежая установка baseline `5.0.1.37`
прошла, сервис активен и каноническая версия runtime подтверждена; обновление
candidate `5.0.1.38` завершилось ошибкой legacy maintenance tool (exit 6), при
этом baseline и сервис остались активны. Android:
реальный system-installer
`5.0.1.37` → `5.0.1.38` прошёл, lavapipe дал чистый UI-скриншот, но x86-гость
не выбирает arm64 APK, поэтому настоящее обновление приложения не доказано.
Отдельный Windows OS baseline Hyper-V запечатан и независимо прочитан:
Windows 11 EnterpriseEval 25H2/build 26200, self-contained VHDX 128 GiB,
VM Off, 0 DVD/0 NIC/0 automatic checkpoints, Secure Boot
`MicrosoftWindows`, первый boot с owned VHD; SHA-256 marker/VHD
`8ded92f7c7a2f522dd6609f6afbb9e023515055ac3cd3db1309df9214e7275cb`.
SHA-256 backend —
`A31969B917C3C6CC243D177C5EEFADCD1D4D3D723285EE3F38240E5C321F5146`.
Этот OS baseline остаётся отдельным от QEMU product lane `lab.py`;
доказательства thin/outer Windows installer, интерактивного UI/UAC,
перезагрузки/отката и self-hosted publication ещё ожидаются. Проверка
server-router `/healthz` и `/manifest.json` не является публикацией.
Сценарии перезагрузки и отката не завершены. Полный release остаётся
fail-closed до receipts установки/обновления, перезагрузки/отката и
self-hosted publication по каждому обязательному lane.

## Помощь с переводами

Загрузите самые актуальные файлы перевода.

Перейдите на [вкладку "Actions"](https://github.com/amnezia-vpn/amnezia-client/actions?query=is%3Asuccess+branch%3Adev), нажмите на первую строку. Затем прокрутите вниз до раздела "Artifacts" и скачайте "AmneziaVPN_translations".

Распакуйте этот файл. Каждый файл с расширением *.ts содержит строки для соответствующего языка.

Переведите или исправьте строки в одном или нескольких файлах *.ts и загрузите их обратно в этот репозиторий в папку ``client/translations``. Это можно сделать через веб-интерфейс или любым другим знакомым вам способом.

## Проверка исходного кода

После клонирования репозитория обязательно загрузите все подмодули.

```bash
git submodule update --init --recursive
```

## Руководство по разработке

Хотите внести свой вклад? Добро пожаловать!

### Требования для сборки

* [`CMake`](https://cmake.org/download/)
* Компилятор и система сборки, в зависимости от таргета:
  - [Linux] Любые `make` и `gcc`
  - [Apple] [`Xcode`](https://developer.apple.com/xcode/) или [`Xcode command line tools`](https://developer.apple.com/xcode/)
  - [Windows] [`Visual Studio 2022`](https://aka.ms/vs/17/release/vs_community.exe) или [`VS 2022 Build Tools`](https://aka.ms/vs/17/release/vs_buildtools.exe)
  - [Android] [`Android SDK`](#установка-android-sdk) и [`Ninja`](https://ninja-build.org/)
* [`Qt 6.10+`](https://www.qt.io/download-open-source) со следующими модулями:
  - Основные модули для таргета (Desktop/Android/iOS)
  - Qt 5 Compatibility module
  - Qt Remote Objects
* Пакетный менеджер [`Conan`](https://conan.io/downloads)
  - На MacOS достаточно использовать `homebrew` или установить в `.venv` в корень проекта 
  - Для остальных систем необходимо прописать пути в `PATH`
* (Необязательно) Заивисимости для установщиков:
  - [Windows/Linux] [`Qt Installer Framework`](https://www.qt.io/download-open-source)
  - [Windows] [`WIX toolset`](https://github.com/wixtoolset/wix/releases)

### Сборка проекта через скрипты

* Запустите скрипты, находящиеся в папке `deploy`
* Если все зависимости установлены в стандартных локациях, скрипт найдёт их самостоятельно
* Если пути отличаются, их нужно явно указать используя:
  - `QT_INSTALL_DIR` - корневая папка установки Qt
  - `QT_ROOT_PATH`   - корневая папка Qt Framework
  - `QIF_ROOT_PATH`  - корневая папка Qt Installer Framework
  - `ANDROID_HOME`   - путь к Android SDK
  - и другие. Их можно получить из вышеуказанных скриптов

Unix-like:
```bash
# Build executables for the host platform
deploy/build.sh

# Or just
deploy/build.sh

# Build executables and installers for the host platform
deploy/build.sh --installer all

# Build Android APK and AAB
deploy/build.sh -t android --aab

# Call for help
deploy/build.sh -h
```

Windows:
```batch
:: Build executables for Windows
deploy/build.bat

:: Build executables with IFW installer for Windows
deploy/build.bat --installer ifw

:: Build executables with IFW and WIX installer for Windows
deploy/build.bat --installer ifw --installer wix

:: Or just
deploy/build.bat --installer all
```

### Разработка в IDE

* Можно использовать любые IDE которые умеют работать с CMake и находить Qt Kits. Например:
  - `Qt Creator`
  - `Visual Studio Code` with `Qt Extension Pack`
  - и так далее

* Для использования `Xcode` нужно сконфигурировать проект с помощью `cmake`. Самый простой способ это сделать - использовать `Qt Creator` для конфигурации. Затем, нужно открыть файл `AmneziaVPN.xcodeproj` из папки сборки с помощью `Xcode`. Учтите, что никакие файлы фактически не сохраняются - они сохраняются в директории сборки. Если требуется, скопируйте файлы вручную

* `Android studio` может быть использована подобным вышеуказанному способу - нужно использовать `cmake` вручную или через `Qt Creator` для конфигурации. Далее, откройте `<build-dir>/client/android-build` в `Android studio`. Не забудьте скопировать изменённые файлы в папку с исходным кодом - все файлы, изменённые в IDE, сохраняются фактически в папке сборки.

### Установка Android SDK

* Android SDK может быть установлен следующими способами:
  - Используя `Qt Creator`, через настройки в пунктах `Preferences`->`SDKs`
  - Используя `Android studio`. По умолчанию необходимые `SDK` устанавливаются автоматически.
  - Вручную, используя `sdk-manager`. Подробности можно найти [здесь](https://developer.android.com/tools)

## Лицензия

GPL v3.0

## Донаты

Patreon: [https://www.patreon.com/amneziavpn](https://www.patreon.com/amneziavpn)

Bitcoin: bc1qmhtgcf9637rl3kqyy22r2a8wa8laka4t9rx2mf <br>
USDT BEP20: 0x6abD576765a826f87D1D95183438f9408C901bE4 <br>
USDT TRC20: TELAitazF1MZGmiNjTcnxDjEiH5oe7LC9d <br>
XMR: 48spms39jt1L2L5vyw2RQW6CXD6odUd4jFu19GZcDyKKQV9U88wsJVjSbL4CfRys37jVMdoaWVPSvezCQPhHXUW5UKLqUp3 <br> 
TON: UQDpU1CyKRmg7L8mNScKk9FRc2SlESuI7N-Hby4nX-CcVmns

## Благодарности

Этот проект тестируется с помощью BrowserStack.
Мы выражаем благодарность [BrowserStack](https://www.browserstack.com) за поддержку нашего проекта.
