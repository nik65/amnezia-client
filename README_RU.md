# Amnezia VPN — self-hosted fork

[English](README.md) | **Русский**

Наш форк [AmneziaVPN](https://github.com/amnezia-vpn/amnezia-client) для собственного
VPN-сервера и управления клиентами Windows, Android и Linux. Он сохраняет базовые
возможности Amnezia и добавляет серверные правила маршрутизации, Fleet Center,
диагностику, собственный подписанный канал обновлений и Linux-клиент без GUI.

**Выпуск 5.0.3.14 / Android versionCode 2200 опубликован 23 октября 2026 года.**
Файлы проверены через рабочий self-hosted канал: подпись Ed25519, полное скачивание,
размеры и SHA-256. [Отчёт о выпуске и контрольные суммы](docs/releases/5.0.3.14.md).

| Платформа выпуска | Пакет |
|---|---|
| Windows x64 | Обычный EXE и self-hosted клиент администратора |
| Android 9+, arm64-v8a | APK, versionCode 2200 |
| Linux x64 с GUI | Установщик `.run` |
| Linux x64 headless | Пакет обновления и отдельный пакет первоначальной установки |

Обновления нашего форка распространяет настроенный self-hosted сервер. Загрузки
с официального сайта Amnezia относятся к upstream-проекту. Исходники для Apple
сохранены, но macOS, iOS и другие архитектуры не входят в манифест этого выпуска.

## Базовые возможности Amnezia

- Простой в использовании — введите IP-адрес, SSH-логин и пароль, и Amnezia автоматически установит VPN-контейнеры Docker на ваш сервер и подключится к VPN.
- Классические VPN-протоколы: OpenVPN, WireGuard и IKEv2.
- Протоколы с маскировкой трафика (обфускацией): OpenVPN с плагином [Cloak](https://github.com/cbeuw/Cloak), Shadowsocks (OpenVPN over Shadowsocks), [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) и XRay.
- Поддержка Split Tunneling — добавляйте любые сайты или приложения в список, чтобы включить VPN только для них.
- Базовая кодовая база поддерживает Windows, macOS, Linux, Android и iOS; состав нашего выпуска указан выше.
- Поддержка конфигурации протокола AmneziaWG на [бета-прошивке Keenetic](https://docs.keenetic.com/ua/air/kn-1611/en/6319-latest-development-release.html#UUID-186c4108-5afd-c10b-f38a-cdff6c17fab3_section-idm33192196168192-improved).

## Что добавлено и улучшено в нашем клиенте

### Серверные правила и split tunneling

- **Server Routing rules**: централизованные правила для доменов, IP и CIDR,
  которые клиент объединяет со своими настройками split tunneling.
- Серверный список обхода VPN позволяет отправлять выбранный трафик напрямую.
  Списки адресов конкретного сервера не встроены как универсальное правило для всех пользователей.
- **Route Inspector** объясняет решение для сайта или IP: локальное правило,
  серверная политика, правило защиты туннеля или маршрут по умолчанию. При наличии
  используется подтверждённая квитанция клиента; без неё показывается прогноз
  сохранённой политики. Это не просмотр таблицы маршрутов ОС.
- Усилены нормализация IP/CIDR, сопоставление доменов, обработка ревизий политики
  и сохранение контекста уже применённых маршрутов. Отдельно учитываются маршруты
  доступа к серверу, диагностике и обновлениям.

### Fleet Center и диагностика

- **Fleet Center** объединяет состояние текущего устройства, соединения,
  наблюдаемого здоровья туннеля, событий восстановления и политики обновления.
- Статус отправителя логов показывает подтверждённую доставку, очередь, ответ
  коллектора, ошибку и время следующей попытки, когда эти сведения доступны.
  Отсутствие данных отображается явно и не считается успешной доставкой.
- Улучшены отправка и обработка логов Windows, Android и headless-клиента:
  ограничение размеров, подтверждение передачи, повторные попытки и heartbeat.
- Android-санитайзер скрывает ключи, пароли и токены, включая записи, разорванные
  границей пакетов. Добавлены проверки полноты и состояния источника логов.
- Для серверной диагностики добавлен helper с systemd timer, восстанавливающий
  перенаправление в актуальное сетевое пространство контейнера без перезапуска VPN.

### Windows и Android

- **Windows:** исправления жизненного цикла службы туннеля и восстановления после
  ошибки запуска WinTun; усилены проверки контекста при согласовании маршрутов.
- **Android:** восстановление связи Activity, VPN-службы и native backend после
  пересоздания интерфейса; проверка идентичности сеанса и результата очистки,
  защита от создания второго туннеля и более точные состояния ошибок.
- Большие наборы маршрутов передаются с учётом ограничений Binder; добавлены
  компактное представление маршрутов и проверки, сохраняющие множество адресов.
- Исправлены обработка отмены coroutine, лишнее создание backend и выбор источника
  счётчиков трафика. Полные логи после подключения проверены на реальном телефоне.
- В исходниках есть объединение включённых сайтов и приложений по условию «ИЛИ»
  для Android 10+; его отдельная матрица маршрутизации на телефоне ещё требует
  приёмки. [Контракт и ограничения](docs/android-included-union.md).

### Linux desktop и headless

- Linux GUI получил проверку привилегированного IPC-партнёра через идентичность
  процесса и защищённую systemd-службу, а также исправления post-install и упаковки.
- **`amneziad` и `amnezia-cli`** обеспечивают работу без графического интерфейса:
  профили, VPN, серверные правила, диагностику и подписанные обновления.
- C++-координатор headless управляет откатом, удержанием предыдущей версии после
  перезагрузки и явным возобновлением обновления. Состояние и журнал проверяются
  перед переходами; ошибки не превращаются в подтверждение успешного отката.
- Разделены пакеты первоначальной установки и обычного обновления; усилены
  ограничения чтения профилей, проверка зависимостей и файловые операции.

### AWG 3.1 и перенос рабочих компонентов на C++

- Для административных профилей добавлены поиск возможностей сервера, подготовка
  параллельного AWG endpoint, выбор свободного UDP-порта, проверка закреплённого
  образа и повторное использование совместимого поколения.
- Подписанное предложение миграции доставляется клиенту через существующий
  туннель. Готовность сервера и переход каждого клиента учитываются отдельно.
  [Сценарий AWG 3.1](docs/automatic-awg31-migration.md).
- Реализованы C++-модули сборщика логов и route-helper, feed/config runtime,
  планирования, policy/epoch, topology, readiness/attestation, control operations
  и транзакционного журнала. Native adapters подключены к выбранным путям;
  для серверных модулей предусмотрен проверяемый optional bundle.
- **Полный отказ от Python не завершён.** Default/legacy delivery, часть
  orchestration, maintenance и control HTTP/PID1 остаются на Python. Наличие
  C++-модуля не означает его активацию на каждом сервере. Conan, сборочные
  инструменты, лаборатория и тесты также сохраняют Python.
  [Подробный статус переноса](docs/python-runtime-migration.md).

### Импорт, интерфейс и устойчивость

- Усилен разбор конфигураций, QR-данных и URI: повреждённые JSON, пустые host,
  недопустимые адреса и ошибки импорта получают явный отказ.
- Исправлены начальные значения портов и переполнение при расчёте размеров
  AWG-пакетов; ограничены объёмы читаемых профилей и сетевых ответов.
- Исправлены время жизни асинхронных проверок/загрузок обновлений, уведомления
  моделей интерфейса и открытие ссылок/каталога логов.
- Улучшены выбор Windows toolchain, имя ARM64-пакета и сокрытие пароля в выводе
  notarization. Наличие этих исправлений не означает публикацию ARM64/Apple-сборок.

## Собственный канал обновлений

Манифест подписывается Ed25519, а каждый файл проверяется по размеру и SHA-256.
Артефакты размещаются по адресам с хешем содержимого. Публикация выполняется
self-hosted клиентом администратора с проверкой SSH host key; предусмотрены
подготовка, подтверждение, чтение результата и восстановление при сбое.
Политики обновления учитывают версию, поколение, срок действия, канал, группу
устройств и паузу выпуска, если соответствующая политика предоставлена сервером.

Обычный установщик предназначен для клиентского обновления; self-hosted пакет
дополнительно содержит комплект для публикации. Доступность обновления на сервере
и его установка на каждом устройстве — отдельные результаты.
[Описание канала](deploy/selfhosted_updates/README.md).

## Ссылки upstream-проекта

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

## Приёмка и проверенный выпуск

Windows и Linux проверяются в принадлежащих release-lab одноразовых гостях
Hyper-V или QEMU через PowerShell Direct либо QGA/QMP. Проверяются владение гостем,
точные байты пакета, результаты операций и очистка. Android проверяется на
реальном смартфоне; Android-эмуляторы и CVD в текущем процессе отключены.

Для **5.0.3.14 / 2200** завершены семь Windows-сценариев установки/обновления/UI,
Linux GUI с наблюдением рабочего окна, headless update → reboot → rollback →
held reboot → resume и проверка Android-подключения с доставкой логов.
Подписанная публикация всех пяти файлов подтверждена полным HTTP-чтением.
Это не утверждение о проверке Windows VPN-трафика или об обновлении всех устройств.

Остаются отдельные вопросы: причина исторического Linux GUI SIGSEGV и двух
стартовых Android-пакетов-заглушек не установлена; проверка пересоздания рабочего
контейнера ради тестирования восстановления диагностического правила не проводилась.
Подробности и границы — в [отчёте выпуска](docs/releases/5.0.3.14.md),
устройство лаборатории — в [release-lab](deploy/release_lab/README.md).

Сборки и публикации выполняются отдельным решением владельца. Ежедневное
сопровождение проверяет официальный стабильный upstream-релиз; при отсутствии
нового релиза анализирует логи и исправляет подтверждённые ошибки без выпуска
новой версии. Обычные коммиты upstream/dev не считаются новым релизом.

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
