#include "systemController.h"

#include <QDebug>
#include <QDesktopServices>
#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QQuickItem>
#include <QScopeGuard>
#include <QStandardPaths>
#include <QUrl>
#include <QtConcurrent>

#ifdef Q_OS_ANDROID
    #include "platforms/android/android_controller.h"
#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    #include "platforms/ios/ios_controller.h"
    #include <CoreFoundation/CoreFoundation.h>
#endif

SystemController::SystemController(QObject *parent)
    : QObject(parent)
{
}

bool SystemController::saveFile(const QString &fileName, const QString &data)
{
#if defined Q_OS_ANDROID
    AndroidController::instance()->saveFile(fileName, data);
    return true;
#endif
    return saveFile(fileName, data.toUtf8());
}

bool SystemController::saveFile(const QString &fileName, const QByteArray &data)
{
#if defined Q_OS_ANDROID
    AndroidController::instance()->saveFile(fileName, QString::fromUtf8(data));
    return true;
#endif

#ifdef Q_OS_IOS
    QUrl fileUrl = QDir::tempPath() + "/" + fileName;
    QFile file(fileUrl.toString());
#else
    QFile file(fileName);
#endif

    if (!file.open(QIODevice::WriteOnly)) {
        qWarning() << "SystemController::saveFile: cannot open" << fileName;
        return false;
    }
    if (file.write(data) != data.size()) {
        qWarning() << "SystemController::saveFile: write failed" << fileName;
        file.close();
        return false;
    }
    file.close();

#ifdef Q_OS_IOS
    QStringList filesToSend;
    filesToSend.append(fileUrl.toString());
    return IosController::Instance()->shareText(filesToSend);
#else
    QFileInfo fi(fileName);

#ifdef Q_OS_MAC
    const auto url = "file://" + fi.absoluteDir().absolutePath();
#else
    const auto url = fi.absoluteDir().absolutePath();
#endif

#ifndef MACOS_NE
    QDesktopServices::openUrl(url);
#endif
    return true;
#endif
}

bool SystemController::readFile(const QString &fileName, QByteArray &data, qint64 maximumBytes)
{
    // Reserve room for one overflow byte without overflowing QByteArray/qint64.
    if (maximumBytes < -1 || maximumBytes >= QByteArray::maxSize()) {
        return false;
    }
#ifdef Q_OS_ANDROID
    auto *android = AndroidController::instance();
    const int fd = android->getFd(fileName);
    if (fd < 0) {
        return false;
    }
    const auto closeFd = qScopeGuard([android] { android->closeFd(); });
    QFile file;
    // Android owns the descriptor; closeFd must run on every path after getFd.
    if (!file.open(fd, QIODevice::ReadOnly, QFileDevice::DontCloseHandle)) {
        return false;
    }
#else
    QFile file(fileName);
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }
#endif
    if (maximumBytes >= 0 && file.size() > maximumBytes) {
        return false;
    }
    const QByteArray bytes = maximumBytes < 0 ? file.readAll() : file.read(maximumBytes + 1);
    if (file.error() != QFile::NoError || !file.atEnd()
        || (maximumBytes >= 0 && bytes.size() > maximumBytes)) {
        return false;
    }
    data = bytes;
    return true;
}

bool SystemController::readFile(const QString &fileName, QString &data, qint64 maximumBytes)
{
    QByteArray byteArray;
    if (!readFile(fileName, byteArray, maximumBytes)) {
        return false;
    }
    data = QString::fromUtf8(byteArray);
    return true;
}

QString SystemController::getFileName(const QString &acceptLabel, const QString &nameFilter,
                                      const QString &selectedFile, const bool isSaveMode, const QString &defaultSuffix)
{
    QString fileName;
#ifdef Q_OS_ANDROID
    Q_ASSERT(!isSaveMode);
    return AndroidController::instance()->openFile(nameFilter);
#endif

#ifdef Q_OS_IOS

    fileName = IosController::Instance()->openFile();
    if (fileName.isEmpty()) {
        return fileName;
    }
    
    CFURLRef url = CFURLCreateWithFileSystemPath(
            kCFAllocatorDefault,
            CFStringCreateWithCharacters(0, reinterpret_cast<const UniChar *>(fileName.unicode()), fileName.length()),
            kCFURLPOSIXPathStyle, 0);

    if (!CFURLStartAccessingSecurityScopedResource(url)) {
        qDebug() << "Could not access path " << QUrl::fromLocalFile(fileName).toString();
    }

    return fileName;
#endif

    QObject *mainFileDialog = m_qmlRoot->findChild<QObject>("mainFileDialog").parent();
    if (!mainFileDialog) {
        return "";
    }

    mainFileDialog->setProperty("acceptLabel", QVariant::fromValue(acceptLabel));
    mainFileDialog->setProperty("nameFilters", QVariant::fromValue(QStringList(nameFilter)));
    mainFileDialog->setProperty("defaultSuffix", QVariant::fromValue(defaultSuffix));
    mainFileDialog->setProperty("isSaveMode", QVariant::fromValue(isSaveMode));
    if (!selectedFile.isEmpty()) {
        mainFileDialog->setProperty("selectedFile", QVariant::fromValue(QUrl(selectedFile)));
    }
    QMetaObject::invokeMethod(mainFileDialog, "open");

    bool isFileDialogAccepted = false;
    QEventLoop wait;
    QObject::connect(this, &SystemController::fileDialogClosed, [&wait, &isFileDialogAccepted](const bool isAccepted) {
        isFileDialogAccepted = isAccepted;
        wait.quit();
    });
    wait.exec();
    QObject::disconnect(this, &SystemController::fileDialogClosed, nullptr, nullptr);

    if (!isFileDialogAccepted) {
        return "";
    }

    fileName = mainFileDialog->property("selectedFile").toString();
    return QUrl(fileName).toLocalFile();
}

void SystemController::setQmlRoot(QObject *qmlRoot)
{
    m_qmlRoot = qmlRoot;
}

bool SystemController::isAuthenticated()
{
#ifdef Q_OS_ANDROID
    return AndroidController::instance()->requestAuthentication();
#else
    return true;
#endif
}

void SystemController::sendTouch(float x, float y)
{
#ifdef Q_OS_ANDROID
    AndroidController::instance()->sendTouch(x, y);
#endif
}
