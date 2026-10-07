#pragma once

#include <QDeadlineTimer>
#include <QLocalSocket>

#include "headlessProtocol.h"

namespace amnezia::headless {

// The deadline belongs to the complete response, not to individual chunks.
inline QByteArray readCliResponseFrame(QLocalSocket &socket, QString &error, int timeoutMs)
{
    const QDeadlineTimer deadline(timeoutMs);
    QByteArray buffer;
    while (buffer.size() <= MaximumFrameSize) {
        if (deadline.hasExpired()) {
            error = QStringLiteral("daemon response deadline exceeded");
            return {};
        }
        buffer.append(socket.readAll());
        const qsizetype newline = buffer.indexOf('\n');
        if (newline >= 0) {
            if (newline + 1 > MaximumFrameSize) {
                error = QStringLiteral("daemon response frame is too large");
                return {};
            }
            return buffer.left(newline + 1);
        }
        if (buffer.size() > MaximumFrameSize) {
            error = QStringLiteral("daemon response frame is too large");
            return {};
        }
        const qint64 remaining = deadline.remainingTime();
        if (remaining <= 0 || !socket.waitForReadyRead(static_cast<int>(remaining))) {
            error = deadline.hasExpired()
                    ? QStringLiteral("daemon response deadline exceeded") : socket.errorString();
            return {};
        }
    }
    error = QStringLiteral("daemon response frame is too large");
    return {};
}

} // namespace amnezia::headless
