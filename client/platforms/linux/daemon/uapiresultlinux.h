#pragma once

#include <QString>
#include <QStringList>
#include <cerrno>

namespace LinuxUapi {
inline int resultErrno(const QString& reply)
{
    int result = EINVAL;
    bool found = false;
    for (const QString& line : reply.split('\n')) {
        if (!line.startsWith(QStringLiteral("errno=")))
            continue;
        if (found)
            return EINVAL;
        found = true;
        const QString value = line.mid(6);
        if (value.isEmpty())
            return EINVAL;
        for (const QChar character : value) {
            if (character < QLatin1Char('0') || character > QLatin1Char('9'))
                return EINVAL;
        }
        bool ok = false;
        result = value.toInt(&ok);
        if (!ok)
            return EINVAL;
    }
    return result;
}
}
