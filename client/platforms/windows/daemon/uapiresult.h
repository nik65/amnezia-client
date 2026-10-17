/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef UAPIRESULT_H
#define UAPIRESULT_H

#include <cerrno>

#include <QString>
#include <QStringList>

namespace amnezia::uapi {

// UAPI replies contain fields followed by one terminal errno line. The
// transport removes the final blank-line frame delimiter before calling this
// parser; malformed or incomplete replies fail closed as EINVAL.
inline int errnoFromReply(const QString& reply) {
  const QStringList lines = reply.split('\n', Qt::KeepEmptyParts);
  bool found = false;
  int result = EINVAL;
  for (int index = 0; index < lines.size(); ++index) {
    const QString& line = lines.at(index);
    const int eq = line.indexOf('=');
    if (eq <= 0 || line.isEmpty()) {
      return EINVAL;
    }
    if (line.left(eq) != QStringLiteral("errno")) {
      if (found) {
        return EINVAL;
      }
      continue;
    }
    if (found || index != lines.size() - 1) {
      return EINVAL;
    }

    const QString value = line.mid(eq + 1);
    if (value.isEmpty()) {
      return EINVAL;
    }
    for (const QChar character : value) {
      if (!character.isDigit()) {
        return EINVAL;
      }
    }
    bool ok = false;
    result = value.toInt(&ok, 10);
    if (!ok) {
      return EINVAL;
    }
    found = true;
  }
  return found ? result : EINVAL;
}

}  // namespace amnezia::uapi

#endif  // UAPIRESULT_H
