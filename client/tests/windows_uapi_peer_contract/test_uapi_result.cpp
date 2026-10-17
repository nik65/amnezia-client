#include <QTest>

#include "platforms/windows/daemon/uapiresult.h"

class UapiResultTest final : public QObject {
  Q_OBJECT

 private slots:
  void acceptsTerminalErrno() {
    QCOMPARE(amnezia::uapi::errnoFromReply(QStringLiteral("errno=0")), 0);
    QCOMPARE(amnezia::uapi::errnoFromReply(
                 QStringLiteral("public_key=abcd\nerrno=0")),
             0);
    QCOMPARE(amnezia::uapi::errnoFromReply(QStringLiteral("errno=5")), 5);
  }

  void rejectsMalformedOrNonTerminalErrno() {
    const QStringList malformed = {
        QString(),
        QStringLiteral("public_key=abcd"),
        QStringLiteral("errno=0\nerrno=5"),
        QStringLiteral("errno=0\npublic_key=abcd"),
        QStringLiteral("errno=+0"),
        QStringLiteral("errno= 0"),
        QStringLiteral("errno=-1"),
        QStringLiteral("errno=0\n"),
    };
    for (const QString& reply : malformed) {
      QCOMPARE(amnezia::uapi::errnoFromReply(reply), EINVAL);
    }
  }
};

QTEST_MAIN(UapiResultTest)
#include "test_uapi_result.moc"
