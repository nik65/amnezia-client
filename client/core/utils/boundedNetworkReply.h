#ifndef AMNEZIA_BOUNDED_NETWORK_REPLY_H
#define AMNEZIA_BOUNDED_NETWORK_REPLY_H

#include <QByteArray>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <memory>
#include <limits>

namespace amnezia {

struct BoundedNetworkReplyBody {
    QByteArray data;
    bool tooLarge = false;
};

// Apply the limit while bytes arrive, rather than after QNetworkReply has
// already accumulated an unbounded response. The reply owns all callbacks.
inline std::shared_ptr<BoundedNetworkReplyBody> boundNetworkReplyBody(
        QNetworkReply *reply, qint64 maximumBytes)
{
    auto body = std::make_shared<BoundedNetworkReplyBody>();
    maximumBytes = qBound<qint64>(0, maximumBytes,
            std::numeric_limits<qint64>::max() - 1);
    reply->setReadBufferSize(maximumBytes + 1);
    const auto drain = [reply, body, maximumBytes]() {
        if (body->tooLarge) {
            return;
        }
        const qint64 availableBudget = maximumBytes - body->data.size();
        const QByteArray chunk = reply->read(availableBudget + 1);
        if (chunk.size() > availableBudget) {
            body->tooLarge = true;
            body->data.clear();
            reply->abort();
            return;
        }
        body->data.append(chunk);
    };
    QObject::connect(reply, &QIODevice::readyRead, reply, drain);
    QObject::connect(reply, &QNetworkReply::finished, reply, drain);
    QObject::connect(reply, &QNetworkReply::metaDataChanged, reply,
                     [reply, body, maximumBytes]() {
        bool valid = false;
        const qint64 declaredBytes = reply->header(
                QNetworkRequest::ContentLengthHeader).toLongLong(&valid);
        if (valid && declaredBytes > maximumBytes) {
            body->tooLarge = true;
            body->data.clear();
            reply->abort();
        }
    });
    return body;
}

} // namespace amnezia

#endif
