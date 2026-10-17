#ifndef REMOTELOGRECEIPT_H
#define REMOTELOGRECEIPT_H

#include <QByteArray>

namespace amnezia
{

// A successful HTTP status alone is not a durable upload receipt. The
// collector returns both headers only after its batch receipt is committed;
// callers must require the exact id they sent so a stale or proxied response
// cannot advance a local cursor.
inline bool remoteLogBatchReceiptAccepted(const QByteArray &acceptedHeader,
                                           const QByteArray &receivedBatchId,
                                           const QByteArray &expectedBatchId) noexcept
{
    return acceptedHeader == QByteArrayLiteral("1")
            && !expectedBatchId.isEmpty()
            && receivedBatchId == expectedBatchId;
}

} // namespace amnezia

#endif // REMOTELOGRECEIPT_H
