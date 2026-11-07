#ifndef ANDROIDPROTOCOLBINDING_H
#define ANDROIDPROTOCOLBINDING_H

#include <QPointer>
#include "core/utils/errorCodes.h"

namespace AndroidProtocolBinding {

inline amnezia::ErrorCode errorForServiceReason(int reason)
{
    return reason == amnezia::ErrorCode::AndroidCombinedRoutingRequiresAndroid10
            ? amnezia::ErrorCode::AndroidCombinedRoutingRequiresAndroid10 : amnezia::ErrorCode::UnknownError;
}

// Called by the queued Android service-error binding. Keep the reason and state
// together, and ignore events whose protocol or connection epoch has retired.
template<class Protocol, class GenericFailure>
bool deliverServiceError(const QPointer<Protocol> &protocol, const QObject *currentProtocol,
                         quint64 eventEpoch, quint64 currentEpoch, amnezia::ErrorCode error,
                         GenericFailure genericFailure)
{
    if (eventEpoch != currentEpoch || !protocol || protocol.data() != currentProtocol) return false;
    if (error == amnezia::ErrorCode::AndroidCombinedRoutingRequiresAndroid10) {
        // The setter publishes the reason before its Error transition.
        protocol->setLastError(error);
    } else {
        // A service Error transition must never surface the success code.
        emit protocol->protocolError(error == amnezia::ErrorCode::NoError
                ? amnezia::ErrorCode::UnknownError : error);
        // Direct observers may retire the protocol while handling the reason.
        if (protocol) genericFailure();
    }
    return true;
}

} // namespace AndroidProtocolBinding

#endif
