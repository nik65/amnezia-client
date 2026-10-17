package org.amnezia.vpn.protocol

sealed class ProtocolException(message: String? = null, cause: Throwable? = null) : Exception(message, cause)

object ProtocolErrorReason {
    // Fixed cross-language code; keep synchronized with ErrorCode in errorCodes.h.
    const val COMBINED_ROUTING_REQUIRES_ANDROID_10 = 105
}

class BadConfigException(message: String? = null, cause: Throwable? = null, val reasonCode: Int = 0) : ProtocolException(message, cause)

class VpnStartException(message: String? = null, cause: Throwable? = null) : ProtocolException(message, cause)
class VpnException(message: String? = null, cause: Throwable? = null) : ProtocolException(message, cause)
