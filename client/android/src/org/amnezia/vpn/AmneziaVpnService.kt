package org.amnezia.vpn

import android.annotation.SuppressLint
import android.app.ActivityManager
import android.app.ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_MANIFEST
import android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.PowerManager
import android.os.Process
import androidx.annotation.MainThread
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import androidx.core.content.getSystemService
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.UnknownHostException
import java.net.URL
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.LazyThreadSafetyMode.NONE
import kotlin.random.Random
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.amnezia.vpn.protocol.BadConfigException
import org.amnezia.vpn.protocol.ProtocolState.CONNECTED
import org.amnezia.vpn.protocol.ProtocolState.CONNECTING
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTING
import org.amnezia.vpn.protocol.ProtocolState.RECONNECTING
import org.amnezia.vpn.protocol.ProtocolState.UNKNOWN
import org.amnezia.vpn.protocol.VpnException
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.protocol.putStatus
import org.amnezia.vpn.util.LoadLibraryException
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.Prefs
import org.amnezia.vpn.util.net.NetworkState
import org.amnezia.vpn.util.net.TrafficStats
import org.json.JSONException
import org.json.JSONObject

private const val TAG = "AmneziaVpnService"

const val ACTION_DISCONNECT = "org.amnezia.vpn.action.disconnect"
const val ACTION_CONNECT = "org.amnezia.vpn.action.connect"

const val MSG_VPN_CONFIG = "VPN_CONFIG"
const val MSG_ERROR = "ERROR"
const val MSG_SAVE_LOGS = "SAVE_LOGS"
const val MSG_CLIENT_NAME = "CLIENT_NAME"

const val AFTER_PERMISSION_CHECK = "AFTER_PERMISSION_CHECK"
private const val PREFS_CONFIG_KEY = "LAST_CONF"
private const val PREFS_SERVER_NAME = "LAST_SERVER_NAME"
private const val PREFS_SERVER_INDEX = "LAST_SERVER_INDEX"
// private const val STATISTICS_SENDING_TIMEOUT = 1000L
private const val TRAFFIC_STATS_UPDATE_TIMEOUT = 1000L
private const val DISCONNECT_TIMEOUT = 5000L
private const val STOP_SERVICE_TIMEOUT = 5000L
private const val CLIENT_LOGS_KEY = "clientLogs"
private const val CLIENT_LOGS_ENDPOINT_KEY = "endpoint"
private const val CLIENT_LOGS_CLIENT_ID_KEY = "clientId"
private const val CLIENT_LOGS_TOKEN_KEY = "token"
private const val CLIENT_LOGS_BOOTSTRAP_KEY = "bootstrap"
private const val CLIENT_LOGS_TRUSTED_ENDPOINT = "http://172.29.172.251:17866/logs"
private const val CLIENT_LOGS_BOOTSTRAP_ENDPOINT = "http://172.29.172.251:17866/bootstrap"
private const val CLIENT_LOGS_INITIAL_UPLOAD_DELAY = 15000L
private const val CLIENT_LOGS_UPLOAD_INTERVAL = 60000L
private const val CLIENT_LOGS_RETRY_BASE_DELAY = 15000L
private const val CLIENT_LOGS_RETRY_MAX_DELAY = 10 * 60 * 1000L
private const val CLIENT_LOGS_RETRY_JITTER_PERMILLE = 200
private const val CLIENT_LOGS_UPLOAD_TIMEOUT = 30000
private const val CLIENT_LOGS_MAX_PAYLOAD_BYTES = 15 * 1024 * 1024
private const val CLIENT_LOGS_MAX_BATCH_RAW_BYTES = 1024 * 1024
private const val CLIENT_LOGS_MAX_BOOTSTRAP_RESPONSE_BYTES = 4096
private const val PREFS_REMOTE_LOG_INSTALLATION_ID = "REMOTE_LOG_INSTALLATION_ID"
private const val PREFS_REMOTE_LOG_ORIGIN_NONCE = "REMOTE_LOG_ORIGIN_NONCE_V1"
private const val PREFS_REMOTE_LOG_TOKEN_PREFIX = "REMOTE_LOG_TOKEN_"
private const val PREFS_REMOTE_LOG_CURSOR_PREFIX = "REMOTE_LOG_CURSOR_V1_"
private const val PREFS_REMOTE_LOG_CURSOR_INDEX = "REMOTE_LOG_CURSOR_INDEX_V1"
private const val CLIENT_LOGS_CURSOR_SCHEMA = 4
private const val CLIENT_LOGS_CURSOR_FINGERPRINT_BYTES = 64 * 1024
private const val CLIENT_LOGS_CURSOR_ANCHOR_BYTES = 4 * 1024
private const val CLIENT_LOGS_MAX_CURSOR_TARGETS = 8
private const val CLIENT_LOGS_KIND_ANDROID = "android"
private const val CLIENT_LOGS_BATCH_ACCEPTED_HEADER = "X-Amnezia-Batch-Accepted"
private const val CLIENT_LOGS_BATCH_ID_HEADER = "X-Amnezia-Batch-Id"
private const val CLIENT_LOGS_SANITIZER_MAX_LINE_CHARS = 64 * 1024
private const val CLIENT_LOGS_SANITIZER_MAX_DETAILED_REDACTIONS = 4096
private const val CLIENT_LOGS_SANITIZER_MAX_EXPLICIT_SECRETS = 4
private const val CLIENT_LOGS_SANITIZER_MAX_EXPLICIT_SECRET_CHARS = 4096
private const val CLIENT_LOGS_MAX_TOKEN_CHARS = 512
private const val CLIENT_LOGS_REDACTED = "[redacted]"
private const val CLIENT_LOGS_REDACTED_LINE = "[redacted sensitive line]"
private const val CLIENT_LOGS_ORIGIN_MARKER = "AMNEZIA_REMOTE_LOG_ORIGIN_V1"
private const val CLIENT_LOGS_SENSITIVE_KEY_PATTERN =
    "(?:x-amnezia-(?:log-token|bootstrap-token|installation-id)|clientlogs[._-]?token|" +
        "remote[_-]?log[_-]?installation[_-]?id|installation[_-]?(?:uuid|id)|" +
        "client[_-]?(?:private|priv)[_-]?key|server[_-]?(?:private|priv)[_-]?key|" +
        "(?:cert|openvpn|wireguard(?:client)?|wg)[_-]?(?:private|priv)[_-]?key|" +
        "(?:private|priv)[_-]?key(?:[_-]?(?:hex|base64))?|" +
        "pre[_-]?shared[_-]?key(?:[_-]?(?:hex|base64))?|" +
        "preshared[_-]?key(?:[_-]?(?:hex|base64))?|" +
        "(?:server|client|wireguard|wg)[_-]?psk[_-]?key|psk(?:[_-]?key)?|" +
        "(?:mtproxy|telemt)[_-]?secret|(?:mtproxy|telemt)[_-]?additional[_-]?secrets|" +
        "additional[_-]?secrets|(?:aes|vpn)[_-]?key|aes[_-]?(?:iv|salt)|" +
        "tls[_-]?(?:auth|crypt(?:[_-]?v2)?)|xhttp[_-]?(?:session|seq|uplink[_-]?data)[_-]?key|" +
        "xpadding[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|" +
        "session[_-]?(?:token|id)|log[_-]?token|bootstrap[_-]?token|client[_-]?secret|" +
        "api[_-]?key|apikey|auth[_-]?data|credentials?|proxy[_-]?authorization|" +
        "proxy[_-]?(?:password|secret)|socks[_-]?(?:pass|password|secret)|" +
        "secret[_-]?(?:key|data)|dynamic[_-]?challenge[_-]?cookie|" +
        "authorization|set[_-]?cookie|cookie|" +
        "password|passwd|pwd|passphrase|pass|secret|token)"

private const val CLIENT_LOGS_SECRET_MODE_AWAIT_DELIMITER = "await-delimiter"
private const val CLIENT_LOGS_SECRET_MODE_AWAIT_VALUE = "await-value"
private const val CLIENT_LOGS_SECRET_MODE_QUOTED = "quoted"
private const val CLIENT_LOGS_SECRET_MODE_BARE = "bare"
private const val CLIENT_LOGS_SECRET_MODE_STRUCTURED = "structured"
private const val CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED = "fail-closed"
private const val CLIENT_LOGS_MAX_SECRET_NESTING = 64
private const val CLIENT_LOGS_MAX_BLOCK_END_MARKER_CHARS = 128

private val SHA256_HEX_PATTERN = Regex("^[0-9a-f]{64}$")
private val CLIENT_LOGS_ORIGIN_RECORD_PREFIX_PATTERN = Regex(
    """^\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}Z \d+ \d+ [VDIWEF] \[[^\r\n]{1,256}] $"""
)
private val CLIENT_LOGS_AUTHORIZATION_PATTERN = Regex(
    """((?<![A-Za-z0-9_-])(?:proxy-)?authorization[ \t]{0,16}[:=][ \t]{0,16})[^\r\n]*""",
    setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE)
)
private val CLIENT_LOGS_COOKIE_PATTERN = Regex(
    """((?<![A-Za-z0-9_-])(?:set-cookie|cookie)[ \t]{0,16}[:=][ \t]{0,16})[^\r\n]*""",
    setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE)
)
private val CLIENT_LOGS_SECRET_KEY_PATTERN = Regex(
    """(?<![A-Za-z0-9])["']?$CLIENT_LOGS_SENSITIVE_KEY_PATTERN["']?(?![A-Za-z0-9_-])""",
    RegexOption.IGNORE_CASE
)
private val CLIENT_LOGS_BEARER_PATTERN = Regex(
    """\b(bearer[ \t]+)[A-Za-z0-9._~+/=-]{4,}""",
    RegexOption.IGNORE_CASE
)
private val CLIENT_LOGS_URL_USER_INFO_PATTERN = Regex(
    """\b([A-Z][A-Z0-9+.-]{1,31}://)[^/\s@]+@""",
    RegexOption.IGNORE_CASE
)
private val CLIENT_LOGS_URL_QUERY_SECRET_PATTERN = Regex(
    """([?&](?:access[_-]?token|refresh[_-]?token|auth[_-]?token|session[_-]?token|""" +
        """log[_-]?token|bootstrap[_-]?token|client[_-]?secret|api[_-]?key|password|""" +
        """passwd|pwd|passphrase|pass|secret|token|installation[_-]?(?:uuid|id))=)[^&#\s]*""",
    RegexOption.IGNORE_CASE
)
private val CLIENT_LOGS_COMMAND_LINE_SECRET_PATTERN = Regex(
    """((?<![A-Za-z0-9])--$CLIENT_LOGS_SENSITIVE_KEY_PATTERN(?:[ \t]*=[ \t]*|[ \t]+))""" +
        """(?:"[^"]*"|'[^']*'|[^\s]+)""",
    RegexOption.IGNORE_CASE
)
private val CLIENT_LOGS_SENSITIVE_BLOCK_BEGIN_PATTERN = Regex(
    """-----BEGIN ([A-Z0-9][A-Z0-9 _-]{0,80})-----|<(tls-auth|tls-crypt(?:-v2)?|secret)>""",
    RegexOption.IGNORE_CASE
)
private val CLIENT_LOGS_SAFE_BLOCK_END_PATTERN = Regex(
    """^(?:-----END [A-Z0-9][A-Z0-9 _-]{0,80}-----|</(?:tls-auth|tls-crypt(?:-v2)?|secret)>)$""",
    RegexOption.IGNORE_CASE
)
private val CLIENT_LOGS_SECRET_MODES = setOf(
    "",
    CLIENT_LOGS_SECRET_MODE_AWAIT_DELIMITER,
    CLIENT_LOGS_SECRET_MODE_AWAIT_VALUE,
    CLIENT_LOGS_SECRET_MODE_QUOTED,
    CLIENT_LOGS_SECRET_MODE_BARE,
    CLIENT_LOGS_SECRET_MODE_STRUCTURED,
    CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED
)

private data class RemoteLogTarget(
    val endpoint: String,
    val clientId: String,
    val token: String,
    val bootstrap: Boolean,
    val tokenCacheKey: String
)

private data class RemoteLogAttempt(
    val target: RemoteLogTarget,
    val generation: Long
)

private data class RemoteLogCursor(
    val offset: Int = 0,
    val fingerprint: String = "",
    val fingerprintBytes: Int = 0,
    val anchor: String = "",
    val pendingEndOffset: Int = 0,
    val pendingBodySha256: String = "",
    val pendingBatchId: String = "",
    val sanitizerBlockEndMarker: String = "",
    val sanitizerBlockEndPrefixChars: Int = 0,
    val sanitizerSecretMode: String = "",
    val sanitizerSecretQuote: String = "",
    val sanitizerSecretEscaped: Boolean = false,
    val sanitizerStructuredClosers: String = "",
    val sanitizerExplicitSecretsSha256: String = ""
)

private data class RemoteLogSanitizerState(
    val blockEndMarker: String = "",
    val blockEndPrefixChars: Int = 0,
    val secretMode: String = "",
    val secretQuote: String = "",
    val secretEscaped: Boolean = false,
    val structuredClosers: String = ""
)

private data class RemoteLogSanitizedPayload(
    val data: ByteArray,
    val state: RemoteLogSanitizerState
)

private data class RemoteLogStructuredText(
    val text: String,
    val state: RemoteLogSanitizerState,
    val overflowed: Boolean
)

private data class RemoteLogBoundedText(
    val text: String,
    val overflowed: Boolean
)

private data class RemoteLogPayload(
    val data: ByteArray,
    val cursorBeforeUpload: RemoteLogCursor,
    val cursorAfterUpload: RemoteLogCursor,
    val batchId: String,
    val sanitizerExplicitSecrets: List<String>
)

private enum class RemoteLogUploadResult {
    ACCEPTED,
    IDLE,
    PAUSED,
    RETRY
}

private data class RemoteLogUploadOutcome(
    val result: RemoteLogUploadResult,
    val retryAfterMs: Long? = null
)

private data class RemoteLogBootstrapOutcome(
    val target: RemoteLogTarget? = null,
    val retryAfterMs: Long? = null,
    val permanentFailure: Boolean = false
)

private class RemoteLogSanitizerBudget(
    var detailedRedactions: Int = CLIENT_LOGS_SANITIZER_MAX_DETAILED_REDACTIONS
)

private class RemoteLogBoundedTextBuilder(private val maxBytes: Int) {
    private val value = StringBuilder(minOf(maxBytes.coerceAtLeast(0), 64 * 1024))
    private var bytes = 0
    var overflowed: Boolean = false
        private set

    fun append(character: Char) {
        append(character.toString())
    }

    fun append(source: CharSequence) {
        append(source, 0, source.length)
    }

    fun append(source: CharSequence, startIndex: Int, endIndex: Int) {
        if (overflowed || startIndex >= endIndex) return
        var index = startIndex
        while (index < endIndex) {
            val character = source[index]
            val isSurrogatePair = character.isHighSurrogate() &&
                index + 1 < endIndex && source[index + 1].isLowSurrogate()
            val encodedBytes = when {
                isSurrogatePair -> 4
                character.code <= 0x7f -> 1
                character.code <= 0x7ff -> 2
                else -> 3
            }
            if (bytes + encodedBytes > maxBytes) {
                overflowed = true
                return
            }
            value.append(character)
            if (isSurrogatePair) {
                value.append(source[index + 1])
                index++
            }
            bytes += encodedBytes
            index++
        }
    }

    override fun toString(): String = value.toString()
}

@SuppressLint("Registered")
open class AmneziaVpnService : VpnService() {

    private lateinit var mainScope: CoroutineScope
    private lateinit var connectionScope: CoroutineScope
    private var isServiceBound = false
    private var vpnProto: VpnProto? = null
    private var protocolState = MutableStateFlow(UNKNOWN)
    private var serverName: String? = null
    private var serverIndex: Int = -1
    private var activeVpnConfig: JSONObject? = null

    private val isConnected
        get() = protocolState.value == CONNECTED

    private val isDisconnected
        get() = protocolState.value == DISCONNECTED

    private val isUnknown
        get() = protocolState.value == UNKNOWN

    private var connectionJob: Job? = null
    private var disconnectionJob: Job? = null
    private var trafficStatsUpdateJob: Job? = null
    private var remoteLogUploadJob: Job? = null
    private val remoteLogTargetLock = Any()
    @Volatile
    private var remoteLogTarget: RemoteLogTarget? = null
    @Volatile
    private var remoteLogTargetGeneration = 0L
    @Volatile
    private var remoteLogPausedGeneration = -1L
    private var remoteLogActiveConnection: HttpURLConnection? = null
    private var remoteLogInstallationIdCache: String? = null
    private val remoteLogOriginLock = Any()
    private val remoteLogSanitizerContractVerified: Boolean by lazy(NONE) {
        verifyRemoteLogSanitizerContract()
    }
    // private var statisticsSendingJob: Job? = null
    private lateinit var networkState: NetworkState
    private lateinit var trafficStats: TrafficStats
    private var controlReceiver: BroadcastReceiver? = null
    private var notificationStateReceiver: BroadcastReceiver? = null
    private var screenOnReceiver: BroadcastReceiver? = null
    private var screenOffReceiver: BroadcastReceiver? = null
    private val clientMessengers = ConcurrentHashMap<Messenger, IpcMessenger>()

    private val isActivityConnected
        get() = clientMessengers.any { it.value.name == ACTIVITY_MESSENGER_NAME }

    private val connectionExceptionHandler = CoroutineExceptionHandler { _, e ->
        connectionJob?.cancel()
        connectionJob = null
        disconnectionJob?.cancel()
        disconnectionJob = null
        protocolState.value = DISCONNECTED
        when (e) {
            is IllegalArgumentException,
            is VpnStartException,
            is VpnException -> onError(e.message ?: e.toString())

            is JSONException,
            is BadConfigException -> onError("VPN config format error: ${e.message}")

            is LoadLibraryException -> onError("${e.message}. Caused: ${e.cause?.message}")

            is UnknownHostException -> onError("Unknown host")

            else -> throw e
        }
    }

    private val actionMessageHandler: Handler by lazy(NONE) {
        object : Handler(Looper.getMainLooper()) {
            override fun handleMessage(msg: Message) {
                val action = msg.extractIpcMessage<Action>()
                Log.d(TAG, "Handle action: $action")
                when (action) {
                    Action.REGISTER_CLIENT -> {
                        val clientName = msg.data.getString(MSG_CLIENT_NAME)
                        val messenger = IpcMessenger(msg.replyTo, clientName)
                        clientMessengers[msg.replyTo] = messenger
                        Log.d(TAG, "Messenger client '$clientName' was registered")
                        // if (clientName == ACTIVITY_MESSENGER_NAME && isConnected) launchSendingStatistics()
                    }

                    Action.UNREGISTER_CLIENT -> {
                        clientMessengers.remove(msg.replyTo)?.let {
                            Log.d(TAG, "Messenger client '${it.name}' was unregistered")
                            // if (it.name == ACTIVITY_MESSENGER_NAME) stopSendingStatistics()
                        }
                    }

                    Action.CONNECT -> {
                        connect(msg.data.getString(MSG_VPN_CONFIG))
                    }

                    Action.DISCONNECT -> {
                        disconnect()
                    }

                    Action.REQUEST_STATUS -> {
                        clientMessengers[msg.replyTo]?.let { clientMessenger ->
                            clientMessenger.send {
                                ServiceEvent.STATUS.packToMessage {
                                    putStatus(this@AmneziaVpnService.protocolState.value)
                                }
                            }
                        }
                    }

                    Action.NOTIFICATION_PERMISSION_GRANTED -> {
                        enableNotification()
                    }

                    Action.SET_SAVE_LOGS -> {
                        Log.saveLogs = true
                    }
                }
            }
        }
    }

    private val vpnServiceMessenger: Messenger by lazy(NONE) {
        Messenger(actionMessageHandler)
    }

    /**
     * Notification setup
     */
    private val foregroundServiceTypeCompat
        get() = when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE -> FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q -> FOREGROUND_SERVICE_TYPE_MANIFEST
            else -> 0
        }

    private val serviceNotification: ServiceNotification by lazy(NONE) { ServiceNotification(this) }

    /**
     * Service overloaded methods
     */
    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "Create Amnezia VPN service")
        mainScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        connectionScope = CoroutineScope(SupervisorJob() + Dispatchers.IO + connectionExceptionHandler)
        loadServerData()
        launchProtocolStateHandler()
        networkState = NetworkState(this, ::reconnect)
        trafficStats = TrafficStats()
        registerBroadcastReceivers()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val isAlwaysOn = intent != null && intent.action == SERVICE_INTERFACE

        if (isAlwaysOn) {
            Log.d(TAG, "Start service via Always-on")
            connect()
        } else if (intent?.getBooleanExtra(AFTER_PERMISSION_CHECK, false) == true) {
            Log.d(TAG, "Start service after permission check")
            connect()
        } else {
            Log.d(TAG, "Start service")
            connect(intent?.getStringExtra(MSG_VPN_CONFIG))
        }
        ServiceCompat.startForeground(
            this, NOTIFICATION_ID,
            serviceNotification.buildNotification(serverName, vpnProto?.label, protocolState.value),
            foregroundServiceTypeCompat
        )
        return START_REDELIVER_INTENT
    }

    override fun onBind(intent: Intent?): IBinder? {
        Log.d(TAG, "onBind by $intent")
        if (intent?.action == SERVICE_INTERFACE) return super.onBind(intent)
        isServiceBound = true
        return vpnServiceMessenger.binder
    }

    override fun onUnbind(intent: Intent?): Boolean {
        Log.d(TAG, "onUnbind by $intent")
        if (intent?.action != SERVICE_INTERFACE) {
            if (clientMessengers.isEmpty()) {
                isServiceBound = false
                if (isUnknown || isDisconnected) stopService()
            }
        }
        return true
    }

    override fun onRebind(intent: Intent?) {
        Log.d(TAG, "onRebind by $intent")
        if (intent?.action != SERVICE_INTERFACE) {
            isServiceBound = true
        }
        super.onRebind(intent)
    }

    override fun onRevoke() {
        Log.d(TAG, "onRevoke")
        // Calls to onRevoke() method may not happen on the main thread of the process
        mainScope.launch {
            disconnect()
        }
    }

    override fun onDestroy() {
        Log.d(TAG, "Destroy service")
        stopRemoteLogUploader()
        unregisterBroadcastReceivers()
        runBlocking {
            disconnect()
            disconnectionJob?.join()
        }
        connectionScope.cancel()
        mainScope.cancel()
        super.onDestroy()
    }

    private fun stopService() {
        Log.d(TAG, "Stop service")
        // the coroutine below will be canceled during the onDestroy call
        mainScope.launch {
            delay(STOP_SERVICE_TIMEOUT)
            Log.w(TAG, "Stop service timeout, kill process")
            Process.killProcess(Process.myPid())
        }
        stopSelf()
    }

    private fun registerBroadcastReceivers() {
        Log.d(TAG, "Register broadcast receivers")
        controlReceiver = registerBroadcastReceiver(
            arrayOf(ACTION_CONNECT, ACTION_DISCONNECT), ContextCompat.RECEIVER_NOT_EXPORTED
        ) {
            it?.action?.let { action ->
                Log.v(TAG, "Broadcast request received: $action")
                when (action) {
                    ACTION_CONNECT -> connect()
                    ACTION_DISCONNECT -> disconnect()
                    else -> Log.w(TAG, "Unknown action received: $action")
                }
            }
        }

        notificationStateReceiver = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            registerBroadcastReceiver(
                arrayOf(
                    NotificationManager.ACTION_NOTIFICATION_CHANNEL_BLOCK_STATE_CHANGED,
                    NotificationManager.ACTION_APP_BLOCK_STATE_CHANGED
                )
            ) {
                val state = it?.getBooleanExtra(NotificationManager.EXTRA_BLOCKED_STATE, false)
                Log.v(TAG, "Notification state changed: ${it?.action}, blocked = $state")
                if (state == false) {
                    enableNotification()
                } else {
                    disableNotification()
                }
            }
        } else null

        registerScreenStateBroadcastReceivers()
    }

    private fun registerScreenStateBroadcastReceivers() {
        if (serviceNotification.isNotificationEnabled()) {
            Log.d(TAG, "Register screen state broadcast receivers")
            screenOnReceiver = registerBroadcastReceiver(Intent.ACTION_SCREEN_ON) {
                if (isConnected && serviceNotification.isNotificationEnabled()) startTrafficStatsUpdateJob()
            }

            screenOffReceiver = registerBroadcastReceiver(Intent.ACTION_SCREEN_OFF) {
                stopTrafficStatsUpdateJob()
            }
        }
    }

    private fun unregisterScreenStateBroadcastReceivers() {
        Log.d(TAG, "Unregister screen state broadcast receivers")
        unregisterBroadcastReceiver(screenOnReceiver)
        unregisterBroadcastReceiver(screenOffReceiver)
        screenOnReceiver = null
        screenOffReceiver = null
    }

    private fun unregisterBroadcastReceivers() {
        Log.d(TAG, "Unregister broadcast receivers")
        unregisterBroadcastReceiver(controlReceiver)
        unregisterBroadcastReceiver(notificationStateReceiver)
        unregisterScreenStateBroadcastReceivers()
        controlReceiver = null
        notificationStateReceiver = null
    }

    /**
     * Methods responsible for processing VPN connection
     */
    private fun launchProtocolStateHandler() {
        mainScope.launch {
            // drop first default UNKNOWN state
            protocolState.drop(1).collect { protocolState ->
                Log.d(TAG, "Protocol state changed: $protocolState")

                serviceNotification.updateNotification(serverName, vpnProto?.label, protocolState)

                clientMessengers.send {
                    ServiceEvent.STATUS_CHANGED.packToMessage {
                        putStatus(protocolState)
                    }
                }

                VpnStateStore.store { VpnState(protocolState, serverName, serverIndex, vpnProto) }

                when (protocolState) {
                    CONNECTED -> {
                        if (this@AmneziaVpnService.protocolState.value != CONNECTED) return@collect
                        networkState.bindNetworkListener()
                        configureRemoteLogUploader(activeVpnConfig)
                        // if (isActivityConnected) launchSendingStatistics()
                        launchTrafficStatsUpdate()
                    }

                    DISCONNECTED -> {
                        if (this@AmneziaVpnService.protocolState.value != DISCONNECTED) return@collect
                        networkState.unbindNetworkListener()
                        stopRemoteLogUploader()
                        activeVpnConfig = null
                        stopTrafficStatsUpdateJob()
                        // stopSendingStatistics()
                        if (!isServiceBound) stopService()
                    }

                    DISCONNECTING -> {
                        networkState.unbindNetworkListener()
                        stopRemoteLogUploader()
                        stopTrafficStatsUpdateJob()
                        // stopSendingStatistics()
                    }

                    RECONNECTING -> {
                        stopTrafficStatsUpdateJob()
                        // stopSendingStatistics()
                    }

                    CONNECTING, UNKNOWN -> {}
                }
            }
        }
    }

/*  @MainThread
    private fun launchSendingStatistics() {
        if (isServiceBound && isConnected) {
            statisticsSendingJob = mainScope.launch {
                while (true) {
                    clientMessenger.send {
                        ServiceEvent.STATISTICS_UPDATE.packToMessage {
                            putStatistics(protocol?.statistics ?: Statistics.EMPTY_STATISTICS)
                        }
                    }
                    delay(STATISTICS_SENDING_TIMEOUT)
                }
            }
        }
    }

    @MainThread
    private fun stopSendingStatistics() {
        statisticsSendingJob?.cancel()
    } */

    @MainThread
    private fun enableNotification() {
        registerScreenStateBroadcastReceivers()
        serviceNotification.updateNotification(serverName, vpnProto?.label, protocolState.value)
        launchTrafficStatsUpdate()
    }

    @MainThread
    private fun disableNotification() {
        unregisterScreenStateBroadcastReceivers()
        stopTrafficStatsUpdateJob()
    }

    @MainThread
    private fun launchTrafficStatsUpdate() {
        stopTrafficStatsUpdateJob()
        if (isConnected &&
            serviceNotification.isNotificationEnabled() &&
            getSystemService<PowerManager>()?.isInteractive != false
        ) {
            Log.v(TAG, "Launch traffic stats update")
            trafficStats.reset()
            startTrafficStatsUpdateJob()
        }
    }

    @MainThread
    private fun startTrafficStatsUpdateJob() {
        if (trafficStatsUpdateJob == null && trafficStats.isSupported()) {
            Log.d(TAG, "Start traffic stats update")
            trafficStatsUpdateJob = mainScope.launch {
                while (true) {
                    trafficStats.getSpeed().let { speed ->
                        if (isConnected) {
                            serviceNotification.updateSpeed(speed)
                        }
                    }
                    delay(TRAFFIC_STATS_UPDATE_TIMEOUT)
                }
            }
        }
    }

    @MainThread
    private fun stopTrafficStatsUpdateJob() {
        Log.d(TAG, "Stop traffic stats update")
        trafficStatsUpdateJob?.cancel()
        trafficStatsUpdateJob = null
    }

    @MainThread
    private fun connect(vpnConfig: String? = null) {
        if (vpnConfig == null) {
            connectToVpn(Prefs.load(PREFS_CONFIG_KEY))
        } else {
            if (!isDisconnected && !isUnknown) return
            Prefs.save(PREFS_CONFIG_KEY, vpnConfig)
            connectToVpn(vpnConfig)
        }
    }

    @MainThread
    private fun connectToVpn(vpnConfig: String) {
        if (!isDisconnected && !isUnknown) return

        Log.d(TAG, "Start VPN connection")

        val config = parseConfigToJson(vpnConfig)
        saveServerData(config)
        if (config == null) {
            activeVpnConfig = null
            stopRemoteLogUploader()
            onError("Invalid VPN config")
            protocolState.value = DISCONNECTED
            return
        }

        try {
            vpnProto = VpnProto.get(config.getString("protocol"))
        } catch (e: Exception) {
            activeVpnConfig = null
            stopRemoteLogUploader()
            onError("Invalid VPN config: ${e.message}")
            protocolState.value = DISCONNECTED
            return
        }

        protocolState.value = CONNECTING

        if (!checkPermission()) {
            activeVpnConfig = null
            stopRemoteLogUploader()
            protocolState.value = DISCONNECTED
            return
        }

        activeVpnConfig = JSONObject(config.toString())
        configureRemoteLogUploader(activeVpnConfig)

        connectionJob = connectionScope.launch {
            disconnectionJob?.join()
            disconnectionJob = null

            vpnProto?.protocol?.let { protocol ->
                protocol.initialize(applicationContext, protocolState, ::onError)
                protocol.startVpn(config, Builder(), ::protect)
            }
        }
    }

    @MainThread
    private fun disconnect() {
        if (isUnknown || isDisconnected || protocolState.value == DISCONNECTING) return

        Log.d(TAG, "Stop VPN connection")

        stopRemoteLogUploader()
        protocolState.value = DISCONNECTING

        disconnectionJob = connectionScope.launch {
            connectionJob?.cancelAndJoin()
            connectionJob = null

            vpnProto?.protocol?.stopVpn()

            try {
                withTimeout(DISCONNECT_TIMEOUT) {
                    // waiting for disconnect state
                    protocolState.first { it == DISCONNECTED }
                }
            } catch (e: TimeoutCancellationException) {
                Log.w(TAG, "Disconnect timeout")
                stopService()
            }
        }
    }

    @MainThread
    private fun reconnect() {
        if (!isConnected) return

        Log.d(TAG, "Reconnect VPN")

        protocolState.value = RECONNECTING

        connectionJob = connectionScope.launch {
            vpnProto?.protocol?.reconnectVpn(Builder(), ::protect)
        }
    }

    private fun configureRemoteLogUploader(config: JSONObject?) {
        var targetChanged = false
        var staleConnection: HttpURLConnection? = null
        var staleJob: Job? = null
        val target = synchronized(remoteLogTargetLock) {
            val parsedTarget = parseRemoteLogTarget(config)
            if (parsedTarget != null && remoteLogTarget != parsedTarget) {
                staleConnection = remoteLogActiveConnection
                remoteLogActiveConnection = null
                staleJob = remoteLogUploadJob
                remoteLogUploadJob = null
                remoteLogTarget = parsedTarget
                remoteLogTargetGeneration++
                remoteLogPausedGeneration = -1L
                targetChanged = true
            }
            parsedTarget
        }
        if (target == null) {
            stopRemoteLogUploader()
            return
        }
        staleConnection?.disconnect()
        staleJob?.cancel()
        if (targetChanged) writeRemoteLogOriginCheckpoint()
        launchRemoteLogUploadJobIfNeeded()
    }

    private fun launchRemoteLogUploadJobIfNeeded() {
        synchronized(remoteLogTargetLock) {
            if (remoteLogTarget == null || remoteLogUploadJob?.isActive == true) return
            remoteLogUploadJob = connectionScope.launch {
                delay(CLIENT_LOGS_INITIAL_UPLOAD_DELAY)
                var consecutiveFailures = 0
                var observedGeneration = remoteLogTargetGeneration
                try {
                    while (true) {
                        val generationBeforeAttempt = remoteLogTargetGeneration
                        if (generationBeforeAttempt != observedGeneration) {
                            observedGeneration = generationBeforeAttempt
                            consecutiveFailures = 0
                        }
                        val outcome = uploadRemoteLogsOnce()
                        val generationAfterAttempt = remoteLogTargetGeneration
                        val nextDelay = if (generationAfterAttempt != observedGeneration) {
                            observedGeneration = generationAfterAttempt
                            consecutiveFailures = 0
                            CLIENT_LOGS_INITIAL_UPLOAD_DELAY
                        } else {
                            when (outcome.result) {
                                RemoteLogUploadResult.ACCEPTED,
                                RemoteLogUploadResult.IDLE,
                                RemoteLogUploadResult.PAUSED -> {
                                    consecutiveFailures = 0
                                    CLIENT_LOGS_UPLOAD_INTERVAL
                                }
                                RemoteLogUploadResult.RETRY -> {
                                    consecutiveFailures = (consecutiveFailures + 1).coerceAtMost(31)
                                    outcome.retryAfterMs ?: remoteLogRetryDelayMs(
                                        consecutiveFailures,
                                        Random.nextInt(
                                            -CLIENT_LOGS_RETRY_JITTER_PERMILLE,
                                            CLIENT_LOGS_RETRY_JITTER_PERMILLE + 1
                                        )
                                    )
                                }
                            }
                        }
                        delay(nextDelay)
                    }
                } finally {
                    val completedJob = coroutineContext[Job]
                    synchronized(remoteLogTargetLock) {
                        if (remoteLogUploadJob === completedJob) {
                            remoteLogUploadJob = null
                        }
                    }
                }
            }
        }
    }

    private fun stopRemoteLogUploader() {
        val (activeConnection, uploadJob) = synchronized(remoteLogTargetLock) {
            remoteLogTarget = null
            remoteLogTargetGeneration++
            remoteLogPausedGeneration = -1L
            val connection = remoteLogActiveConnection
            remoteLogActiveConnection = null
            val job = remoteLogUploadJob
            remoteLogUploadJob = null
            connection to job
        }
        activeConnection?.disconnect()
        uploadJob?.cancel()
    }

    private fun currentRemoteLogAttempt(): RemoteLogAttempt? = synchronized(remoteLogTargetLock) {
        val target = remoteLogTarget ?: return@synchronized null
        val generation = remoteLogTargetGeneration
        if (remoteLogPausedGeneration == generation || protocolState.value != CONNECTED) {
            null
        } else {
            RemoteLogAttempt(target, generation)
        }
    }

    private fun isRemoteLogAttemptActive(attempt: RemoteLogAttempt): Boolean = synchronized(remoteLogTargetLock) {
        remoteLogTarget == attempt.target &&
            remoteLogTargetGeneration == attempt.generation &&
            protocolState.value == CONNECTED
    }

    private fun pauseRemoteLogAttempt(attempt: RemoteLogAttempt): Boolean = synchronized(remoteLogTargetLock) {
        if (remoteLogTarget != attempt.target || remoteLogTargetGeneration != attempt.generation ||
            protocolState.value != CONNECTED
        ) {
            false
        } else {
            remoteLogPausedGeneration = attempt.generation
            true
        }
    }

    private fun registerRemoteLogConnection(
        attempt: RemoteLogAttempt,
        connection: HttpURLConnection
    ): Boolean = synchronized(remoteLogTargetLock) {
        if (remoteLogTarget != attempt.target || remoteLogTargetGeneration != attempt.generation ||
            remoteLogPausedGeneration == attempt.generation || protocolState.value != CONNECTED
        ) {
            false
        } else {
            remoteLogActiveConnection = connection
            true
        }
    }

    private fun releaseRemoteLogConnection(connection: HttpURLConnection) {
        synchronized(remoteLogTargetLock) {
            if (remoteLogActiveConnection === connection) {
                remoteLogActiveConnection = null
            }
        }
    }

    private fun parseRemoteLogTarget(config: JSONObject?): RemoteLogTarget? {
        val clientLogs = config?.optJSONObject(CLIENT_LOGS_KEY) ?: deriveLegacyRemoteLogTarget(config) ?: return null
        val endpoint = clientLogs.optString(CLIENT_LOGS_ENDPOINT_KEY)
        val clientId = clientLogs.optString(CLIENT_LOGS_CLIENT_ID_KEY)
        val bootstrap = clientLogs.optBoolean(CLIENT_LOGS_BOOTSTRAP_KEY, false)
        val configuredToken = clientLogs.optString(CLIENT_LOGS_TOKEN_KEY)
        val tokenCacheKey = remoteLogTokenPrefsKey(config?.optString("hostName").orEmpty(), clientId)
        val token = when {
            configuredToken.isNotEmpty() -> {
                if (!isValidRemoteLogToken(configuredToken)) return null
                configuredToken
            }
            bootstrap -> Prefs.loadSecureString(tokenCacheKey).takeIf(::isValidRemoteLogToken).orEmpty()
            else -> ""
        }
        if (endpoint != CLIENT_LOGS_TRUSTED_ENDPOINT || !SHA256_HEX_PATTERN.matches(clientId) ||
            (!bootstrap && !isValidRemoteLogToken(token))
        ) {
            return null
        }
        return RemoteLogTarget(endpoint, clientId, token, bootstrap, tokenCacheKey)
    }

    private fun deriveLegacyRemoteLogTarget(config: JSONObject?): JSONObject? {
        if (config == null || config.has(CLIENT_LOGS_KEY)) return null

        val protocol = config.optString("protocol").lowercase(Locale.US)
        val configKey = protocol + "_config_data"
        val configData = config.optJSONObject(configKey) ?: return null
        val containerScope = when (protocol) {
            "wireguard" -> "amnezia-wireguard"
            "awg" -> if (configData.optString("protocol_version") == "2") "amnezia-awg2" else "amnezia-awg"
            else -> return null
        }
        if (configData.optBoolean("isThirdPartyConfig", false)) return null

        val clientId = configData.optString(CLIENT_LOGS_CLIENT_ID_KEY).ifBlank {
            configData.optString("client_pub_key")
        }
        if (clientId.isBlank()) return null

        val clientLogId = sha256Hex("$containerScope\t$clientId")
        return JSONObject().apply {
            put(CLIENT_LOGS_ENDPOINT_KEY, CLIENT_LOGS_TRUSTED_ENDPOINT)
            put(CLIENT_LOGS_CLIENT_ID_KEY, clientLogId)
            put(CLIENT_LOGS_BOOTSTRAP_KEY, true)
        }
    }

    private fun uploadRemoteLogsOnce(
        allowTokenRefreshRetry: Boolean = true,
        sanitizerExplicitSecrets: List<String>? = null,
        requiredInitialAttempt: RemoteLogAttempt? = null
    ): RemoteLogUploadOutcome {
        var connection: HttpURLConnection? = null
        val initialAttempt = currentRemoteLogAttempt()
        if (initialAttempt == null) {
            val paused = synchronized(remoteLogTargetLock) {
                remoteLogTarget != null && remoteLogPausedGeneration == remoteLogTargetGeneration &&
                    protocolState.value == CONNECTED
            }
            return RemoteLogUploadOutcome(
                if (paused) RemoteLogUploadResult.PAUSED else RemoteLogUploadResult.IDLE
            )
        }
        var attempt = initialAttempt
        return try {
            if (requiredInitialAttempt != null && attempt != requiredInitialAttempt) {
                return RemoteLogUploadOutcome(RemoteLogUploadResult.IDLE)
            }
            var target = attempt.target
            if (target.token.isEmpty()) {
                val bootstrapOutcome = bootstrapRemoteLogTarget(attempt)
                val bootstrappedTarget = bootstrapOutcome.target
                if (bootstrappedTarget == null) {
                    if (!isRemoteLogAttemptActive(attempt)) {
                        return RemoteLogUploadOutcome(RemoteLogUploadResult.IDLE)
                    }
                    if (bootstrapOutcome.permanentFailure && pauseRemoteLogAttempt(attempt)) {
                        Log.w(TAG, "Remote log uploader paused after permanent bootstrap failure")
                        return RemoteLogUploadOutcome(RemoteLogUploadResult.PAUSED)
                    }
                    return RemoteLogUploadOutcome(
                        RemoteLogUploadResult.RETRY,
                        bootstrapOutcome.retryAfterMs
                    )
                }
                var secureStoreFailed = false
                val installAttempt = attempt
                val installed = synchronized(remoteLogTargetLock) {
                    val token = bootstrappedTarget.token
                    if (remoteLogTarget != target || remoteLogTargetGeneration != installAttempt.generation ||
                        protocolState.value != CONNECTED
                    ) {
                        false
                    } else if (!Prefs.saveSecureString(target.tokenCacheKey, token)) {
                        Log.w(TAG, "Remote log bootstrap token was not stored securely")
                        secureStoreFailed = true
                        false
                    } else {
                        remoteLogTarget = bootstrappedTarget
                        true
                    }
                }
                if (!installed) {
                    return RemoteLogUploadOutcome(
                        if (secureStoreFailed) RemoteLogUploadResult.RETRY else RemoteLogUploadResult.IDLE
                    )
                }
                target = bootstrappedTarget
                attempt = attempt.copy(target = target)
                Log.d(TAG, "Remote log bootstrap succeeded")
            }
            if (!isRemoteLogAttemptActive(attempt)) return RemoteLogUploadOutcome(RemoteLogUploadResult.IDLE)

            val logBytes = Log.getAppLogs(CLIENT_LOGS_MAX_PAYLOAD_BYTES).toByteArray(Charsets.UTF_8)
            val payload = prepareRemoteLogPayload(
                target = target,
                logBytes = logBytes,
                explicitSecrets = sanitizerExplicitSecrets ?: listOf(
                    target.token,
                    remoteLogInstallationId(),
                    loadRemoteLogOriginNonce().orEmpty()
                )
            ) ?: return RemoteLogUploadOutcome(RemoteLogUploadResult.IDLE)
            if (!saveRemoteLogCursorForAttempt(attempt, payload.cursorBeforeUpload)) {
                Log.w(TAG, "Remote log cursor could not be persisted; upload postponed")
                return RemoteLogUploadOutcome(
                    if (isRemoteLogAttemptActive(attempt)) {
                        RemoteLogUploadResult.RETRY
                    } else {
                        RemoteLogUploadResult.IDLE
                    }
                )
            }

            connection = (URL(target.endpoint).openConnection(Proxy.NO_PROXY) as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = CLIENT_LOGS_UPLOAD_TIMEOUT
                readTimeout = CLIENT_LOGS_UPLOAD_TIMEOUT
                instanceFollowRedirects = false
                useCaches = false
                doOutput = true
                setRequestProperty("Content-Type", "text/plain; charset=utf-8")
                setRequestProperty("X-Amnezia-Client-Id", target.clientId)
                setRequestProperty("X-Amnezia-Log-Token", target.token)
                setRequestProperty("X-Amnezia-Log-Kind", CLIENT_LOGS_KIND_ANDROID)
                setRequestProperty("X-Amnezia-Installation-Id", remoteLogInstallationId())
                setRequestProperty("X-Amnezia-Batch-Id", payload.batchId)
                setFixedLengthStreamingMode(payload.data.size)
            }
            if (!registerRemoteLogConnection(attempt, connection)) {
                return RemoteLogUploadOutcome(RemoteLogUploadResult.IDLE)
            }
            if (!isRemoteLogAttemptActive(attempt)) return RemoteLogUploadOutcome(RemoteLogUploadResult.IDLE)
            connection.outputStream.use { output -> output.write(payload.data) }
            val statusCode = connection.responseCode
            if (!isRemoteLogAttemptActive(attempt)) return RemoteLogUploadOutcome(RemoteLogUploadResult.IDLE)
            val batchAccepted = isRemoteLogUploadAcknowledged(
                statusCode = statusCode,
                acceptedHeader = connection.getHeaderField(CLIENT_LOGS_BATCH_ACCEPTED_HEADER),
                echoedBatchId = connection.getHeaderField(CLIENT_LOGS_BATCH_ID_HEADER),
                expectedBatchId = payload.batchId
            )
            if (batchAccepted) {
                if (!saveRemoteLogCursorForAttempt(attempt, payload.cursorAfterUpload)) {
                    Log.w(TAG, "Remote log cursor acknowledgement could not be persisted")
                    RemoteLogUploadOutcome(
                        if (isRemoteLogAttemptActive(attempt)) {
                            RemoteLogUploadResult.RETRY
                        } else {
                            RemoteLogUploadResult.IDLE
                        }
                    )
                } else {
                    RemoteLogUploadOutcome(RemoteLogUploadResult.ACCEPTED)
                }
            } else {
                if (statusCode in 200..299) {
                    Log.w(TAG, "Remote log upload response did not acknowledge the expected batch")
                }
                if ((statusCode == 401 || statusCode == 403) && target.bootstrap && allowTokenRefreshRetry) {
                    val retryTarget = target.copy(token = "")
                    var secureStoreFailed = false
                    val refreshAttempt = attempt
                    val retryAllowed = synchronized(remoteLogTargetLock) {
                        if (remoteLogTarget != target || remoteLogTargetGeneration != refreshAttempt.generation ||
                            protocolState.value != CONNECTED
                        ) {
                            false
                        } else if (!Prefs.saveSecureString(target.tokenCacheKey, "")) {
                            Log.w(TAG, "Remote log bootstrap token could not be cleared securely")
                            secureStoreFailed = true
                            false
                        } else {
                            remoteLogTarget = retryTarget
                            true
                        }
                    }
                    if (secureStoreFailed) return RemoteLogUploadOutcome(RemoteLogUploadResult.RETRY)
                    if (retryAllowed) {
                        releaseRemoteLogConnection(connection)
                        connection.disconnect()
                        connection = null
                        val retryAttempt = attempt.copy(target = retryTarget)
                        return uploadRemoteLogsOnce(
                            allowTokenRefreshRetry = false,
                            sanitizerExplicitSecrets = payload.sanitizerExplicitSecrets,
                            requiredInitialAttempt = retryAttempt
                        )
                    }
                    return RemoteLogUploadOutcome(RemoteLogUploadResult.IDLE)
                }
                if (statusCode <= 0) {
                    Log.w(TAG, "Remote log upload returned no valid HTTP status")
                    RemoteLogUploadOutcome(RemoteLogUploadResult.RETRY)
                } else if (statusCode == 429 || statusCode == 503) {
                    val retryAfterMs = remoteLogRetryAfterMs(connection.getHeaderField("Retry-After"))
                    Log.w(TAG, "Remote log upload throttled: status=$statusCode retryAfterMs=$retryAfterMs")
                    RemoteLogUploadOutcome(RemoteLogUploadResult.RETRY, retryAfterMs)
                } else if (statusCode == 408 || statusCode == 425 || statusCode in 500..599) {
                    Log.w(TAG, "Remote log upload failed transiently: status=$statusCode")
                    RemoteLogUploadOutcome(RemoteLogUploadResult.RETRY)
                } else if (pauseRemoteLogAttempt(attempt)) {
                    Log.w(TAG, "Remote log uploader paused after non-retryable response: status=$statusCode")
                    RemoteLogUploadOutcome(RemoteLogUploadResult.PAUSED)
                } else {
                    RemoteLogUploadOutcome(RemoteLogUploadResult.IDLE)
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            if (!isRemoteLogAttemptActive(attempt)) {
                RemoteLogUploadOutcome(RemoteLogUploadResult.IDLE)
            } else {
                Log.w(TAG, "Remote log upload failed: $e")
                RemoteLogUploadOutcome(RemoteLogUploadResult.RETRY)
            }
        } finally {
            connection?.let {
                releaseRemoteLogConnection(it)
                it.disconnect()
            }
        }
    }

    private fun bootstrapRemoteLogTarget(attempt: RemoteLogAttempt): RemoteLogBootstrapOutcome {
        val target = attempt.target
        if (!target.bootstrap || target.clientId.isBlank()) {
            return RemoteLogBootstrapOutcome(permanentFailure = true)
        }

        var connection: HttpURLConnection? = null
        return try {
            connection = (URL(CLIENT_LOGS_BOOTSTRAP_ENDPOINT).openConnection(Proxy.NO_PROXY) as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = CLIENT_LOGS_UPLOAD_TIMEOUT
                readTimeout = CLIENT_LOGS_UPLOAD_TIMEOUT
                instanceFollowRedirects = false
                useCaches = false
                doOutput = true
                setRequestProperty("X-Amnezia-Client-Id", target.clientId)
                setRequestProperty("X-Amnezia-Installation-Id", remoteLogInstallationId())
                setFixedLengthStreamingMode(0)
            }
            if (!registerRemoteLogConnection(attempt, connection)) return RemoteLogBootstrapOutcome()
            connection.outputStream.use { }
            val statusCode = connection.responseCode
            if (!isRemoteLogAttemptActive(attempt)) return RemoteLogBootstrapOutcome()
            if (statusCode !in 200..299) {
                Log.w(TAG, "Remote log bootstrap failed: status=$statusCode endpoint=$CLIENT_LOGS_BOOTSTRAP_ENDPOINT clientId=${target.clientId}")
                return when {
                    statusCode <= 0 -> RemoteLogBootstrapOutcome()
                    statusCode == 429 || statusCode == 503 -> RemoteLogBootstrapOutcome(
                        retryAfterMs = remoteLogRetryAfterMs(connection.getHeaderField("Retry-After"))
                    )
                    statusCode == 408 || statusCode == 425 || statusCode in 500..599 ->
                        RemoteLogBootstrapOutcome()
                    else -> RemoteLogBootstrapOutcome(permanentFailure = true)
                }
            }
            val response = readLimitedUtf8(connection.inputStream, CLIENT_LOGS_MAX_BOOTSTRAP_RESPONSE_BYTES)
            if (response == null) {
                Log.w(TAG, "Remote log bootstrap response is too large")
                return RemoteLogBootstrapOutcome(permanentFailure = true)
            }
            val clientLogs = JSONObject(response)
            val endpoint = clientLogs.optString(CLIENT_LOGS_ENDPOINT_KEY)
            val clientId = clientLogs.optString(CLIENT_LOGS_CLIENT_ID_KEY)
            val token = clientLogs.optString(CLIENT_LOGS_TOKEN_KEY)
            if (endpoint != target.endpoint || clientId != target.clientId ||
                !SHA256_HEX_PATTERN.matches(clientId) || !isValidRemoteLogToken(token)
            ) {
                Log.w(TAG, "Remote log bootstrap returned invalid target")
                return RemoteLogBootstrapOutcome(permanentFailure = true)
            }
            RemoteLogBootstrapOutcome(target = target.copy(token = token))
        } catch (e: CancellationException) {
            throw e
        } catch (e: JSONException) {
            Log.w(TAG, "Remote log bootstrap returned invalid JSON")
            RemoteLogBootstrapOutcome(permanentFailure = true)
        } catch (e: Exception) {
            Log.w(TAG, "Remote log bootstrap failed: $e")
            RemoteLogBootstrapOutcome()
        } finally {
            connection?.let {
                releaseRemoteLogConnection(it)
                it.disconnect()
            }
        }
    }

    private fun remoteLogInstallationId(): String {
        remoteLogInstallationIdCache?.let { return it }
        val existing = Prefs.load<String>(PREFS_REMOTE_LOG_INSTALLATION_ID).trim()
        try {
            if (existing.isNotBlank()) {
                return UUID.fromString(existing).toString().also { remoteLogInstallationIdCache = it }
            }
        } catch (_: IllegalArgumentException) {
            Log.w(TAG, "Replacing invalid remote log installation identifier")
        }
        val created = UUID.randomUUID().toString()
        Prefs.save(PREFS_REMOTE_LOG_INSTALLATION_ID, created)
        remoteLogInstallationIdCache = created
        return created
    }

    private fun loadRemoteLogOriginNonce(): String? {
        val stored = Prefs.load<String>(PREFS_REMOTE_LOG_ORIGIN_NONCE).trim()
        return try {
            UUID.fromString(stored).toString().takeIf { it == stored.lowercase(Locale.US) }
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    private fun writeRemoteLogOriginCheckpoint(): Boolean = synchronized(remoteLogOriginLock) {
        val nonce = UUID.randomUUID().toString()
        val stored = Prefs.prefs.edit().putString(PREFS_REMOTE_LOG_ORIGIN_NONCE, nonce).commit()
        if (!stored) {
            Log.w(TAG, "Remote log origin checkpoint could not be persisted")
            false
        } else {
            Log.i(TAG, "$CLIENT_LOGS_ORIGIN_MARKER $nonce")
            true
        }
    }

    private fun remoteLogOriginCheckpointOffset(logBytes: ByteArray, nonce: String): Int? {
        val canonicalNonce = try {
            UUID.fromString(nonce).toString()
        } catch (_: IllegalArgumentException) {
            return null
        }
        if (canonicalNonce != nonce.lowercase(Locale.US)) return null
        val marker = "$TAG: $CLIENT_LOGS_ORIGIN_MARKER $canonicalNonce\n".toByteArray(Charsets.UTF_8)
        if (marker.size > logBytes.size) return null

        for (candidate in logBytes.size - marker.size downTo 0) {
            var matches = true
            for (index in marker.indices) {
                if (logBytes[candidate + index] != marker[index]) {
                    matches = false
                    break
                }
            }
            if (!matches) continue

            var lineStart = candidate
            while (lineStart > 0 && logBytes[lineStart - 1] != '\n'.code.toByte()) lineStart--
            if (candidate - lineStart > 512) continue
            val prefix = logBytes.copyOfRange(lineStart, candidate).toString(Charsets.UTF_8)
            if (CLIENT_LOGS_ORIGIN_RECORD_PREFIX_PATTERN.matches(prefix)) {
                return candidate + marker.size
            }
        }
        return null
    }

    private fun freshRemoteLogCursorAtOrigin(
        logBytes: ByteArray,
        explicitSecretsSha256: String
    ): RemoteLogCursor? {
        val nonce = loadRemoteLogOriginNonce() ?: return null
        val offset = remoteLogOriginCheckpointOffset(logBytes, nonce) ?: return null
        val fingerprintBytes = minOf(CLIENT_LOGS_CURSOR_FINGERPRINT_BYTES, logBytes.size)
        return RemoteLogCursor(
            offset = offset,
            fingerprint = sha256Hex(logBytes.copyOfRange(0, fingerprintBytes)),
            fingerprintBytes = fingerprintBytes,
            anchor = remoteLogAnchor(logBytes, offset),
            sanitizerExplicitSecretsSha256 = explicitSecretsSha256
        )
    }

    private fun remoteLogTokenPrefsKey(hostName: String, clientId: String): String =
        PREFS_REMOTE_LOG_TOKEN_PREFIX + sha256Hex("$hostName\t$clientId")

    private fun prepareRemoteLogPayload(
        target: RemoteLogTarget,
        logBytes: ByteArray,
        explicitSecrets: List<String>
    ): RemoteLogPayload? {
        if (logBytes.isEmpty() || !remoteLogSanitizerContractVerified) return null

        val sanitizerSecrets = normalizedRemoteLogExplicitSecrets(explicitSecrets)
        val explicitSecretsSha256 = remoteLogExplicitSecretsSha256(sanitizerSecrets)
        val storedCursor = loadRemoteLogCursor(target)
        var cursor = storedCursor
        val cursorFingerprintMatches = cursor.fingerprintBytes in 1..logBytes.size &&
            cursor.fingerprint == sha256Hex(logBytes.copyOfRange(0, cursor.fingerprintBytes))
        val cursorOffsetMatches = cursor.offset in 0..logBytes.size &&
            (cursor.offset == 0 || cursor.anchor == remoteLogAnchor(logBytes, cursor.offset))
        if (!cursorFingerprintMatches || !cursorOffsetMatches) {
            cursor = freshRemoteLogCursorAtOrigin(logBytes, explicitSecretsSha256) ?: run {
                writeRemoteLogOriginCheckpoint()
                return null
            }
        }

        var offset = cursor.offset
        var retryingPendingPayload = cursor.pendingEndOffset > offset
        if (retryingPendingPayload) {
            val pendingBodyMatches = cursor.pendingEndOffset <= logBytes.size &&
                cursor.pendingBodySha256 == sha256Hex(logBytes.copyOfRange(offset, cursor.pendingEndOffset))
            if (!pendingBodyMatches) {
                cursor = freshRemoteLogCursorAtOrigin(logBytes, explicitSecretsSha256) ?: run {
                    writeRemoteLogOriginCheckpoint()
                    return null
                }
                offset = cursor.offset
                retryingPendingPayload = false
            }
        }

        val endOffset = if (retryingPendingPayload) {
            cursor.pendingEndOffset
        } else {
            minOf(logBytes.size.toLong(), offset.toLong() + CLIENT_LOGS_MAX_BATCH_RAW_BYTES).toInt()
        }
        if (offset >= endOffset) return null

        val body = logBytes.copyOfRange(offset, endOffset)
        val rawBodySha256 = sha256Hex(body)
        val explicitSecretSetChanged = retryingPendingPayload &&
            cursor.sanitizerExplicitSecretsSha256 != explicitSecretsSha256
        if (!retryingPendingPayload) {
            cursor = cursor.copy(sanitizerExplicitSecretsSha256 = explicitSecretsSha256)
        }
        val sanitizedPayload = sanitizeRemoteLogPayload(
            payload = body,
            explicitSecrets = sanitizerSecrets,
            initialState = RemoteLogSanitizerState(
                blockEndMarker = cursor.sanitizerBlockEndMarker,
                blockEndPrefixChars = cursor.sanitizerBlockEndPrefixChars,
                secretMode = cursor.sanitizerSecretMode,
                secretQuote = cursor.sanitizerSecretQuote,
                secretEscaped = cursor.sanitizerSecretEscaped,
                structuredClosers = cursor.sanitizerStructuredClosers
            ),
            forceRedactedOutput = explicitSecretSetChanged
        )
        val uploadBody = sanitizedPayload.data
        val bodyBoundFingerprint = "${cursor.fingerprint}:$rawBodySha256:${sha256Hex(uploadBody)}"
        val candidateBatchId = remoteLogBatchId(
            target = target,
            kind = CLIENT_LOGS_KIND_ANDROID,
            fingerprint = bodyBoundFingerprint,
            offset = offset,
            length = uploadBody.size
        )
        val batchId = if (retryingPendingPayload) cursor.pendingBatchId else candidateBatchId
        val cursorBeforeUpload = cursor.copy(
            pendingEndOffset = endOffset,
            pendingBodySha256 = rawBodySha256,
            pendingBatchId = batchId
        )
        val cursorAfterUpload = RemoteLogCursor(
            offset = endOffset,
            fingerprint = cursor.fingerprint,
            fingerprintBytes = cursor.fingerprintBytes,
            anchor = remoteLogAnchor(logBytes, endOffset),
            sanitizerBlockEndMarker = sanitizedPayload.state.blockEndMarker,
            sanitizerBlockEndPrefixChars = sanitizedPayload.state.blockEndPrefixChars,
            sanitizerSecretMode = sanitizedPayload.state.secretMode,
            sanitizerSecretQuote = sanitizedPayload.state.secretQuote,
            sanitizerSecretEscaped = sanitizedPayload.state.secretEscaped,
            sanitizerStructuredClosers = sanitizedPayload.state.structuredClosers,
            sanitizerExplicitSecretsSha256 = explicitSecretsSha256
        )
        return RemoteLogPayload(
            uploadBody,
            cursorBeforeUpload,
            cursorAfterUpload,
            batchId,
            sanitizerSecrets
        )
    }

    private fun isValidRemoteLogToken(value: String): Boolean =
        value.length in 8..CLIENT_LOGS_MAX_TOKEN_CHARS &&
            value.all { it.code in 0x21..0x7e }

    private fun normalizedRemoteLogExplicitSecrets(explicitSecrets: List<String>): List<String> =
        explicitSecrets.asSequence()
            .filter { it.length in 8..CLIENT_LOGS_SANITIZER_MAX_EXPLICIT_SECRET_CHARS }
            .filter { it != CLIENT_LOGS_REDACTED }
            .distinct()
            .sorted()
            .take(CLIENT_LOGS_SANITIZER_MAX_EXPLICIT_SECRETS)
            .toList()

    private fun remoteLogExplicitSecretsSha256(explicitSecrets: List<String>): String =
        sha256Hex(explicitSecrets.joinToString("\u0000"))

    private fun sanitizeRemoteLogPayload(
        payload: ByteArray,
        explicitSecrets: List<String> = emptyList(),
        initialState: RemoteLogSanitizerState = RemoteLogSanitizerState(),
        forceRedactedOutput: Boolean = false,
        maxOutputBytes: Int = CLIENT_LOGS_MAX_PAYLOAD_BYTES
    ): RemoteLogSanitizedPayload {
        if (payload.isEmpty()) return RemoteLogSanitizedPayload(payload, initialState)

        val safeInitialState = if (isValidRemoteLogSanitizerState(initialState)) {
            initialState
        } else {
            RemoteLogSanitizerState(secretMode = CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED)
        }
        val budget = RemoteLogSanitizerBudget()
        val source = payload.toString(Charsets.UTF_8)
        val structured = sanitizeRemoteLogStructuredText(
            source,
            safeInitialState,
            budget,
            maxOutputBytes
        )
        val trailingPartialRecord = !source.endsWith('\n')
        val lines = sanitizeRemoteLogLines(
            source = structured.text,
            budget = budget,
            redactTrailingPartialRecord = trailingPartialRecord,
            maxOutputBytes = maxOutputBytes
        )
        val exactSecretsRedacted = redactRemoteLogExplicitSecrets(
            lines.text,
            normalizedRemoteLogExplicitSecrets(explicitSecrets),
            maxOutputBytes
        )

        val sanitizedBytes = exactSecretsRedacted.text.toByteArray(Charsets.UTF_8)
        val overflowed = structured.overflowed || lines.overflowed || exactSecretsRedacted.overflowed ||
            sanitizedBytes.size > maxOutputBytes
        val boundedBytes = if (!forceRedactedOutput && !overflowed) {
            sanitizedBytes
        } else {
            "$CLIENT_LOGS_REDACTED_LINE\n".toByteArray(Charsets.UTF_8)
        }
        val nextState = if (trailingPartialRecord &&
            structured.state.blockEndMarker.isEmpty() &&
            structured.state.secretMode.isEmpty()
        ) {
            RemoteLogSanitizerState(secretMode = CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED)
        } else {
            structured.state
        }
        return RemoteLogSanitizedPayload(boundedBytes, nextState)
    }

    private fun sanitizeRemoteLogStructuredText(
        source: String,
        initialState: RemoteLogSanitizerState,
        budget: RemoteLogSanitizerBudget,
        maxOutputBytes: Int
    ): RemoteLogStructuredText {
        val sanitized = RemoteLogBoundedTextBuilder(maxOutputBytes)
        var blockEndMarker = initialState.blockEndMarker
        var blockEndPrefixChars = initialState.blockEndPrefixChars
        var secretMode = initialState.secretMode
        var secretQuote = initialState.secretQuote
        var secretEscaped = initialState.secretEscaped
        var structuredClosers = initialState.structuredClosers
        var position = 0
        var cachedBlockMatch: MatchResult? = null
        var blockSearchExhausted = false
        var cachedKeyMatch: MatchResult? = null
        var keySearchExhausted = false

        fun nextSensitiveBlock(startOffset: Int): MatchResult? {
            cachedBlockMatch?.let { cached ->
                if (cached.range.first >= startOffset) return cached
            }
            if (blockSearchExhausted) return null
            return CLIENT_LOGS_SENSITIVE_BLOCK_BEGIN_PATTERN.find(source, startOffset).also { match ->
                cachedBlockMatch = match
                blockSearchExhausted = match == null
            }
        }

        fun consumeCachedBlockMatch() {
            cachedBlockMatch = null
            blockSearchExhausted = false
        }

        fun nextSensitiveKey(startOffset: Int): MatchResult? {
            cachedKeyMatch?.let { cached ->
                if (cached.range.first >= startOffset) return cached
                cachedKeyMatch = null
                keySearchExhausted = false
            }
            if (keySearchExhausted) return null
            return CLIENT_LOGS_SECRET_KEY_PATTERN.find(source, startOffset).also { match ->
                cachedKeyMatch = match
                keySearchExhausted = match == null
            }
        }

        fun consumeCachedKeyMatch() {
            cachedKeyMatch = null
            keySearchExhausted = false
        }

        while (position < source.length) {
            if (secretMode == CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED) {
                sanitized.append(CLIENT_LOGS_REDACTED_LINE)
                position = source.length
                break
            }

            if (blockEndMarker.isNotEmpty()) {
                sanitized.append(CLIENT_LOGS_REDACTED_LINE)
                val progress = consumeRemoteLogSensitiveBlock(
                    source,
                    position,
                    blockEndMarker,
                    blockEndPrefixChars
                )
                position = progress.first
                blockEndPrefixChars = progress.second
                if (progress.third) {
                    sanitized.append(blockEndMarker)
                    blockEndMarker = ""
                    blockEndPrefixChars = 0
                }
                continue
            }

            when (secretMode) {
                CLIENT_LOGS_SECRET_MODE_AWAIT_DELIMITER -> {
                    val whitespaceStart = position
                    var crossedLineBoundary = false
                    while (position < source.length && source[position].isWhitespace()) {
                        if (source[position] == '\n' || source[position] == '\r') crossedLineBoundary = true
                        position++
                    }
                    sanitized.append(source.substring(whitespaceStart, position))
                    if (position >= source.length) {
                        if (crossedLineBoundary) secretMode = CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED
                        break
                    }
                    if (crossedLineBoundary) {
                        secretMode = CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED
                        position = source.length
                    } else if (source[position] == ':' || source[position] == '=') {
                        sanitized.append(source[position++])
                        secretMode = CLIENT_LOGS_SECRET_MODE_AWAIT_VALUE
                    } else {
                        secretMode = CLIENT_LOGS_SECRET_MODE_BARE
                    }
                    continue
                }

                CLIENT_LOGS_SECRET_MODE_AWAIT_VALUE -> {
                    val whitespaceStart = position
                    var crossedLineBoundary = false
                    while (position < source.length && source[position].isWhitespace()) {
                        if (source[position] == '\n' || source[position] == '\r') crossedLineBoundary = true
                        position++
                    }
                    sanitized.append(source.substring(whitespaceStart, position))
                    if (position >= source.length) {
                        if (crossedLineBoundary) secretMode = CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED
                        break
                    }

                    val blockMatch = nextSensitiveBlock(position)
                        ?.takeIf { it.range.first == position }
                    if (blockMatch != null) {
                        sanitized.append(blockMatch.value)
                        blockEndMarker = remoteLogSensitiveBlockEndMarker(blockMatch)
                        blockEndPrefixChars = 0
                        secretMode = ""
                        position = blockMatch.range.last + 1
                        consumeCachedBlockMatch()
                        continue
                    }

                    when (source[position]) {
                        '"', '\'' -> {
                            secretQuote = source[position].toString()
                            secretEscaped = false
                            secretMode = CLIENT_LOGS_SECRET_MODE_QUOTED
                            sanitized.append(source[position++])
                        }

                        '[' -> {
                            structuredClosers = "]"
                            secretQuote = ""
                            secretEscaped = false
                            secretMode = CLIENT_LOGS_SECRET_MODE_STRUCTURED
                            position++
                        }

                        '{' -> {
                            structuredClosers = "}"
                            secretQuote = ""
                            secretEscaped = false
                            secretMode = CLIENT_LOGS_SECRET_MODE_STRUCTURED
                            position++
                        }

                        '|', '>' -> {
                            secretMode = CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED
                            position = source.length
                        }

                        else -> if (crossedLineBoundary) {
                            secretMode = CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED
                            position = source.length
                        } else {
                            secretMode = CLIENT_LOGS_SECRET_MODE_BARE
                        }
                    }
                    continue
                }

                CLIENT_LOGS_SECRET_MODE_QUOTED -> {
                    sanitized.append(CLIENT_LOGS_REDACTED)
                    val quote = secretQuote.singleOrNull()
                    if (quote == null) {
                        secretMode = CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED
                        continue
                    }
                    var closed = false
                    while (position < source.length) {
                        val character = source[position++]
                        if (secretEscaped) {
                            secretEscaped = false
                        } else if (character == '\\') {
                            secretEscaped = true
                        } else if (character == quote) {
                            sanitized.append(character)
                            secretMode = ""
                            secretQuote = ""
                            secretEscaped = false
                            closed = true
                            break
                        }
                    }
                    if (!closed) break
                    continue
                }

                CLIENT_LOGS_SECRET_MODE_BARE -> {
                    sanitized.append(CLIENT_LOGS_REDACTED)
                    while (position < source.length && !isRemoteLogBareValueDelimiter(source[position])) position++
                    if (position >= source.length) break
                    secretMode = ""
                    continue
                }

                CLIENT_LOGS_SECRET_MODE_STRUCTURED -> {
                    sanitized.append(CLIENT_LOGS_REDACTED)
                    val closers = StringBuilder(structuredClosers)
                    var closed = false
                    while (position < source.length) {
                        val character = source[position++]
                        val quote = secretQuote.singleOrNull()
                        if (quote != null) {
                            if (secretEscaped) {
                                secretEscaped = false
                            } else if (character == '\\') {
                                secretEscaped = true
                            } else if (character == quote) {
                                secretQuote = ""
                            }
                            continue
                        }

                        when (character) {
                            '"', '\'' -> secretQuote = character.toString()
                            '[' -> closers.append(']')
                            '{' -> closers.append('}')
                            else -> if (closers.isNotEmpty() && character == closers.last()) {
                                closers.setLength(closers.length - 1)
                                if (closers.isEmpty()) {
                                    secretMode = ""
                                    secretQuote = ""
                                    secretEscaped = false
                                    closed = true
                                    break
                                }
                            }
                        }
                        if (closers.length > CLIENT_LOGS_MAX_SECRET_NESTING) {
                            secretMode = CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED
                            closers.clear()
                            position = source.length
                            break
                        }
                    }
                    structuredClosers = closers.toString()
                    if (!closed) break
                    continue
                }
            }

            val blockMatch = nextSensitiveBlock(position)
            val keyMatch = nextSensitiveKey(position)
            val nextIsBlock = blockMatch != null && (keyMatch == null || blockMatch.range.first <= keyMatch.range.first)
            val nextMatch = if (nextIsBlock) blockMatch else keyMatch
            if (nextMatch == null) {
                sanitized.append(source.substring(position))
                position = source.length
                break
            }

            sanitized.append(source.substring(position, nextMatch.range.first))
            sanitized.append(nextMatch.value)
            position = nextMatch.range.last + 1
            if (nextIsBlock) {
                blockEndMarker = remoteLogSensitiveBlockEndMarker(nextMatch)
                blockEndPrefixChars = 0
                consumeRemoteLogSanitizerBudget(budget)
                consumeCachedBlockMatch()
                if (budget.detailedRedactions <= 0) {
                    secretMode = CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED
                    position = source.length
                }
                continue
            }

            consumeCachedKeyMatch()
            val whitespaceStart = position
            var crossedLineBoundary = false
            while (position < source.length && source[position].isWhitespace()) {
                if (source[position] == '\n' || source[position] == '\r') crossedLineBoundary = true
                position++
            }
            if (position >= source.length) {
                sanitized.append(source.substring(whitespaceStart, position))
                secretMode = if (crossedLineBoundary) {
                    CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED
                } else {
                    CLIENT_LOGS_SECRET_MODE_AWAIT_DELIMITER
                }
                break
            }
            if (crossedLineBoundary) {
                secretMode = CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED
                position = source.length
            } else if (source[position] == ':' || source[position] == '=') {
                sanitized.append(source.substring(whitespaceStart, position + 1))
                position++
                secretMode = CLIENT_LOGS_SECRET_MODE_AWAIT_VALUE
                consumeRemoteLogSanitizerBudget(budget)
                if (budget.detailedRedactions <= 0) {
                    secretMode = CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED
                    position = source.length
                }
            } else {
                position = whitespaceStart
                secretMode = CLIENT_LOGS_SECRET_MODE_BARE
            }
        }

        val state = RemoteLogSanitizerState(
            blockEndMarker = blockEndMarker,
            blockEndPrefixChars = blockEndPrefixChars,
            secretMode = secretMode,
            secretQuote = secretQuote,
            secretEscaped = secretEscaped,
            structuredClosers = structuredClosers
        )
        return RemoteLogStructuredText(
            text = sanitized.toString(),
            state = if (isValidRemoteLogSanitizerState(state)) {
                state
            } else {
                RemoteLogSanitizerState(secretMode = CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED)
            },
            overflowed = sanitized.overflowed
        )
    }

    private fun sanitizeRemoteLogLines(
        source: String,
        budget: RemoteLogSanitizerBudget,
        redactTrailingPartialRecord: Boolean,
        maxOutputBytes: Int
    ): RemoteLogBoundedText {
        val sanitized = RemoteLogBoundedTextBuilder(maxOutputBytes)
        var lineStart = 0
        while (lineStart < source.length) {
            val newlineIndex = source.indexOf('\n', lineStart)
            val lineEnd = if (newlineIndex >= 0) newlineIndex else source.length
            if (redactTrailingPartialRecord && newlineIndex < 0) {
                sanitized.append(CLIENT_LOGS_REDACTED_LINE)
            } else {
                sanitized.append(sanitizeRemoteLogLine(source.substring(lineStart, lineEnd), budget))
            }
            if (newlineIndex < 0) break
            sanitized.append('\n')
            lineStart = newlineIndex + 1
        }
        return RemoteLogBoundedText(sanitized.toString(), sanitized.overflowed)
    }

    private fun redactRemoteLogExplicitSecrets(
        source: String,
        explicitSecrets: List<String>,
        maxOutputBytes: Int
    ): RemoteLogBoundedText {
        val sanitized = RemoteLogBoundedTextBuilder(maxOutputBytes)
        var position = 0
        while (position < source.length) {
            var nextOffset = -1
            var nextSecret = ""
            explicitSecrets.forEach { secret ->
                val offset = source.indexOf(secret, position)
                if (offset >= 0 && (nextOffset < 0 || offset < nextOffset ||
                        (offset == nextOffset && secret.length > nextSecret.length))
                ) {
                    nextOffset = offset
                    nextSecret = secret
                }
            }
            if (nextOffset < 0) {
                sanitized.append(source, position, source.length)
                break
            }
            sanitized.append(source, position, nextOffset)
            sanitized.append(CLIENT_LOGS_REDACTED)
            position = nextOffset + nextSecret.length
        }
        return RemoteLogBoundedText(sanitized.toString(), sanitized.overflowed)
    }

    private fun sanitizeRemoteLogLine(line: String, budget: RemoteLogSanitizerBudget): String {
        val containsSensitiveValue = CLIENT_LOGS_AUTHORIZATION_PATTERN.containsMatchIn(line) ||
            CLIENT_LOGS_COOKIE_PATTERN.containsMatchIn(line) ||
            CLIENT_LOGS_BEARER_PATTERN.containsMatchIn(line) ||
            CLIENT_LOGS_URL_USER_INFO_PATTERN.containsMatchIn(line) ||
            CLIENT_LOGS_URL_QUERY_SECRET_PATTERN.containsMatchIn(line) ||
            CLIENT_LOGS_COMMAND_LINE_SECRET_PATTERN.containsMatchIn(line)
        if (!containsSensitiveValue) return line
        if (line.length > CLIENT_LOGS_SANITIZER_MAX_LINE_CHARS || budget.detailedRedactions <= 0) {
            consumeRemoteLogSanitizerBudget(budget)
            return CLIENT_LOGS_REDACTED_LINE
        }

        var result = CLIENT_LOGS_AUTHORIZATION_PATTERN.replace(line) { match ->
            consumeRemoteLogSanitizerBudget(budget)
            match.groupValues[1] + CLIENT_LOGS_REDACTED
        }
        result = CLIENT_LOGS_COOKIE_PATTERN.replace(result) { match ->
            consumeRemoteLogSanitizerBudget(budget)
            match.groupValues[1] + CLIENT_LOGS_REDACTED
        }
        result = CLIENT_LOGS_URL_USER_INFO_PATTERN.replace(result) { match ->
            consumeRemoteLogSanitizerBudget(budget)
            match.groupValues[1] + CLIENT_LOGS_REDACTED + "@"
        }
        result = CLIENT_LOGS_URL_QUERY_SECRET_PATTERN.replace(result) { match ->
            consumeRemoteLogSanitizerBudget(budget)
            match.groupValues[1] + CLIENT_LOGS_REDACTED
        }
        result = CLIENT_LOGS_COMMAND_LINE_SECRET_PATTERN.replace(result) { match ->
            consumeRemoteLogSanitizerBudget(budget)
            match.groupValues[1] + CLIENT_LOGS_REDACTED
        }
        return CLIENT_LOGS_BEARER_PATTERN.replace(result) { match ->
            consumeRemoteLogSanitizerBudget(budget)
            match.groupValues[1] + CLIENT_LOGS_REDACTED
        }
    }

    private fun consumeRemoteLogSanitizerBudget(budget: RemoteLogSanitizerBudget) {
        if (budget.detailedRedactions > 0) budget.detailedRedactions--
    }

    private fun isRemoteLogBareValueDelimiter(character: Char): Boolean =
        character == '\n' || character == '\r'

    private fun remoteLogSensitiveBlockEndMarker(match: MatchResult): String {
        val pemLabel = match.groupValues[1]
        return if (pemLabel.isNotEmpty()) {
            "-----END $pemLabel-----"
        } else {
            "</${match.groupValues[2]}>"
        }
    }

    private fun consumeRemoteLogSensitiveBlock(
        source: String,
        startOffset: Int,
        endMarker: String,
        initialPrefixChars: Int
    ): Triple<Int, Int, Boolean> {
        val marker = endMarker.uppercase(Locale.US)
        if (marker.isEmpty() || initialPrefixChars !in 0 until marker.length) {
            return Triple(source.length, 0, false)
        }
        val prefixTable = IntArray(marker.length)
        var prefixLength = 0
        for (index in 1 until marker.length) {
            while (prefixLength > 0 && marker[index] != marker[prefixLength]) {
                prefixLength = prefixTable[prefixLength - 1]
            }
            if (marker[index] == marker[prefixLength]) prefixLength++
            prefixTable[index] = prefixLength
        }

        var matched = initialPrefixChars
        var position = startOffset
        while (position < source.length) {
            val character = source[position].uppercaseChar()
            while (matched > 0 && character != marker[matched]) {
                matched = prefixTable[matched - 1]
            }
            if (character == marker[matched]) matched++
            position++
            if (matched == marker.length) return Triple(position, 0, true)
        }
        return Triple(position, matched, false)
    }

    private fun isValidRemoteLogSanitizerState(state: RemoteLogSanitizerState): Boolean {
        if (state.secretMode !in CLIENT_LOGS_SECRET_MODES) return false
        if (state.blockEndMarker.length > CLIENT_LOGS_MAX_BLOCK_END_MARKER_CHARS) return false
        if (state.blockEndMarker.isNotEmpty() && !CLIENT_LOGS_SAFE_BLOCK_END_PATTERN.matches(state.blockEndMarker)) {
            return false
        }
        if (state.blockEndMarker.isEmpty() && state.blockEndPrefixChars != 0) return false
        if (state.blockEndMarker.isNotEmpty() && state.blockEndPrefixChars !in 0 until state.blockEndMarker.length) {
            return false
        }
        if (state.blockEndMarker.isNotEmpty() && state.secretMode.isNotEmpty()) return false
        if (state.structuredClosers.length > CLIENT_LOGS_MAX_SECRET_NESTING ||
            state.structuredClosers.any { it != ']' && it != '}' }
        ) {
            return false
        }

        return when (state.secretMode) {
            CLIENT_LOGS_SECRET_MODE_QUOTED ->
                state.secretQuote in setOf("\"", "'") && state.structuredClosers.isEmpty()
            CLIENT_LOGS_SECRET_MODE_STRUCTURED ->
                state.structuredClosers.isNotEmpty() &&
                    state.secretQuote in setOf("", "\"", "'") &&
                    (state.secretQuote.isNotEmpty() || !state.secretEscaped)
            CLIENT_LOGS_SECRET_MODE_AWAIT_DELIMITER,
            CLIENT_LOGS_SECRET_MODE_AWAIT_VALUE,
            CLIENT_LOGS_SECRET_MODE_BARE,
            CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED,
            "" -> state.secretQuote.isEmpty() && !state.secretEscaped && state.structuredClosers.isEmpty()
            else -> false
        }
    }

    private fun verifyRemoteLogSanitizerContract(): Boolean {
        val explicitSecret = "contract-explicit-log-token-9071"
        val installationId = "123e4567-e89b-12d3-a456-426614174000"
        val source = """
            route add 10.0.0.0/8 via 192.0.2.1
            dns vpn.example.test 203.0.113.8
            Authorization: Bearer contractAuthorization.12345
            GET /health?token=contract-query-token-123&password=contract-password-456
            {"bootstrapToken":"contract-bootstrap-token-789","host":"vpn.example.test"}
            X-Amnezia-Log-Token: contract-amnezia-log-token-321
            Bearer contractStandalone.654321
            Cookie: session=contract-cookie-secret-111
            INFO Authorization: Bearer contract-prefixed-authorization-112
            DEBUG Cookie: sid=contract-cookie-one-113; csrf=contract-prefixed-cookie-114
            proxy=https://contract-user:contract-url-password@vpn.example.test/path
            server_priv_key=contract-server-private-key-222
            client_priv_key=contract-client-private-key-333
            psk_key=contract-preshared-key-444
            mtproxy_secret=contract-mtproxy-secret-555
            telemt_secret=contract-telemt-secret-666
            aes_key=contract-aes-key-777
            vpn_key=contract-vpn-key-888
            tls_auth=contract-tls-auth-key-999
            xhttp_session_key=contract-xhttp-key-101
            xpadding_key=contract-xpadding-key-202
            "pass": "contract-xray-pass-303"
            secret_key=contract-secret-key-304
            proxy_secret=contract-proxy-secret-305
            wg_private_key=contract-wg-private-key-306
            --password=contract-cli-password-307
            certPrivKey=contract-cert-private-key-308
            privateKeyHex=contract-private-key-hex-309
            serverPskKey=contract-server-psk-key-310
            secretData=contract-secret-data-311
            dynamicChallengeCookie=contract-dynamic-cookie-312
            "mtproxy_additional_secrets": [
              "contract-array-secret-404",
              "contract-array-secret-505"
            ]
            "password"
            :
            "contract-pretty-password-606"
            opaque=$explicitSecret
            installationId=$installationId
            -----BEGIN PRIVATE KEY-----
            contract-pem-body-secret-777
            -----END PRIVATE KEY-----
        """.trimIndent().toByteArray(Charsets.UTF_8)
        val exactSecrets = listOf(explicitSecret, installationId)
        val first = sanitizeRemoteLogPayload(source, exactSecrets)
        val second = sanitizeRemoteLogPayload(source, exactSecrets)
        val text = first.data.toString(Charsets.UTF_8)
        val forbidden = listOf(
            "contractAuthorization.12345",
            "contract-query-token-123",
            "contract-password-456",
            "contract-bootstrap-token-789",
            "contract-amnezia-log-token-321",
            "contractStandalone.654321",
            "contract-cookie-secret-111",
            "contract-prefixed-authorization-112",
            "contract-cookie-one-113",
            "contract-prefixed-cookie-114",
            "contract-user",
            "contract-url-password",
            "contract-server-private-key-222",
            "contract-client-private-key-333",
            "contract-preshared-key-444",
            "contract-mtproxy-secret-555",
            "contract-telemt-secret-666",
            "contract-aes-key-777",
            "contract-vpn-key-888",
            "contract-tls-auth-key-999",
            "contract-xhttp-key-101",
            "contract-xpadding-key-202",
            "contract-xray-pass-303",
            "contract-secret-key-304",
            "contract-proxy-secret-305",
            "contract-wg-private-key-306",
            "contract-cli-password-307",
            "contract-cert-private-key-308",
            "contract-private-key-hex-309",
            "contract-server-psk-key-310",
            "contract-secret-data-311",
            "contract-dynamic-cookie-312",
            "contract-array-secret-404",
            "contract-array-secret-505",
            "contract-pretty-password-606",
            explicitSecret,
            installationId,
            "contract-pem-body-secret-777"
        )
        val required = listOf(
            "route add 10.0.0.0/8 via 192.0.2.1",
            "dns vpn.example.test 203.0.113.8",
            "vpn.example.test",
            CLIENT_LOGS_REDACTED
        )
        val firstPem = sanitizeRemoteLogPayload(
            "-----BEGIN PRIVATE KEY-----\ncontract-cross-payload-pem-707".toByteArray(Charsets.UTF_8)
        )
        val secondPem = sanitizeRemoteLogPayload(
            "contract-cross-payload-pem-808\n-----END PRIVATE KEY-----\nhealth=healthy\n"
                .toByteArray(Charsets.UTF_8),
            initialState = firstPem.state
        )
        val firstStaticKey = sanitizeRemoteLogPayload(
            "-----BEGIN OpenVPN Static key V1-----\ncontract-static-key-909".toByteArray(Charsets.UTF_8)
        )
        val secondStaticKey = sanitizeRemoteLogPayload(
            "contract-static-key-010\n-----END OpenVPN Static key V1-----\nroute=preserved\n"
                .toByteArray(Charsets.UTF_8),
            initialState = firstStaticKey.state
        )
        val firstArray = sanitizeRemoteLogPayload(
            "telemt_additional_secrets=[\n\"contract-cross-array-111\",".toByteArray(Charsets.UTF_8)
        )
        val secondArray = sanitizeRemoteLogPayload(
            "\"contract-cross-array-222\"\n]\ndns=preserved\n".toByteArray(Charsets.UTF_8),
            initialState = firstArray.state
        )
        val splitBeginFirst = sanitizeRemoteLogPayload(
            "INFO -----BEGIN OpenVPN Sta".toByteArray(Charsets.UTF_8)
        )
        val splitBeginSecond = sanitizeRemoteLogPayload(
            "tic key V1-----\ncontract-split-begin-secret-333\n-----END OpenVPN Static key V1-----\n"
                .toByteArray(Charsets.UTF_8),
            initialState = splitBeginFirst.state
        )
        val yamlSecret = sanitizeRemoteLogPayload(
            "password: |\n  contract-yaml-secret-334\n".toByteArray(Charsets.UTF_8)
        )
        val changedSecretSet = sanitizeRemoteLogPayload(
            "opaque-old-token-335\nroute=hidden-on-secret-set-change\n".toByteArray(Charsets.UTF_8),
            explicitSecrets = listOf("different-current-token-336"),
            forceRedactedOutput = true
        )
        val multilineScalar = sanitizeRemoteLogPayload(
            "password:\n  contract-multiline-first-337\n  contract-multiline-second-338\n"
                .toByteArray(Charsets.UTF_8)
        )
        val multilineKeyWithoutDelimiter = sanitizeRemoteLogPayload(
            "password\n  contract-multiline-third-339\n".toByteArray(Charsets.UTF_8)
        )
        val delimiterOnNextLine = sanitizeRemoteLogPayload(
            "password\n: contract-delimiter-first-339a\ncontract-delimiter-second-339b\n"
                .toByteArray(Charsets.UTF_8)
        )
        val splitMultilineFirst = sanitizeRemoteLogPayload(
            "password:\n  ".toByteArray(Charsets.UTF_8)
        )
        val splitMultilineSecond = sanitizeRemoteLogPayload(
            "contract-multiline-fourth-340\n".toByteArray(Charsets.UTF_8),
            initialState = splitMultilineFirst.state
        )
        val boundedOverflow = sanitizeRemoteLogPayload(
            ("route=" + "Ж".repeat(80) + "\n").toByteArray(Charsets.UTF_8),
            maxOutputBytes = 64
        )
        val repeatedBlocks = sanitizeRemoteLogPayload(
            (buildString {
                repeat(32) {
                    append("-----BEGIN PRIVATE KEY-----\ncontract-repeated-block-$it\n-----END PRIVATE KEY-----\n")
                }
                append("password=contract-after-repeated-blocks-341\n")
            }).toByteArray(Charsets.UTF_8)
        )
        val originNonce = "123e4567-e89b-12d3-a456-426614174001"
        val originPrefix =
            "07-21 12:34:56.789Z 1 2 I [main] $TAG: $CLIENT_LOGS_ORIGIN_MARKER $originNonce\n"
        val originLog = (originPrefix + "route ok\n").toByteArray(Charsets.UTF_8)
        val cappedRetryLow = remoteLogRetryDelayMs(31, -CLIENT_LOGS_RETRY_JITTER_PERMILLE)
        val cappedRetryMid = remoteLogRetryDelayMs(31, 0)
        val cappedRetryHigh = remoteLogRetryDelayMs(31, CLIENT_LOGS_RETRY_JITTER_PERMILLE)
        val crossPayloadText = firstPem.data.toString(Charsets.UTF_8) +
            firstStaticKey.data.toString(Charsets.UTF_8) +
            firstArray.data.toString(Charsets.UTF_8) +
            secondPem.data.toString(Charsets.UTF_8) +
            secondStaticKey.data.toString(Charsets.UTF_8) +
            secondArray.data.toString(Charsets.UTF_8)
        return first.data.contentEquals(second.data) &&
            first.state == second.state &&
            first.data.size <= CLIENT_LOGS_MAX_PAYLOAD_BYTES &&
            forbidden.none { text.contains(it) } &&
            required.all { text.contains(it) } &&
            firstPem.state.blockEndMarker.isNotEmpty() &&
            firstStaticKey.state.blockEndMarker.isNotEmpty() &&
            firstArray.state.secretMode == CLIENT_LOGS_SECRET_MODE_STRUCTURED &&
            listOf(
                "contract-cross-payload-pem-808",
                "contract-static-key-010",
                "contract-cross-array-222",
                "contract-cross-payload-pem-707",
                "contract-static-key-909",
                "contract-cross-array-111"
            ).none { crossPayloadText.contains(it) } &&
            secondPem.state == RemoteLogSanitizerState() &&
            secondStaticKey.state == RemoteLogSanitizerState() &&
            secondArray.state == RemoteLogSanitizerState() &&
            splitBeginFirst.state.secretMode == CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED &&
            !splitBeginSecond.data.toString(Charsets.UTF_8).contains("contract-split-begin-secret-333") &&
            splitBeginSecond.state.secretMode == CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED &&
            yamlSecret.state.secretMode == CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED &&
            !yamlSecret.data.toString(Charsets.UTF_8).contains("contract-yaml-secret-334") &&
            !changedSecretSet.data.toString(Charsets.UTF_8).contains("opaque-old-token-335") &&
            multilineScalar.state.secretMode == CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED &&
            listOf("contract-multiline-first-337", "contract-multiline-second-338")
                .none { multilineScalar.data.toString(Charsets.UTF_8).contains(it) } &&
            multilineKeyWithoutDelimiter.state.secretMode == CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED &&
            !multilineKeyWithoutDelimiter.data.toString(Charsets.UTF_8).contains("contract-multiline-third-339") &&
            delimiterOnNextLine.state.secretMode == CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED &&
            listOf("contract-delimiter-first-339a", "contract-delimiter-second-339b")
                .none { delimiterOnNextLine.data.toString(Charsets.UTF_8).contains(it) } &&
            splitMultilineFirst.state.secretMode == CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED &&
            splitMultilineSecond.state.secretMode == CLIENT_LOGS_SECRET_MODE_FAIL_CLOSED &&
            !splitMultilineSecond.data.toString(Charsets.UTF_8).contains("contract-multiline-fourth-340") &&
            boundedOverflow.data.contentEquals("$CLIENT_LOGS_REDACTED_LINE\n".toByteArray(Charsets.UTF_8)) &&
            !repeatedBlocks.data.toString(Charsets.UTF_8).contains("contract-after-repeated-blocks-341") &&
            remoteLogOriginCheckpointOffset(originLog, originNonce) ==
                originPrefix.toByteArray(Charsets.UTF_8).size &&
            remoteLogOriginCheckpointOffset(
                ("untrusted $TAG: $CLIENT_LOGS_ORIGIN_MARKER $originNonce\n").toByteArray(Charsets.UTF_8),
                originNonce
            ) == null &&
            remoteLogOriginCheckpointOffset(
                "07-21 12:34:56.789Z 1 2 I [main] Contract: private-key-body\n"
                    .toByteArray(Charsets.UTF_8),
                originNonce
            ) == null &&
            !isValidRemoteLogToken("1234567") &&
            isValidRemoteLogToken("12345678") &&
            isValidRemoteLogToken("x".repeat(CLIENT_LOGS_MAX_TOKEN_CHARS)) &&
            !isValidRemoteLogToken("x".repeat(CLIENT_LOGS_MAX_TOKEN_CHARS + 1)) &&
            !isValidRemoteLogToken("token with space") &&
            !isValidRemoteLogToken("токен-не-ascii") &&
            !isValidRemoteLogToken("token\u0000value") &&
            isRemoteLogUploadAcknowledged(204, "1", "contract-batch-id", "contract-batch-id") &&
            !isRemoteLogUploadAcknowledged(204, null, "contract-batch-id", "contract-batch-id") &&
            !isRemoteLogUploadAcknowledged(204, "1", "wrong-batch-id", "contract-batch-id") &&
            !isRemoteLogUploadAcknowledged(500, "1", "contract-batch-id", "contract-batch-id") &&
            remoteLogRetryDelayMs(1, 0) == CLIENT_LOGS_RETRY_BASE_DELAY &&
            remoteLogRetryDelayMs(2, 0) ==
                minOf(CLIENT_LOGS_RETRY_BASE_DELAY * 2, CLIENT_LOGS_RETRY_MAX_DELAY) &&
            cappedRetryMid - cappedRetryLow == cappedRetryHigh - cappedRetryMid &&
            cappedRetryHigh <= CLIENT_LOGS_RETRY_MAX_DELAY &&
            remoteLogRetryDelayMs(1, -CLIENT_LOGS_RETRY_JITTER_PERMILLE) <
                CLIENT_LOGS_RETRY_BASE_DELAY &&
            remoteLogRetryDelayMs(1, CLIENT_LOGS_RETRY_JITTER_PERMILLE) >
                CLIENT_LOGS_RETRY_BASE_DELAY &&
            remoteLogRetryAfterMs("2", 0L) == 2000L &&
            remoteLogRetryAfterMs("999999", 0L) == CLIENT_LOGS_RETRY_MAX_DELAY &&
            remoteLogRetryAfterMs("invalid", 0L) == null &&
            crossPayloadText.contains("health=healthy") &&
            crossPayloadText.contains("route=preserved") &&
            crossPayloadText.contains("dns=preserved")
    }

    private fun isRemoteLogUploadAcknowledged(
        statusCode: Int,
        acceptedHeader: String?,
        echoedBatchId: String?,
        expectedBatchId: String
    ): Boolean = statusCode in 200..299 &&
        acceptedHeader == "1" &&
        expectedBatchId.isNotEmpty() &&
        echoedBatchId == expectedBatchId

    private fun remoteLogRetryDelayMs(failureCount: Int, jitterPermille: Int): Long {
        val maxBaseDelay = CLIENT_LOGS_RETRY_MAX_DELAY * 1000 /
            (1000 + CLIENT_LOGS_RETRY_JITTER_PERMILLE)
        var baseDelay = CLIENT_LOGS_RETRY_BASE_DELAY
        repeat((failureCount.coerceAtLeast(1) - 1).coerceAtMost(30)) {
            baseDelay = minOf(maxBaseDelay, baseDelay * 2)
        }
        val boundedJitter = jitterPermille.coerceIn(
            -CLIENT_LOGS_RETRY_JITTER_PERMILLE,
            CLIENT_LOGS_RETRY_JITTER_PERMILLE
        )
        return (baseDelay + baseDelay * boundedJitter / 1000)
            .coerceIn(1L, CLIENT_LOGS_RETRY_MAX_DELAY)
    }

    private fun remoteLogRetryAfterMs(value: String?, nowMs: Long = System.currentTimeMillis()): Long? {
        val retryAfter = value?.trim()?.takeIf { it.isNotEmpty() && it.length <= 128 } ?: return null
        retryAfter.toLongOrNull()?.let { seconds ->
            if (seconds < 0) return null
            return (seconds.coerceAtMost(CLIENT_LOGS_RETRY_MAX_DELAY / 1000) * 1000)
                .coerceAtLeast(1000L)
        }
        return try {
            val formatter = SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US).apply {
                isLenient = false
                timeZone = TimeZone.getTimeZone("GMT")
            }
            val retryAt = formatter.parse(retryAfter)?.time ?: return null
            (retryAt - nowMs).coerceIn(1000L, CLIENT_LOGS_RETRY_MAX_DELAY)
        } catch (_: Exception) {
            null
        }
    }

    private fun remoteLogBatchId(
        target: RemoteLogTarget,
        kind: String,
        fingerprint: String,
        offset: Int,
        length: Int
    ): String {
        val canonical = buildString {
            append(remoteLogTargetIdentity(target))
            append('\u0000')
            append(kind)
            append('\u0000')
            append(fingerprint)
            append('\u0000')
            append(offset)
            append('\u0000')
            append(length)
        }
        return sha256Hex(canonical)
    }

    private fun remoteLogTargetIdentity(target: RemoteLogTarget): String {
        val canonical = buildString {
            append("amnezia-remote-log-target-v1")
            append('\u0000')
            append(target.tokenCacheKey)
            append('\u0000')
            append(target.endpoint)
            append('\u0000')
            append(target.clientId)
            append('\u0000')
            append(remoteLogInstallationId().lowercase(Locale.US))
        }
        return sha256Hex(canonical)
    }

    private fun remoteLogCursorPrefsKey(targetId: String): String =
        PREFS_REMOTE_LOG_CURSOR_PREFIX + targetId

    private fun loadRemoteLogCursor(target: RemoteLogTarget): RemoteLogCursor {
        return try {
            val targetId = remoteLogTargetIdentity(target)
            val encoded = Prefs.load<String>(remoteLogCursorPrefsKey(targetId))
            if (encoded.isBlank() || encoded.length > 2048) return RemoteLogCursor()
            val value = JSONObject(encoded)
            if (value.optInt("schema") != CLIENT_LOGS_CURSOR_SCHEMA) return RemoteLogCursor()

            val offsetLong = value.optLong("offset", -1L)
            val fingerprint = value.optString("fingerprint")
            val fingerprintBytes = value.optInt("fingerprintBytes", -1)
            val anchor = value.optString("anchor")
            val pendingEndOffsetLong = value.optLong("pendingEndOffset", 0L)
            val pendingBodySha256 = value.optString("pendingBodySha256")
            val pendingBatchId = value.optString("pendingBatchId")
            val sanitizerExplicitSecretsSha256 = value.optString("sanitizerExplicitSecretsSha256")
            val sanitizerState = RemoteLogSanitizerState(
                blockEndMarker = value.optString("sanitizerBlockEndMarker"),
                blockEndPrefixChars = value.optInt("sanitizerBlockEndPrefixChars", 0),
                secretMode = value.optString("sanitizerSecretMode"),
                secretQuote = value.optString("sanitizerSecretQuote"),
                secretEscaped = value.optBoolean("sanitizerSecretEscaped", false),
                structuredClosers = value.optString("sanitizerStructuredClosers")
            )
            val offsetIsValid = offsetLong in 0..Int.MAX_VALUE.toLong()
            val pendingOffsetIsValid = pendingEndOffsetLong in 0..Int.MAX_VALUE.toLong()
            val offset = offsetLong.coerceIn(0, Int.MAX_VALUE.toLong()).toInt()
            val pendingEndOffset = pendingEndOffsetLong.coerceIn(0, Int.MAX_VALUE.toLong()).toInt()
            val fingerprintIsValid = fingerprintBytes in 1..CLIENT_LOGS_CURSOR_FINGERPRINT_BYTES &&
                SHA256_HEX_PATTERN.matches(fingerprint)
            val anchorIsValid = (offset == 0 && anchor.isEmpty()) ||
                (offset > 0 && SHA256_HEX_PATTERN.matches(anchor))
            val pendingIsValid = if (pendingEndOffset == 0) {
                pendingBodySha256.isEmpty() && pendingBatchId.isEmpty()
            } else {
                offsetIsValid && pendingOffsetIsValid && pendingEndOffsetLong > offsetLong &&
                    pendingEndOffsetLong - offsetLong in 1..CLIENT_LOGS_MAX_BATCH_RAW_BYTES.toLong() &&
                    SHA256_HEX_PATTERN.matches(pendingBodySha256) &&
                    SHA256_HEX_PATTERN.matches(pendingBatchId)
            }
            if (!offsetIsValid || !pendingOffsetIsValid || !fingerprintIsValid || !anchorIsValid || !pendingIsValid ||
                !SHA256_HEX_PATTERN.matches(sanitizerExplicitSecretsSha256) ||
                !isValidRemoteLogSanitizerState(sanitizerState)
            ) {
                RemoteLogCursor()
            } else {
                RemoteLogCursor(
                    offset = offset,
                    fingerprint = fingerprint,
                    fingerprintBytes = fingerprintBytes,
                    anchor = anchor,
                    pendingEndOffset = pendingEndOffset,
                    pendingBodySha256 = pendingBodySha256,
                    pendingBatchId = pendingBatchId,
                    sanitizerBlockEndMarker = sanitizerState.blockEndMarker,
                    sanitizerBlockEndPrefixChars = sanitizerState.blockEndPrefixChars,
                    sanitizerSecretMode = sanitizerState.secretMode,
                    sanitizerSecretQuote = sanitizerState.secretQuote,
                    sanitizerSecretEscaped = sanitizerState.secretEscaped,
                    sanitizerStructuredClosers = sanitizerState.structuredClosers,
                    sanitizerExplicitSecretsSha256 = sanitizerExplicitSecretsSha256
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "Ignoring invalid remote log cursor: ${e.javaClass.simpleName}")
            RemoteLogCursor()
        }
    }

    private fun saveRemoteLogCursorForAttempt(
        attempt: RemoteLogAttempt,
        cursor: RemoteLogCursor
    ): Boolean = synchronized(remoteLogTargetLock) {
        if (remoteLogTarget != attempt.target || remoteLogTargetGeneration != attempt.generation ||
            protocolState.value != CONNECTED
        ) {
            false
        } else {
            saveRemoteLogCursor(attempt.target, cursor)
        }
    }

    private fun saveRemoteLogCursor(target: RemoteLogTarget, cursor: RemoteLogCursor): Boolean {
        return try {
            val targetId = remoteLogTargetIdentity(target)
            val key = remoteLogCursorPrefsKey(targetId)
            val value = JSONObject().apply {
                put("schema", CLIENT_LOGS_CURSOR_SCHEMA)
                put("offset", cursor.offset)
                put("fingerprint", cursor.fingerprint)
                put("fingerprintBytes", cursor.fingerprintBytes)
                put("anchor", cursor.anchor)
                put("pendingEndOffset", cursor.pendingEndOffset)
                put("pendingBodySha256", cursor.pendingBodySha256)
                put("pendingBatchId", cursor.pendingBatchId)
                put("sanitizerBlockEndMarker", cursor.sanitizerBlockEndMarker)
                put("sanitizerBlockEndPrefixChars", cursor.sanitizerBlockEndPrefixChars)
                put("sanitizerSecretMode", cursor.sanitizerSecretMode)
                put("sanitizerSecretQuote", cursor.sanitizerSecretQuote)
                put("sanitizerSecretEscaped", cursor.sanitizerSecretEscaped)
                put("sanitizerStructuredClosers", cursor.sanitizerStructuredClosers)
                put("sanitizerExplicitSecretsSha256", cursor.sanitizerExplicitSecretsSha256)
            }.toString()

            val prefs = Prefs.prefs
            val indexedTargets = Prefs.load<String>(PREFS_REMOTE_LOG_CURSOR_INDEX)
                .split(',')
                .filter { SHA256_HEX_PATTERN.matches(it) }
            val storedTargets = prefs.all.keys
                .asSequence()
                .filter { it.startsWith(PREFS_REMOTE_LOG_CURSOR_PREFIX) }
                .map { it.removePrefix(PREFS_REMOTE_LOG_CURSOR_PREFIX) }
                .filter { SHA256_HEX_PATTERN.matches(it) }
                .toList()
            val targets = (storedTargets.filter { it !in indexedTargets } + indexedTargets)
                .distinct()
                .filter { it != targetId }
                .toMutableList()
                .apply { add(targetId) }
            val evictedTargets = ArrayList<String>()
            while (targets.size > CLIENT_LOGS_MAX_CURSOR_TARGETS) {
                evictedTargets.add(targets.removeAt(0))
            }

            val editor = prefs.edit()
                .putString(key, value)
                .putString(PREFS_REMOTE_LOG_CURSOR_INDEX, targets.joinToString(","))
            evictedTargets.forEach { editor.remove(remoteLogCursorPrefsKey(it)) }
            editor.commit()
        } catch (e: Exception) {
            Log.w(TAG, "Saving remote log cursor failed: ${e.javaClass.simpleName}")
            false
        }
    }

    private fun remoteLogAnchor(data: ByteArray, offset: Int): String {
        if (offset <= 0 || offset > data.size) return ""
        val anchorOffset = (offset - CLIENT_LOGS_CURSOR_ANCHOR_BYTES).coerceAtLeast(0)
        return sha256Hex(data.copyOfRange(anchorOffset, offset))
    }

    private fun readLimitedUtf8(stream: InputStream, maxBytes: Int): String? {
        val buffer = ByteArray(512)
        val data = ArrayList<Byte>(maxBytes.coerceAtMost(4096))
        stream.use { input ->
            while (true) {
                val remaining = maxBytes + 1 - data.size
                if (remaining <= 0) return null
                val read = input.read(buffer, 0, minOf(buffer.size, remaining))
                if (read < 0) break
                for (i in 0 until read) {
                    data.add(buffer[i])
                }
                if (data.size > maxBytes) return null
            }
        }
        return data.toByteArray().toString(Charsets.UTF_8)
    }

    private fun sha256Hex(value: String): String = sha256Hex(value.toByteArray(Charsets.UTF_8))

    private fun sha256Hex(value: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(value)
            .joinToString("") { "%02x".format(Locale.US, it.toInt() and 0xff) }

    /**
     * Utils methods
     */
    private fun onError(msg: String) {
        Log.e(TAG, msg)
        mainScope.launch {
            clientMessengers.send {
                ServiceEvent.ERROR.packToMessage {
                    putString(MSG_ERROR, msg)
                }
            }
        }
    }

    private fun parseConfigToJson(vpnConfig: String): JSONObject? =
        if (vpnConfig.isBlank()) {
            null
        } else {
            try {
                JSONObject(vpnConfig)
            } catch (e: JSONException) {
                onError("Invalid VPN config json format: ${e.message}")
                null
            }
        }

    private fun saveServerData(config: JSONObject?) {
        serverName = config?.opt("description") as String?
        serverIndex = config?.opt("serverIndex") as Int? ?: -1
        Log.d(TAG, "Save server data: ($serverIndex, $serverName)")
        Prefs.save(PREFS_SERVER_NAME, serverName)
        Prefs.save(PREFS_SERVER_INDEX, serverIndex)
    }

    private fun loadServerData() {
        serverName = Prefs.load<String>(PREFS_SERVER_NAME).ifBlank { null }
        if (serverName != null) serverIndex = Prefs.load(PREFS_SERVER_INDEX)
        Log.d(TAG, "Load server data: ($serverIndex, $serverName)")
    }

    private fun checkPermission(): Boolean =
        if (prepare(applicationContext) != null) {
            Intent(this, VpnRequestActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra(EXTRA_PROTOCOL, vpnProto)
            }.also {
                startActivity(it)
            }
            false
        } else {
            true
        }

    companion object {
        fun isRunning(context: Context, processName: String): Boolean =
            context.getSystemService<ActivityManager>()!!.runningAppProcesses.any {
                it.processName == processName && it.importance <= IMPORTANCE_FOREGROUND_SERVICE
            }
    }
}
