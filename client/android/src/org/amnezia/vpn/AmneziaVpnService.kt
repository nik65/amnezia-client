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
import java.net.UnknownHostException
import java.net.URL
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.LazyThreadSafetyMode.NONE
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
private const val CLIENT_LOGS_UPLOAD_TIMEOUT = 30000
private const val CLIENT_LOGS_MAX_PAYLOAD_BYTES = 15 * 1024 * 1024
private const val CLIENT_LOGS_MAX_BOOTSTRAP_RESPONSE_BYTES = 4096
private const val PREFS_REMOTE_LOG_INSTALLATION_ID = "REMOTE_LOG_INSTALLATION_ID"
private const val PREFS_REMOTE_LOG_TOKEN_PREFIX = "REMOTE_LOG_TOKEN_"

private data class RemoteLogTarget(
    val endpoint: String,
    val clientId: String,
    val token: String,
    val bootstrap: Boolean,
    val tokenCacheKey: String
)

@SuppressLint("Registered")
open class AmneziaVpnService : VpnService() {

    private lateinit var mainScope: CoroutineScope
    private lateinit var connectionScope: CoroutineScope
    private var isServiceBound = false
    private var vpnProto: VpnProto? = null
    private var protocolState = MutableStateFlow(UNKNOWN)
    private var serverName: String? = null
    private var serverIndex: Int = -1

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
    private var remoteLogTarget: RemoteLogTarget? = null
    private var remoteLogOffsetBytes = -1
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
        unregisterBroadcastReceivers()
        runBlocking {
            disconnect()
            disconnectionJob?.join()
        }
        remoteLogUploadJob?.cancel()
        remoteLogUploadJob = null
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
                        networkState.bindNetworkListener()
                        configureRemoteLogUploader(parseConfigToJson(Prefs.load(PREFS_CONFIG_KEY)))
                        // if (isActivityConnected) launchSendingStatistics()
                        launchTrafficStatsUpdate()
                    }

                    DISCONNECTED -> {
                        networkState.unbindNetworkListener()
                        stopRemoteLogUploader()
                        stopTrafficStatsUpdateJob()
                        // stopSendingStatistics()
                        if (!isServiceBound) stopService()
                    }

                    DISCONNECTING -> {
                        networkState.unbindNetworkListener()
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
            Prefs.save(PREFS_CONFIG_KEY, vpnConfig)
            connectToVpn(vpnConfig)
        }
    }

    @MainThread
    private fun connectToVpn(vpnConfig: String) {
        if (isConnected || protocolState.value == CONNECTING) return

        Log.d(TAG, "Start VPN connection")

        val config = parseConfigToJson(vpnConfig)
        saveServerData(config)
        if (config == null) {
            stopRemoteLogUploader()
            onError("Invalid VPN config")
            protocolState.value = DISCONNECTED
            return
        }

        try {
            vpnProto = VpnProto.get(config.getString("protocol"))
        } catch (e: Exception) {
            stopRemoteLogUploader()
            onError("Invalid VPN config: ${e.message}")
            protocolState.value = DISCONNECTED
            return
        }

        protocolState.value = CONNECTING

        if (!checkPermission()) {
            stopRemoteLogUploader()
            protocolState.value = DISCONNECTED
            return
        }

        configureRemoteLogUploader(config)

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
        val target = parseRemoteLogTarget(config)
        if (target == null) {
            stopRemoteLogUploader()
            return
        }
        if (remoteLogTarget != target) {
            remoteLogTarget = target
            remoteLogOffsetBytes = -1
        }
        if (remoteLogUploadJob == null) {
            remoteLogUploadJob = connectionScope.launch {
                delay(CLIENT_LOGS_INITIAL_UPLOAD_DELAY)
                while (true) {
                    uploadRemoteLogsOnce()
                    delay(CLIENT_LOGS_UPLOAD_INTERVAL)
                }
            }
        }
    }

    private fun stopRemoteLogUploader() {
        remoteLogTarget = null
        remoteLogOffsetBytes = -1
        remoteLogUploadJob?.cancel()
        remoteLogUploadJob = null
    }

    private fun parseRemoteLogTarget(config: JSONObject?): RemoteLogTarget? {
        val clientLogs = config?.optJSONObject(CLIENT_LOGS_KEY) ?: deriveLegacyRemoteLogTarget(config) ?: return null
        val endpoint = clientLogs.optString(CLIENT_LOGS_ENDPOINT_KEY)
        val clientId = clientLogs.optString(CLIENT_LOGS_CLIENT_ID_KEY)
        val bootstrap = clientLogs.optBoolean(CLIENT_LOGS_BOOTSTRAP_KEY, false)
        val configuredToken = clientLogs.optString(CLIENT_LOGS_TOKEN_KEY)
        val tokenCacheKey = remoteLogTokenPrefsKey(config?.optString("hostName").orEmpty(), clientId)
        val token = configuredToken.ifBlank {
            if (bootstrap) Prefs.loadSecureString(tokenCacheKey) else ""
        }
        if (endpoint != CLIENT_LOGS_TRUSTED_ENDPOINT || clientId.isBlank() || (!bootstrap && token.isBlank())) {
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

    private fun uploadRemoteLogsOnce(allowTokenRefreshRetry: Boolean = true) {
        var connection: HttpURLConnection? = null
        try {
            var target = remoteLogTarget ?: return
            if (protocolState.value != CONNECTED) return
            if (target.token.isBlank()) {
                target = bootstrapRemoteLogTarget(target) ?: return
                remoteLogTarget = target
            }
            if (remoteLogTarget != target || protocolState.value != CONNECTED) return

            val logBytes = Log.getAppLogs(CLIENT_LOGS_MAX_PAYLOAD_BYTES).toByteArray(Charsets.UTF_8)
            val startOffset = if (remoteLogOffsetBytes < 0 || remoteLogOffsetBytes > logBytes.size) {
                (logBytes.size - CLIENT_LOGS_MAX_PAYLOAD_BYTES).coerceAtLeast(0)
            } else {
                remoteLogOffsetBytes
            }
            if (startOffset >= logBytes.size) return

            val payload = logBytes.copyOfRange(startOffset, logBytes.size)
            if (payload.isEmpty()) return

            connection = (URL(target.endpoint).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = CLIENT_LOGS_UPLOAD_TIMEOUT
                readTimeout = CLIENT_LOGS_UPLOAD_TIMEOUT
                doOutput = true
                setRequestProperty("Content-Type", "text/plain; charset=utf-8")
                setRequestProperty("X-Amnezia-Client-Id", target.clientId)
                setRequestProperty("X-Amnezia-Log-Token", target.token)
                setRequestProperty("X-Amnezia-Log-Kind", "android")
                setRequestProperty("X-Amnezia-Installation-Id", remoteLogInstallationId())
                setFixedLengthStreamingMode(payload.size)
            }
            if (remoteLogTarget != target || protocolState.value != CONNECTED) return
            connection.outputStream.use { output -> output.write(payload) }
            val statusCode = connection.responseCode
            if (remoteLogTarget != target || protocolState.value != CONNECTED) return
            if (statusCode in 200..299) {
                remoteLogOffsetBytes = logBytes.size
            } else {
                if (statusCode == 403 && target.bootstrap && allowTokenRefreshRetry) {
                    Prefs.saveSecureString(target.tokenCacheKey, "")
                    remoteLogTarget = target.copy(token = "")
                    uploadRemoteLogsOnce(false)
                }
                Log.w(TAG, "Remote log upload failed: status=$statusCode endpoint=${target.endpoint} clientId=${target.clientId}")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Remote log upload failed: $e")
        } finally {
            connection?.disconnect()
        }
    }

    private fun bootstrapRemoteLogTarget(target: RemoteLogTarget): RemoteLogTarget? {
        if (!target.bootstrap || target.clientId.isBlank()) return null

        var connection: HttpURLConnection? = null
        return try {
            connection = (URL(CLIENT_LOGS_BOOTSTRAP_ENDPOINT).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = CLIENT_LOGS_UPLOAD_TIMEOUT
                readTimeout = CLIENT_LOGS_UPLOAD_TIMEOUT
                doOutput = true
                setRequestProperty("X-Amnezia-Client-Id", target.clientId)
                setRequestProperty("X-Amnezia-Installation-Id", remoteLogInstallationId())
                setFixedLengthStreamingMode(0)
            }
            connection.outputStream.use { }
            val statusCode = connection.responseCode
            if (statusCode !in 200..299) {
                Log.w(TAG, "Remote log bootstrap failed: status=$statusCode endpoint=$CLIENT_LOGS_BOOTSTRAP_ENDPOINT clientId=${target.clientId}")
                return null
            }
            val response = readLimitedUtf8(connection.inputStream, CLIENT_LOGS_MAX_BOOTSTRAP_RESPONSE_BYTES)
            if (response == null) {
                Log.w(TAG, "Remote log bootstrap response is too large")
                return null
            }
            val clientLogs = JSONObject(response)
            val endpoint = clientLogs.optString(CLIENT_LOGS_ENDPOINT_KEY)
            val clientId = clientLogs.optString(CLIENT_LOGS_CLIENT_ID_KEY)
            val token = clientLogs.optString(CLIENT_LOGS_TOKEN_KEY)
            if (endpoint != target.endpoint || clientId != target.clientId || token.isBlank()) {
                Log.w(TAG, "Remote log bootstrap returned invalid target")
                return null
            }
            if (!Prefs.saveSecureString(target.tokenCacheKey, token)) {
                Log.w(TAG, "Remote log bootstrap token was not stored securely")
                return null
            }
            Log.d(TAG, "Remote log bootstrap succeeded")
            target.copy(token = token)
        } catch (e: Exception) {
            Log.w(TAG, "Remote log bootstrap failed: $e")
            null
        } finally {
            connection?.disconnect()
        }
    }

    private fun remoteLogInstallationId(): String {
        val existing = Prefs.load<String>(PREFS_REMOTE_LOG_INSTALLATION_ID)
        if (existing.isNotBlank()) return existing
        val created = UUID.randomUUID().toString()
        Prefs.save(PREFS_REMOTE_LOG_INSTALLATION_ID, created)
        return created
    }

    private fun remoteLogTokenPrefsKey(hostName: String, clientId: String): String =
        PREFS_REMOTE_LOG_TOKEN_PREFIX + sha256Hex("$hostName\t$clientId")

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

    private fun sha256Hex(value: String): String =
        MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

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
