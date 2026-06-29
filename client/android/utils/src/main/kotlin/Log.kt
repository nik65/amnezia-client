package org.amnezia.vpn.util

import android.content.Context
import android.os.Build
import android.os.Process
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.RandomAccessFile
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.time.ZonedDateTime
import java.time.ZoneOffset
import java.util.concurrent.locks.ReentrantLock
import org.amnezia.vpn.util.Log.Priority.D
import org.amnezia.vpn.util.Log.Priority.E
import org.amnezia.vpn.util.Log.Priority.F
import org.amnezia.vpn.util.Log.Priority.I
import org.amnezia.vpn.util.Log.Priority.V
import org.amnezia.vpn.util.Log.Priority.W
import android.util.Log as NativeLog

private const val TAG = "Log"
private const val LOG_FILE_NAME = "amneziaVPN.log"
private const val ROTATE_LOG_FILE_NAME = "amneziaVPN.rotate.log"
private const val LOCK_FILE_NAME = ".lock"
private const val DATE_TIME_PATTERN = "MM-dd HH:mm:ss.SSS"
private const val PREFS_SAVE_LOGS_KEY = "SAVE_LOGS"
private const val LOG_MAX_FILE_SIZE = 1024 * 1024
private const val DEFAULT_EXPORT_MAX_BYTES = 15 * 1024 * 1024
private const val LOGCAT_MAX_LINES = 4000

/**
 * | Priority          | Save to file | Logcat logging                               |
 * |-------------------|--------------|----------------------------------------------|
 * | Verbose           | Don't save   | Only in Debug build                          |
 * | Debug             | Save         | In Debug build or if log saving is enabled   |
 * | Info, Warn, Error | Save         | Enabled                                      |
 * | Fatal (Assert)    | Save         | Enabled. Depending on system configuration,  |
 * |                   |              | create a report and/or terminate the process |
 */
object Log {
    private val dateTimeFormat: DateTimeFormatter = DateTimeFormatter.ofPattern(DATE_TIME_PATTERN)

    private lateinit var logDir: File
    private val logFile: File by lazy { File(logDir, LOG_FILE_NAME) }
    private val rotateLogFile: File by lazy { File(logDir, ROTATE_LOG_FILE_NAME) }

    private val fileLock: FileChannel by lazy { RandomAccessFile(File(logDir, LOCK_FILE_NAME).path, "rw").channel }
    private val threadLock: ReentrantLock by lazy { ReentrantLock() }

    @Volatile
    private var _saveLogs: Boolean = false
    var saveLogs: Boolean
        get() = _saveLogs
        set(value) {
            if (_saveLogs != value) {
                if (value && !logDir.exists() && !logDir.mkdir()) {
                    NativeLog.e(TAG, "Failed to create dir: $logDir")
                    return
                }
                _saveLogs = value
                Prefs.save(PREFS_SAVE_LOGS_KEY, value)
            }
        }

    @JvmStatic
    fun v(tag: String, msg: String) = log(tag, msg, V)

    @JvmStatic
    fun d(tag: String, msg: String) = log(tag, msg, D)

    @JvmStatic
    fun i(tag: String, msg: String) = log(tag, msg, I)

    @JvmStatic
    fun w(tag: String, msg: String) = log(tag, msg, W)

    @JvmStatic
    fun e(tag: String, msg: String) = log(tag, msg, E)

    @JvmStatic
    fun f(tag: String, msg: String) = log(tag, msg, F)

    fun v(tag: String, msg: Any?) = v(tag, msg.toString())

    fun d(tag: String, msg: Any?) = d(tag, msg.toString())

    fun i(tag: String, msg: Any?) = i(tag, msg.toString())

    fun w(tag: String, msg: Any?) = w(tag, msg.toString())

    fun e(tag: String, msg: Any?) = e(tag, msg.toString())

    fun f(tag: String, msg: Any?) = f(tag, msg.toString())

    fun init(context: Context) {
        v(TAG, "Init Log")
        logDir = File(context.cacheDir, "logs")
        saveLogs = true
    }

    fun getLogs(maxBytes: Int = DEFAULT_EXPORT_MAX_BYTES): String {
        val logText = "${deviceInfo()}\n${readLogs(maxBytes / 2)}\nLOGCAT:\n${getLogcat(maxBytes / 2)}"
        return trimUtf8Tail(logText, maxBytes)
    }

    fun getAppLogs(maxBytes: Int = DEFAULT_EXPORT_MAX_BYTES): String {
        val logText = readLogs(maxBytes)
        return trimUtf8Tail(logText, maxBytes)
    }

    private fun trimUtf8Tail(logText: String, maxBytes: Int): String {
        val bytes = logText.toByteArray(Charsets.UTF_8)
        return if (bytes.size > maxBytes) {
            String(bytes.copyOfRange(bytes.size - maxBytes, bytes.size), Charsets.UTF_8)
        } else {
            logText
        }
    }

    fun clearLogs() {
        if (logDir.exists()) {
            withLock {
                logFile.delete()
                rotateLogFile.delete()
            }
        }
    }

    private fun log(tag: String, msg: String, priority: Priority) {
        if (saveLogs && priority != V) saveLogMsg(formatLogMsg(tag, msg, priority))

        if (priority == F) {
            NativeLog.wtf(tag, msg)
        } else if (
            (priority != V && priority != D) ||
            (priority == V && BuildConfig.DEBUG) ||
            (priority == D && (BuildConfig.DEBUG || saveLogs))
        ) {
            NativeLog.println(priority.level, tag, msg)
        }
    }

    private fun saveLogMsg(msg: String) {
        withLock {
            if (logFile.length() > LOG_MAX_FILE_SIZE) {
                logFile.renameTo(rotateLogFile)
            }
            try {
                logFile.appendText(msg)
            } catch (e: IOException) {
                NativeLog.e(TAG, "Failed to write log: $e")
            }
        }
    }

    private fun formatLogMsg(tag: String, msg: String, priority: Priority): String {
        val utcDate = ZonedDateTime.now(ZoneOffset.UTC).format(dateTimeFormat)
        return "${utcDate}Z ${Process.myPid()} ${Process.myTid()} $priority [${Thread.currentThread().name}] " +
            "$tag: $msg\n"
    }

    private fun deviceInfo(): String {
        val sb = StringBuilder()
        sb.append("Model: ").appendLine(Build.MODEL)
        sb.append("Brand: ").appendLine(Build.BRAND)
        sb.append("Product: ").appendLine(Build.PRODUCT)
        sb.append("Device: ").appendLine(Build.DEVICE)
        sb.append("Codename: ").appendLine(Build.VERSION.CODENAME)
        sb.append("Release: ").appendLine(Build.VERSION.RELEASE)
        sb.append("SDK: ").appendLine(Build.VERSION.SDK_INT)
        sb.append("ABI: ").appendLine(Build.SUPPORTED_ABIS.joinToString())
        return sb.toString()
    }

    private fun readLogs(maxBytes: Int): String {
        var logText = ""
        withLock {
            try {
                if (rotateLogFile.exists()) logText = readFileTail(rotateLogFile, maxBytes / 2)
                if (logFile.exists()) logText += readFileTail(logFile, maxBytes / 2)
            } catch (e: IOException) {
                val errorMsg = "Failed to read log: $e"
                NativeLog.e(TAG, errorMsg)
                logText += errorMsg
            }
        }
        return logText
    }

    private fun getLogcat(maxBytes: Int): String {
        try {
            val process = ProcessBuilder("logcat", "-d", "-t", LOGCAT_MAX_LINES.toString()).redirectErrorStream(true).start()
            return process.inputStream.use { stream ->
                readStreamPrefix(stream, maxBytes)
            }
        } catch (e: IOException) {
            val errorMsg = "Failed to get logcat log: $e"
            NativeLog.e(TAG, errorMsg)
            return errorMsg
        }
    }

    private fun readFileTail(file: File, maxBytes: Int): String {
        if (maxBytes <= 0) return ""
        RandomAccessFile(file, "r").use { input ->
            val length = input.length()
            val start = (length - maxBytes).coerceAtLeast(0)
            input.seek(start)
            val bytes = ByteArray((length - start).toInt())
            input.readFully(bytes)
            return String(bytes, Charsets.UTF_8)
        }
    }

    private fun readStreamPrefix(stream: InputStream, maxBytes: Int): String {
        if (maxBytes <= 0) return ""
        val output = ByteArrayOutputStream(maxBytes.coerceAtMost(64 * 1024))
        val buffer = ByteArray(8 * 1024)
        while (output.size() < maxBytes) {
            val read = stream.read(buffer, 0, minOf(buffer.size, maxBytes - output.size()))
            if (read <= 0) break
            output.write(buffer, 0, read)
        }
        return String(output.toByteArray(), Charsets.UTF_8)
    }

    private fun withLock(block: () -> Unit) {
        threadLock.lock()
        try {
            var l: FileLock? = null
            try {
                l = fileLock.lock()
                block()
            } catch (e: IOException) {
                NativeLog.e(TAG, "Failed to get file lock: $e")
            } finally {
                try {
                    l?.release()
                } catch (e: IOException) {
                    NativeLog.e(TAG, "Failed to release file lock: $e")
                }
            }
        } finally {
            threadLock.unlock()
        }
    }

    private fun withTryLock(condition: () -> Boolean, block: () -> Unit) {
        if (condition()) {
            if (threadLock.tryLock()) {
                try {
                    if (condition()) {
                        var l: FileLock? = null
                        try {
                            l = fileLock.tryLock()
                            if (l != null) {
                                if (condition()) {
                                    block()
                                }
                            }
                        } catch (e: IOException) {
                            NativeLog.e(TAG, "Failed to get file tryLock: $e")
                        } finally {
                            try {
                                l?.release()
                            } catch (e: IOException) {
                                NativeLog.e(TAG, "Failed to release file tryLock: $e")
                            }
                        }
                    }
                } finally {
                    threadLock.unlock()
                }
            }
        }
    }

    private enum class Priority(val level: Int) {
        V(2),
        D(3),
        I(4),
        W(5),
        E(6),
        F(7)
    }
}
