package com.anchor.bootstrap

import android.content.Context
import android.net.Uri
import android.os.Build
import android.provider.Settings
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

const val OFFICIAL_MANAGER_PACKAGE = "com.resukisu.resukisu"

data class BootstrapSnapshot(
    val keyStatus: AdbKeyStatus,
    val running: Boolean,
    val stopping: Boolean,
    val autoDisableUsbDebugging: Boolean,
    val forceUmh: Boolean,
    val status: String,
    val log: String,
) {
    companion object {
        fun empty() = BootstrapSnapshot(AdbKeyStatus.MISSING_BOTH, false, false, false, false, "Checking…", "")
    }
}

data class BootstrapBasicInfo(
    val model: String,
    val device: String,
    val androidVersion: String,
    val kernel: String,
    val usbDebugging: Boolean,
    val tcpAdb: String,
    val keyStatus: String,
) {
    fun displayText(): String = buildString {
        appendLine("Device: $model / $device")
        appendLine("Android: $androidVersion")
        appendLine("Kernel: $kernel")
        appendLine("USB debugging: ${if (usbDebugging) "Enabled" else "Disabled"}")
        appendLine("TCP ADB: $tcpAdb")
        append("ADB key: $keyStatus")
    }

    companion object {
        fun loading() = BootstrapBasicInfo("Loading", "", "", "", false, "Loading", "Loading")
    }
}

class BootstrapController(private val context: Context) {
    private val keyStore = AdbKeyStore(context)
    private val logStore = AppLogStore(context)
    private val optionsFile = File(context.noBackupFilesDir, "options.conf")

    fun snapshot(includePreviousResult: Boolean): BootstrapSnapshot {
        val running = BootstrapService.isRunning()
        val status = BootstrapService.currentStatus()
        val log = if (running) {
            logStore.readRecentDiagnostics(MAX_LIVE_LOG_CHARS)
                .ifBlank { "Status: $status" }
        } else if (includePreviousResult) {
            completedRunLog()
        } else {
            ""
        }
        return BootstrapSnapshot(
            keyStatus = keyStore.status(),
            running = running,
            stopping = BootstrapService.isStopRequested(),
            autoDisableUsbDebugging = autoDisableUsbDebugging(),
            forceUmh = forceUmh(),
            status = status,
            log = log
        )
    }

    fun importKey(part: AdbKeyPart, uri: Uri) {
        keyStore.import(part, uri).fold(
            onSuccess = { appendDiagnostic("[+] Imported ${if (part == AdbKeyPart.PRIVATE) "adbkey" else "adbkey.pub"}") },
            onFailure = { appendDiagnostic("[!] Key import failed: ${it.message}") }
        )
    }

    fun appendDiagnostic(line: String) = logStore.appendDiagnostic(line)

    fun recordResult(line: String) = logStore.recordResult(line)

    fun detailedDiagnostics(): String = logStore.readCurrentDiagnostics()

    fun clearLog() {
        logStore.clearDiagnostics()
    }

    fun isUsbDebuggingEnabled(): Boolean = runCatching {
        Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
    }.getOrDefault(false)

    fun setAutoDisableUsbDebugging(enabled: Boolean) {
        writeOptions(autoDisableUsbDebugging = enabled, forceUmh = forceUmh())
    }

    fun setForceUmh(enabled: Boolean) {
        writeOptions(autoDisableUsbDebugging = autoDisableUsbDebugging(), forceUmh = enabled)
    }

    fun forceUmh(): Boolean = readOption("force_umh")

    fun basicInfo(): BootstrapBasicInfo {
        val tcpAdb = runCatching {
            Socket().use { socket -> socket.connect(InetSocketAddress("127.0.0.1", 5555), 750) }
            "Listening on 5555"
        }.getOrElse { "Not listening on 5555" }
        return BootstrapBasicInfo(
            model = Build.MODEL,
            device = Build.DEVICE,
            androidVersion = Build.VERSION.RELEASE,
            kernel = System.getProperty("os.version") ?: "Unknown",
            usbDebugging = isUsbDebuggingEnabled(),
            tcpAdb = tcpAdb,
            keyStatus = keyStore.status().description,
        )
    }

    private fun autoDisableUsbDebugging(): Boolean = readOption("disable_usb_debugging")

    private fun readOption(name: String): Boolean = runCatching {
        optionsFile.readText().lineSequence().any { it.trim() == "$name=1" }
    }.getOrDefault(false)

    private fun writeOptions(autoDisableUsbDebugging: Boolean, forceUmh: Boolean) {
        optionsFile.parentFile?.mkdirs()
        optionsFile.writeText(
            "disable_usb_debugging=${if (autoDisableUsbDebugging) 1 else 0}\n" +
                "force_umh=${if (forceUmh) 1 else 0}\n"
        )
    }

    private fun completedRunLog(): String {
        val diagnostics = logStore.readCurrentDiagnostics().trimEnd()
        val result = logStore.readResult()
        return listOf(diagnostics, result)
            .filter { it.isNotBlank() }
            .joinToString("\n\n")
    }

    private companion object {
        const val MAX_LIVE_LOG_CHARS = 48_000
    }
}
