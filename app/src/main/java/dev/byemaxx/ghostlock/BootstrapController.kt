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
    val status: String,
    val log: String,
) {
    companion object {
        fun empty() = BootstrapSnapshot(AdbKeyStatus.MISSING_BOTH, false, false, false, "正在检查…", "")
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
        appendLine("设备: $model / $device")
        appendLine("Android: $androidVersion")
        appendLine("Kernel: $kernel")
        appendLine("USB 调试: ${if (usbDebugging) "已开启" else "未开启"}")
        appendLine("TCP ADB: $tcpAdb")
        append("ADB key: $keyStatus")
    }

    companion object {
        fun loading() = BootstrapBasicInfo("读取中", "", "", "", false, "读取中", "读取中")
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
                .ifBlank { "运行状态：$status" }
        } else if (includePreviousResult) {
            readLog()
        } else {
            ""
        }
        return BootstrapSnapshot(
            keyStatus = keyStore.status(),
            running = running,
            stopping = BootstrapService.isStopRequested(),
            autoDisableUsbDebugging = autoDisableUsbDebugging(),
            status = status,
            log = log
        )
    }

    fun importKey(part: AdbKeyPart, uri: Uri) {
        keyStore.import(part, uri).fold(
            onSuccess = { appendDiagnostic("[+] 已导入 ${if (part == AdbKeyPart.PRIVATE) "adbkey" else "adbkey.pub"}") },
            onFailure = { appendDiagnostic("[!] 密钥导入失败: ${it.message}") }
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
        optionsFile.parentFile?.mkdirs()
        optionsFile.writeText("disable_usb_debugging=${if (enabled) 1 else 0}\n")
    }

    fun basicInfo(): BootstrapBasicInfo {
        val tcpAdb = runCatching {
            Socket().use { socket -> socket.connect(InetSocketAddress("127.0.0.1", 5555), 750) }
            "5555 正在监听"
        }.getOrElse { "5555 未监听" }
        return BootstrapBasicInfo(
            model = Build.MODEL,
            device = Build.DEVICE,
            androidVersion = Build.VERSION.RELEASE,
            kernel = System.getProperty("os.version") ?: "未知",
            usbDebugging = isUsbDebuggingEnabled(),
            tcpAdb = tcpAdb,
            keyStatus = keyStore.status().description,
        )
    }

    private fun autoDisableUsbDebugging(): Boolean = runCatching {
        optionsFile.readText().lineSequence().any { it.trim() == "disable_usb_debugging=1" }
    }.getOrDefault(false)

    private fun readLog(): String {
        return logStore.readResult()
    }

    private companion object {
        const val MAX_LIVE_LOG_CHARS = 48_000
    }
}
