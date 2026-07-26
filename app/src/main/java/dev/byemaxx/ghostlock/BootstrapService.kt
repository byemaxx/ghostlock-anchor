package com.anchor.bootstrap

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.PowerManager
import java.io.File
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class BootstrapService : Service() {
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            requestStop()
            return START_NOT_STICKY
        }
        if (intent?.action != ACTION_RUN || !running.compareAndSet(false, true)) return START_NOT_STICKY
        stopRequested.set(false)
        updateStatus("Bootstrap 正在启动")
        startForeground(NOTIFICATION_ID, notification(getString(R.string.bootstrap_running), true))
        Thread(::runBootstrap, "anchor-bootstrap").start()
        return START_NOT_STICKY
    }

    override fun onCreate() {
        super.onCreate()
        val channel = NotificationChannel(CHANNEL_ID, getString(R.string.bootstrap_channel), NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        wakeLock = getSystemService(PowerManager::class.java)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "anchor:bootstrap")
            .also { it.acquire(TimeUnit.MINUTES.toMillis(12)) }
    }

    private fun runBootstrap() {
        val controller = BootstrapController(applicationContext)
        val keyStore = AdbKeyStore(applicationContext)
        var process: Process? = null
        try {
            controller.clearLog()
            controller.recordResult("启动中。")
            if (!keyStore.status().ready) {
                updateStatus("缺少完整 ADB 密钥对")
                controller.recordResult("启动失败：${keyStore.status().description}")
                return
            }
            val binary = File(applicationInfo.nativeLibraryDir, "libanchor.so")
            check(binary.isFile) { "未找到 libanchor.so" }

            updateStatus("Anchor 正在运行")
            val startedProcess = ProcessBuilder(binary.absolutePath, "--bootstrap")
                .redirectErrorStream(true)
                .apply {
                    environment()["PSELECT_SHIFT"] = "-2"
                    environment()["PSELECT_ROUTE_DELAY_USEC"] = "50000"
                    environment()["ANCHOR_ADBKEY_PATH"] = keyStore.privateKey.absolutePath
                    environment()["ANCHOR_ADBKEY_PUB_PATH"] = keyStore.publicKey.absolutePath
                }
                .start()
            process = startedProcess
            activeProcess.set(startedProcess)
            val outputThread = Thread({
                startedProcess.inputStream.bufferedReader().useLines { lines ->
                    lines.forEach { line ->
                        controller.appendDiagnostic(line)
                        progressForDiagnostic(line)?.let(::updateStatus)
                    }
                }
            }, "anchor-log-reader").apply { start() }

            if (!startedProcess.waitFor(12, TimeUnit.MINUTES)) {
                startedProcess.destroyForcibly()
                startedProcess.waitFor(5, TimeUnit.SECONDS)
                outputThread.join(5_000)
                controller.recordResult("启动超时，启动器已终止。")
                updateStatus("Bootstrap 超时")
                return
            }
            outputThread.join(5_000)

            if (stopRequested.get()) {
                controller.recordResult("启动已由用户停止。")
                updateStatus("Bootstrap 已停止")
                return
            }

            if (startedProcess.exitValue() != 0) {
                controller.recordResult("启动失败（退出码 ${startedProcess.exitValue()}），可直接重试。")
                updateStatus("Bootstrap 失败")
                return
            }

            if (waitForRoot()) {
                controller.recordResult("启动完成：已检测到可用 su。")
                updateStatus("Root 成功，已交给官方 ReSukiSU")
                openOfficialManager()
            } else {
                controller.recordResult("启动结束，但未检测到可用 su。")
                updateStatus("Bootstrap 未取得 su")
            }
        } catch (error: Exception) {
            controller.appendDiagnostic("[!] Bootstrap 异常: ${error.message}")
            controller.recordResult("启动异常，请清理日志后重试。")
            updateStatus("Bootstrap 异常")
        } finally {
            activeProcess.compareAndSet(process, null)
            stopRequested.set(false)
            running.set(false)
            wakeLock?.let { if (it.isHeld) it.release() }
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun waitForRoot(): Boolean {
        repeat(30) {
            if (hasRoot()) return true
            Thread.sleep(2_000)
        }
        return false
    }

    private fun hasRoot(): Boolean = runCatching {
        val process = ProcessBuilder("su", "-c", "id").redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().use { it.readText() }
        process.waitFor(5, TimeUnit.SECONDS) && process.exitValue() == 0 && output.contains("uid=0")
    }.getOrDefault(false)

    private fun openOfficialManager() {
        val intent = packageManager.getLaunchIntentForPackage(OFFICIAL_MANAGER_PACKAGE) ?: return
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        startActivity(intent)
    }

    private fun notification(text: String, ongoing: Boolean): Notification = Notification.Builder(this, CHANNEL_ID)
        .setSmallIcon(android.R.drawable.ic_lock_lock)
        .setContentTitle(getString(R.string.app_name))
        .setContentText(text)
        .setOngoing(ongoing)
        .build()

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        const val ACTION_RUN = "com.anchor.bootstrap.action.RUN"
        const val ACTION_STOP = "com.anchor.bootstrap.action.STOP"
        private const val CHANNEL_ID = "anchor_bootstrap"
        private const val NOTIFICATION_ID = 1001
        private val running = AtomicBoolean(false)
        private val stopRequested = AtomicBoolean(false)
        private val activeProcess = AtomicReference<Process?>(null)
        @Volatile private var status = "尚未运行"

        fun isRunning(): Boolean = running.get()
        fun isStopRequested(): Boolean = stopRequested.get()
        fun currentStatus(): String = status
        fun requestStop() {
            if (!running.get()) return
            stopRequested.set(true)
            activeProcess.get()?.destroyForcibly()
        }
        private fun updateStatus(value: String) { status = value }

        /** Full diagnostics remain in app-private storage; expose only broad
         * lifecycle stages to the UI while a run is active. */
        private fun progressForDiagnostic(line: String): String? = when {
            "Waiting for adb TCP" in line -> "正在等待本地 ADB 连接"
            "adbd ready" in line -> "本地 ADB 已连接"
            "Connecting via mini-adb" in line -> "正在建立本地连接"
            "AUTH token" in line -> "正在验证 ADB 密钥"
            "sending public key" in line -> "等待在设备上确认 ADB 授权"
            "adb: connected" in line -> "ADB 授权完成，正在启动远端任务"
            "exploit start" in line -> "远端任务已启动"
            "Write 1" in line || "Write 2" in line -> "正在执行启动阶段"
            "child is root" in line -> "正在完成启动"
            "waiting for su" in line -> "正在等待权限服务"
            else -> null
        }
    }
}
