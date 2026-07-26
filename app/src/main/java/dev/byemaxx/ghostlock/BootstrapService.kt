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
        updateStatus("Starting Bootstrap")
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
            controller.recordResult("Starting…")
            if (!keyStore.status().ready) {
                updateStatus("Missing ADB key pair")
                controller.recordResult("Bootstrap failed: ${keyStore.status().description}")
                return
            }
            val binary = File(applicationInfo.nativeLibraryDir, "libanchor.so")
            check(binary.isFile) { "libanchor.so was not found" }

            updateStatus("Anchor is running")
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
                controller.recordResult("Timed out; the bootstrap process was terminated.")
                updateStatus("Bootstrap timed out")
                return
            }
            outputThread.join(5_000)

            if (stopRequested.get()) {
                controller.recordResult("Stopped by user.")
                updateStatus("Bootstrap stopped")
                return
            }

            if (startedProcess.exitValue() != 0) {
                controller.recordResult("Bootstrap failed (exit code ${startedProcess.exitValue()}). You can retry directly.")
                updateStatus("Bootstrap failed")
                return
            }

            if (waitForRoot()) {
                controller.recordResult("Bootstrap completed: usable su detected.")
                updateStatus("Root succeeded; passed to official ReSukiSU")
                openOfficialManager()
            } else {
                controller.recordResult("Bootstrap ended without detecting usable su.")
                updateStatus("Bootstrap did not obtain su")
            }
        } catch (error: Exception) {
            controller.appendDiagnostic("[!] Bootstrap error: ${error.message}")
            controller.recordResult("Bootstrap error. Clear logs and retry.")
            updateStatus("Bootstrap error")
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
        @Volatile private var status = "Not started"

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
            "Waiting for adb TCP" in line -> "Waiting for local ADB connection"
            "adbd ready" in line -> "Local ADB connected"
            "Connecting via mini-adb" in line -> "Establishing local connection"
            "AUTH token" in line -> "Verifying ADB key"
            "sending public key" in line -> "Confirm ADB authorization on the device"
            "adb: connected" in line -> "ADB authorized; starting remote task"
            "exploit start" in line -> "Remote task started"
            "Write 1" in line || "Write 2" in line -> "Running bootstrap stage"
            "child is root" in line -> "Completing bootstrap"
            "waiting for su" in line -> "Waiting for permission service"
            else -> null
        }
    }
}
