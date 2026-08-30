package com.anchor.bootstrap

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import android.os.Build
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
        val runFromBoot = intent?.action == ACTION_RUN_BOOT
        val afterUnlock = intent?.getStringExtra(EXTRA_BOOT_BROADCAST) == Intent.ACTION_BOOT_COMPLETED
        if ((intent?.action != ACTION_RUN && !runFromBoot) || !running.compareAndSet(false, true)) return START_NOT_STICKY
        stopRequested.set(false)
        updateStatus(if (runFromBoot) "Starting boot Bootstrap" else "Starting Bootstrap")
        val foregroundNotification = notification(getString(R.string.bootstrap_running), true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                foregroundNotification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, foregroundNotification)
        }
        Thread({ runBootstrap(runFromBoot, afterUnlock) }, "anchor-bootstrap").start()
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

    private fun runBootstrap(runFromBoot: Boolean, afterUnlock: Boolean) {
        val controller = BootstrapController(applicationContext)
        val keyStore = AdbKeyStore(applicationContext)
        var process: Process? = null
        var campaign: BootRunCoordinator.BootCampaign? = null
        var campaignResult = "failed"
        try {
            if (AnchorDisableSwitch.isDisabled(applicationContext)) {
                campaignResult = "disabled"
                updateStatus("Anchor disabled by recovery marker")
                controller.appendDiagnostic("[!] Native Bootstrap skipped: ${AnchorDisableSwitch.FILE_NAME} is present.")
                controller.recordResult("Anchor is disabled by the recovery marker. Remove it before retrying.")
                return
            }
            if (runFromBoot) {
                val bootCampaign = BootRunCoordinator(applicationContext).begin(afterUnlock)
                campaign = bootCampaign
                when (bootCampaign.decision) {
                    BootCampaignDecision.ALREADY_FINISHED -> {
                        updateStatus("Boot Bootstrap already completed")
                        controller.recordResult("Boot Bootstrap already completed for this boot.")
                        return
                    }
                    BootCampaignDecision.ALREADY_RUNNING -> {
                        updateStatus("Boot Bootstrap already running")
                        controller.appendDiagnostic("[+] Ignored duplicate boot broadcast; campaign already running.")
                        return
                    }
                    BootCampaignDecision.START -> Unit
                }
                if (hasRoot()) {
                    campaignResult = "already-rooted"
                    updateStatus("Root already available")
                    controller.recordResult("Boot Bootstrap skipped: usable su already detected.")
                    return
                }
            }
            controller.clearLog()
            controller.recordResult(if (runFromBoot) "Starting boot Bootstrap…" else "Starting…")
            if (!keyStore.status().ready) {
                if (runFromBoot && !afterUnlock) campaignResult = "awaiting-unlock"
                updateStatus("Missing ADB key pair")
                controller.recordResult("Bootstrap failed: ${keyStore.status().description}")
                return
            }
            val binary = File(applicationInfo.nativeLibraryDir, "libanchor.so")
            check(binary.isFile) { "libanchor.so was not found" }
            val directContext = applicationContext.createDeviceProtectedStorageContext()
            val bootstrapLockDir = File(directContext.noBackupFilesDir, "bootstrap-lock")
            check(bootstrapLockDir.isDirectory || bootstrapLockDir.mkdirs()) {
                "Could not create the bootstrap lock directory"
            }
            // This private copy is only the unprivileged deployment source.
            // The native root handoff atomically publishes it to /data/adb/anchor.
            val policyRepairScript = File(directContext.noBackupFilesDir, "repair_selinux_policy.sh")
            assets.open("repair_selinux_policy.sh").use { input ->
                policyRepairScript.outputStream().use(input::copyTo)
            }
            check(policyRepairScript.setReadable(true, true)) {
                "Could not make the policy repair script readable"
            }

            updateStatus("Anchor is running")
            val kernelProfile = KernelProfiles.current(applicationContext)
            val shiftOverride = controller.pselectShiftOverride().trim()
            val effectivePselectShift = shiftOverride.ifBlank { kernelProfile.pselectShift?.toString().orEmpty() }
            controller.appendDiagnostic(
                "[+] native launch profile: device=${Build.DEVICE} model=${Build.MODEL} " +
                    "directory=${kernelProfile.deviceDirectory} default=${kernelProfile.pselectShift ?: "<native>"} " +
                    "override=${shiftOverride.ifBlank { "<none>" }} " +
                    "effective=${effectivePselectShift.ifBlank { "<unset>" }}"
            )
            // Mirror upstream's shell form through ProcessBuilder's environment:
            //   PSELECT_SHIFT=-2 /data/local/tmp/a/e --bootstrap
            // Do not use Toybox env here: Android's randomized app path can contain
            // '=' and Toybox env may mistake that path for another assignment.
            val nativeCommand = listOf(binary.absolutePath, "--bootstrap")
            controller.appendDiagnostic(
                "[+] native command: PSELECT_SHIFT=${effectivePselectShift.ifBlank { "<native>" }} " +
                    nativeCommand.joinToString(" ")
            )
            val attempts = if (runFromBoot) MAX_BOOT_ATTEMPTS else 1
            for (attempt in 1..attempts) {
                if (stopRequested.get()) {
                    campaignResult = "stopped"
                    controller.recordResult("Stopped by user.")
                    updateStatus("Bootstrap stopped")
                    return
                }
                if (attempt > 1) {
                    val delay = BOOT_RETRY_DELAYS_MILLIS[attempt - 2]
                    updateStatus("Retrying boot Bootstrap ($attempt/$attempts)")
                    controller.appendDiagnostic("[+] Boot Bootstrap retry $attempt/$attempts after ${delay / 1_000}s.")
                    Thread.sleep(delay)
                }
                val startedProcess = ProcessBuilder(nativeCommand)
                    .redirectErrorStream(true)
                    .apply {
                        applyEnvironmentOverrides(environment(), controller.preEnv())
                        if (effectivePselectShift.isBlank()) environment().remove("PSELECT_SHIFT")
                        else environment()["PSELECT_SHIFT"] = effectivePselectShift
                        environment()["ANCHOR_ADBKEY_PATH"] = keyStore.privateKey.absolutePath
                        environment()["ANCHOR_ADBKEY_PUB_PATH"] = keyStore.publicKey.absolutePath
                        environment()["ANCHOR_BOOTSTRAP_LOCK_DIR"] = bootstrapLockDir.absolutePath
                        environment()["ANCHOR_FORCE_UMH"] = if (controller.forceUmh()) "1" else "0"
                        environment()["ANCHOR_LOAD_POLICY"] = if (controller.loadPolicy()) "1" else "0"
                        environment()["ANCHOR_POLICY_REPAIR_SOURCE"] = policyRepairScript.absolutePath
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
                val timeout = if (runFromBoot) BOOT_ATTEMPT_TIMEOUT_MINUTES else 12L
                if (!startedProcess.waitFor(timeout, TimeUnit.MINUTES)) {
                    startedProcess.destroyForcibly()
                    startedProcess.waitFor(5, TimeUnit.SECONDS)
                    outputThread.join(5_000)
                    controller.appendDiagnostic("[!] Bootstrap attempt $attempt timed out.")
                } else {
                    outputThread.join(5_000)
                    if (stopRequested.get()) {
                        campaignResult = "stopped"
                        controller.recordResult("Stopped by user.")
                        updateStatus("Bootstrap stopped")
                        return
                    }
                    if (startedProcess.exitValue() == 0 && waitForRoot()) {
                        campaignResult = "success"
                        controller.recordResult("Bootstrap completed: usable su detected.")
                        updateStatus("Root succeeded; passed to official ReSukiSU")
                        if (!runFromBoot) openOfficialManager()
                        return
                    }
                    controller.appendDiagnostic("[!] Bootstrap attempt $attempt exited ${startedProcess.exitValue()} without usable su.")
                }
                activeProcess.compareAndSet(startedProcess, null)
            }
            controller.recordResult(if (runFromBoot) "Boot Bootstrap failed after $attempts bounded attempts." else "Bootstrap ended without detecting usable su.")
            updateStatus(if (runFromBoot) "Boot Bootstrap failed" else "Bootstrap did not obtain su")
        } catch (error: Exception) {
            controller.appendDiagnostic("[!] Bootstrap error: ${error.message}")
            controller.recordResult("Bootstrap error. Clear logs and retry.")
            updateStatus("Bootstrap error")
        } finally {
            runCatching { campaign?.finish(campaignResult) }
                .onFailure { error ->
                    controller.appendDiagnostic("[!] Could not finalize boot campaign state: ${error.message}")
                    controller.recordResult("Boot Bootstrap state could not be finalized; open Anchor before retrying.")
                }
            campaign?.close()
            activeProcess.compareAndSet(process, null)
            stopRequested.set(false)
            running.set(false)
            wakeLock?.let { if (it.isHeld) it.release() }
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun applyEnvironmentOverrides(environment: MutableMap<String, String>, value: String) {
        value.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith('#') }
            .forEach { entry ->
                val separator = entry.indexOf('=')
                if (separator > 0) {
                    val name = entry.substring(0, separator).trim()
                    if (name.matches(Regex("[A-Za-z_][A-Za-z0-9_]*"))) {
                        environment[name] = entry.substring(separator + 1)
                    }
                }
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
        const val ACTION_RUN_BOOT = "com.anchor.bootstrap.action.RUN_BOOT"
        const val ACTION_STOP = "com.anchor.bootstrap.action.STOP"
        private const val EXTRA_BOOT_BROADCAST = "boot_broadcast"
        private const val CHANNEL_ID = "anchor_bootstrap"
        private const val NOTIFICATION_ID = 1001
        private const val MAX_BOOT_ATTEMPTS = 3
        // Three attempts, two one-minute root checks, and backoff stay within
        // the service's twelve-minute wake-lock lifetime.
        private const val BOOT_ATTEMPT_TIMEOUT_MINUTES = 2L
        private val BOOT_RETRY_DELAYS_MILLIS = longArrayOf(15_000, 45_000)
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
        fun startBootCampaign(context: Context, broadcastAction: String) {
            if (AnchorDisableSwitch.isDisabled(context)) {
                recordDisabled(context)
                return
            }
            if (!BootstrapController(context).runOnBoot()) {
                recordBootOptOut(context)
                return
            }
            val intent = Intent(context, BootstrapService::class.java)
                .setAction(ACTION_RUN_BOOT)
                .putExtra(EXTRA_BOOT_BROADCAST, broadcastAction)
            runCatching { context.startForegroundService(intent) }
                .onFailure { error -> recordBootStartFailure(context, error) }
        }
        private fun recordBootStartFailure(context: Context, error: Throwable) {
            BootstrapController(context).apply {
                appendDiagnostic("[!] Boot Bootstrap could not start: ${error.javaClass.simpleName}: ${error.message}")
                recordResult("Boot Bootstrap could not start. Open Anchor after unlock for details.")
            }
            val manager = context.getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(NotificationChannel(CHANNEL_ID, context.getString(R.string.bootstrap_channel), NotificationManager.IMPORTANCE_LOW))
            manager.notify(
                NOTIFICATION_ID,
                Notification.Builder(context, CHANNEL_ID)
                    .setSmallIcon(android.R.drawable.ic_lock_lock)
                    .setContentTitle(context.getString(R.string.app_name))
                    .setContentText("Boot Bootstrap could not start; open Anchor after unlock.")
                    .build()
            )
        }
        private fun recordDisabled(context: Context) {
            BootstrapController(context).apply {
                appendDiagnostic("[!] Boot Bootstrap skipped: ${AnchorDisableSwitch.FILE_NAME} is present.")
                recordResult("Anchor is disabled by the recovery marker. Remove it before retrying.")
            }
            val manager = context.getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(NotificationChannel(CHANNEL_ID, context.getString(R.string.bootstrap_channel), NotificationManager.IMPORTANCE_LOW))
            manager.notify(
                NOTIFICATION_ID,
                Notification.Builder(context, CHANNEL_ID)
                    .setSmallIcon(android.R.drawable.ic_lock_lock)
                    .setContentTitle(context.getString(R.string.app_name))
                    .setContentText("Boot Bootstrap disabled by recovery marker.")
                    .build()
            )
        }
        private fun recordBootOptOut(context: Context) {
            BootstrapController(context).apply {
                appendDiagnostic("[+] Boot Bootstrap skipped: Run on boot is disabled in Anchor settings.")
                recordResult("Boot Bootstrap is disabled in Anchor settings.")
            }
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
