package com.anchor.bootstrap

import android.content.Context
import java.io.File
import java.io.RandomAccessFile
import java.nio.channels.FileChannel
import java.nio.channels.FileLock

internal enum class BootCampaignDecision { START, ALREADY_FINISHED, ALREADY_RUNNING }

/** A recovery-accessible escape hatch for disabling all native launches. */
internal object AnchorDisableSwitch {
    const val FILE_NAME = ".ANCHOR_DISABLE"

    fun marker(context: Context): File = File(
        context.createDeviceProtectedStorageContext().filesDir,
        FILE_NAME
    )

    fun isDisabled(context: Context): Boolean = isDisabled(marker(context))

    internal fun isDisabled(marker: File): Boolean = marker.isFile
}

/** Pure policy so the boot delivery cases remain unit-testable. */
internal object BootCampaignPolicy {
    fun decide(completedForCurrentBoot: Boolean, lockAvailable: Boolean): BootCampaignDecision = when {
        completedForCurrentBoot -> BootCampaignDecision.ALREADY_FINISHED
        lockAvailable -> BootCampaignDecision.START
        else -> BootCampaignDecision.ALREADY_RUNNING
    }
}

/**
 * Coordinates the two Android boot broadcasts across process restarts. The lock
 * stays held for the native campaign; the terminal marker prevents a later
 * BOOT_COMPLETED delivery from repeating a failed or successful campaign.
 */
internal class BootRunCoordinator(context: Context) {
    private val directContext = context.createDeviceProtectedStorageContext()
    private val directory = File(directContext.noBackupFilesDir, "boot-run")
    private val lockFile = File(directory, "campaign.lock")
    private val terminalFile = File(directory, "terminal.txt")

    fun begin(allowAfterUnlockRetry: Boolean): BootCampaign {
        check(directory.isDirectory || directory.mkdirs()) { "Could not create boot-run state directory" }
        val bootId = File(PROC_BOOT_ID).readText().trim().takeIf { it.matches(BOOT_ID) }
            ?: error("Could not read the current boot identifier")
        if (isFinishedFor(bootId, allowAfterUnlockRetry)) {
            return BootCampaign(BootCampaignDecision.ALREADY_FINISHED, null, bootId)
        }

        val file = RandomAccessFile(lockFile, "rw")
        val channel = file.channel
        val lock = runCatching { channel.tryLock() }.getOrNull()
        val decision = BootCampaignPolicy.decide(isFinishedFor(bootId, allowAfterUnlockRetry), lock != null)
        if (decision != BootCampaignDecision.START) {
            runCatching { lock?.release() }
            channel.close()
            file.close()
            return BootCampaign(decision, null, bootId)
        }
        try {
            writeState(bootId, "running")
        } catch (error: Exception) {
            LockHandle(file, channel, lock!!).close()
            throw error
        }
        return BootCampaign(BootCampaignDecision.START, LockHandle(file, channel, lock!!), bootId)
    }

    private fun isFinishedFor(bootId: String, allowAfterUnlockRetry: Boolean): Boolean = runCatching {
        val values = terminalFile.readLines().associate { line ->
            line.substringBefore('=') to line.substringAfter('=', "")
        }
        values["boot_id"] == bootId &&
            !(allowAfterUnlockRetry && values["result"] == RESULT_AWAITING_UNLOCK)
    }.getOrDefault(false)

    inner class BootCampaign internal constructor(
        val decision: BootCampaignDecision,
        private val lock: LockHandle?,
        private val bootId: String,
    ) : AutoCloseable {
        fun finish(result: String) {
            if (decision != BootCampaignDecision.START) return
            writeState(bootId, result)
        }

        override fun close() {
            lock?.close()
        }
    }

    private fun writeState(bootId: String, result: String) {
        val temporary = File(directory, "terminal.new")
        temporary.writeText("boot_id=$bootId\nresult=$result\n")
        check(temporary.renameTo(terminalFile)) { "Could not record boot campaign result" }
    }

    internal class LockHandle(
        private val file: RandomAccessFile,
        private val channel: FileChannel,
        private val lock: FileLock,
    ) : AutoCloseable {
        override fun close() {
            runCatching { lock.release() }
            runCatching { channel.close() }
            runCatching { file.close() }
        }
    }

    private companion object {
        const val PROC_BOOT_ID = "/proc/sys/kernel/random/boot_id"
        const val RESULT_AWAITING_UNLOCK = "awaiting-unlock"
        val BOOT_ID = Regex("[0-9a-fA-F-]{36}")
    }
}
