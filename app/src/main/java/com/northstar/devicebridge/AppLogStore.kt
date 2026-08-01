package com.anchor.bootstrap

import android.content.Context
import java.io.File
import java.io.FileOutputStream

/** App-private diagnostic storage for both the live and completed-run UI. */
class AppLogStore(context: Context) {
    private val directory = File(context.noBackupFilesDir, "diagnostics")
    private val activeLog = File(directory, "bootstrap.log")
    private val resultFile = File(context.filesDir, "bootstrap_result.txt")

    @Synchronized
    fun appendDiagnostic(line: String) {
        directory.mkdirs()
        val data = (line.take(MAX_LINE_CHARS) + "\n").toByteArray(Charsets.UTF_8)
        if (activeLog.length() + data.size > MAX_LOG_BYTES) rotate()
        FileOutputStream(activeLog, true).use {
            it.write(data)
            it.fd.sync()
        }
    }

    @Synchronized
    fun recordResult(line: String) {
        resultFile.parentFile?.mkdirs()
        FileOutputStream(resultFile, false).use {
            it.write((line.take(MAX_RESULT_CHARS) + "\n").toByteArray(Charsets.UTF_8))
            it.fd.sync()
        }
    }

    fun readResult(): String = runCatching { resultFile.readText(Charsets.UTF_8).trim() }.getOrDefault("")

    fun readRecentDiagnostics(maxChars: Int): String = runCatching {
        activeLog.readText(Charsets.UTF_8)
            .replace(ANSI_ESCAPE, "")
            .takeLast(maxChars)
    }.getOrDefault("")

    /** The menu's explicit detail view can show the complete active log. */
    fun readCurrentDiagnostics(): String = readRecentDiagnostics(MAX_UI_DIAGNOSTIC_CHARS)

    @Synchronized
    fun clearDiagnostics() {
        activeLog.delete()
        (1..ROTATED_LOG_COUNT).forEach { File(directory, "bootstrap.$it.log").delete() }
    }

    private fun rotate() {
        File(directory, "bootstrap.$ROTATED_LOG_COUNT.log").delete()
        for (index in ROTATED_LOG_COUNT - 1 downTo 1) {
            val source = File(directory, "bootstrap.$index.log")
            if (source.isFile) source.renameTo(File(directory, "bootstrap.${index + 1}.log"))
        }
        if (activeLog.isFile) activeLog.renameTo(File(directory, "bootstrap.1.log"))
    }

    private companion object {
        const val MAX_LOG_BYTES = 256 * 1024L
        const val ROTATED_LOG_COUNT = 3
        const val MAX_LINE_CHARS = 8_192
        const val MAX_RESULT_CHARS = 512
        const val MAX_UI_DIAGNOSTIC_CHARS = 256 * 1024
        val ANSI_ESCAPE = Regex("\\x1b\\[[0-9;]*m")
    }
}
