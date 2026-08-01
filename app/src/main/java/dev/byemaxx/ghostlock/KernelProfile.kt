package com.anchor.bootstrap

import android.content.Context
import android.os.Build
import java.util.concurrent.TimeUnit

data class KernelProfile(
    val deviceDirectory: String = "default",
    val pselectShift: Int? = null,
)

object KernelProfiles {
    private val currentRelease: String by lazy(::detectKernelRelease)

    fun forDevice(context: Context, device: String = Build.DEVICE, model: String = Build.MODEL): KernelProfile = runCatching {
        val identifiers = setOf(device, model).map { it.trim().lowercase() }
        context.assets.open("kernel_profiles.conf").bufferedReader().useLines { lines ->
            lines.mapNotNull(::parseLine)
                .firstOrNull { it.identifiers.any(identifiers::contains) }
                ?.let { KernelProfile(it.deviceDirectory, it.pselectShift) }
                ?: KernelProfile()
        }
    }.getOrDefault(KernelProfile())

    fun current(context: Context): KernelProfile = forDevice(context)

    fun readKernelRelease(): String = currentRelease

    private fun detectKernelRelease(): String = runCatching {
        ProcessBuilder("/system/bin/uname", "-r")
            .redirectErrorStream(true)
            .start()
            .apply { waitFor(2, TimeUnit.SECONDS) }
            .inputStream.bufferedReader().use { it.readText().trim() }
    }.getOrDefault(System.getProperty("os.version") ?: "Unknown")

    private data class ConfiguredProfile(
        val deviceDirectory: String,
        val identifiers: Set<String>,
        val pselectShift: Int?,
    )

    private fun parseLine(line: String): ConfiguredProfile? {
        val fields = line.substringBefore('#').trim().split('|')
        if (fields.size != 3 || fields[0].isBlank() || fields[1].isBlank()) return null
        val shift = fields[2].trim().takeIf { it.isNotEmpty() }?.toIntOrNull()
            ?: if (fields[2].isBlank()) null else return null
        return ConfiguredProfile(
            deviceDirectory = fields[0].trim(),
            identifiers = fields[1].split(',').map { it.trim().lowercase() }.toSet(),
            pselectShift = shift,
        )
    }
}
