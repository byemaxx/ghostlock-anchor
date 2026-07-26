package com.anchor.bootstrap

import android.content.Context
import android.net.Uri
import java.io.File
import java.io.FileOutputStream

enum class AdbKeyPart { PRIVATE, PUBLIC }

enum class AdbKeyStatus(val description: String) {
    MISSING_BOTH("No adbkey or adbkey.pub configured. Import a matching device-specific key pair."),
    MISSING_PRIVATE("adbkey.pub is present, but the matching adbkey private key is missing."),
    MISSING_PUBLIC("adbkey is present, but the matching adbkey.pub public key is missing."),
    READY("Key pair ready and stored in this app's private noBackup directory."),
    INVALID("Invalid key file format. Re-import a matching ADB key pair."),
    ;

    val ready: Boolean get() = this == READY
}

class AdbKeyStore(private val context: Context) {
    private val directory = File(context.noBackupFilesDir, "adb")
    val privateKey = File(directory, "adbkey")
    val publicKey = File(directory, "adbkey.pub")

    fun status(): AdbKeyStatus {
        val privatePresent = privateKey.isFile
        val publicPresent = publicKey.isFile
        if (!privatePresent && !publicPresent) return AdbKeyStatus.MISSING_BOTH
        if (!privatePresent) return AdbKeyStatus.MISSING_PRIVATE
        if (!publicPresent) return AdbKeyStatus.MISSING_PUBLIC
        return if (validPrivate(privateKey) && validPublic(publicKey)) AdbKeyStatus.READY else AdbKeyStatus.INVALID
    }

    fun import(part: AdbKeyPart, uri: Uri): Result<Unit> = runCatching {
        directory.mkdirs()
        val destination = if (part == AdbKeyPart.PRIVATE) privateKey else publicKey
        val temporary = File(directory, "${destination.name}.new")
        temporary.delete()
        context.contentResolver.openInputStream(uri)?.use { input ->
            FileOutputStream(temporary).use { output -> input.copyTo(output) }
        } ?: error("Unable to read the selected file")

        val valid = if (part == AdbKeyPart.PRIVATE) validPrivate(temporary) else validPublic(temporary)
        if (!valid) {
            temporary.delete()
            error("The selected file is not a valid ${if (part == AdbKeyPart.PRIVATE) "ADB private key" else "ADB public key"}")
        }

        if (destination.exists() && !destination.delete()) error("Unable to replace ${destination.name}")
        if (!temporary.renameTo(destination)) error("Unable to install ${destination.name}")
        destination.setReadable(true, true)
        destination.setWritable(part == AdbKeyPart.PRIVATE, true)
    }

    private fun validPrivate(file: File): Boolean = runCatching {
        val text = file.readText(Charsets.US_ASCII)
        text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----")
    }.getOrDefault(false)

    private fun validPublic(file: File): Boolean = runCatching {
        val firstToken = file.readText(Charsets.US_ASCII).trim().substringBefore(' ')
        firstToken.length > 100 && firstToken.matches(Regex("[A-Za-z0-9+/=]+"))
    }.getOrDefault(false)
}
