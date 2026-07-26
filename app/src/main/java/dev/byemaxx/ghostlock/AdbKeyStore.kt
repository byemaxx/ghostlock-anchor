package com.anchor.bootstrap

import android.content.Context
import android.net.Uri
import java.io.File
import java.io.FileOutputStream

enum class AdbKeyPart { PRIVATE, PUBLIC }

enum class AdbKeyStatus(val description: String) {
    MISSING_BOTH("未配置 adbkey 与 adbkey.pub。请导入一对匹配的设备专属密钥。"),
    MISSING_PRIVATE("仅存在 adbkey.pub；缺少与之匹配的私钥 adbkey。"),
    MISSING_PUBLIC("仅存在 adbkey；缺少与之匹配的公钥 adbkey.pub。"),
    READY("密钥对已就绪，保存在本 App 的 noBackup 私有目录。"),
    INVALID("密钥文件格式无效，请重新导入一对匹配的 ADB key。"),
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
        } ?: error("无法读取所选文件")

        val valid = if (part == AdbKeyPart.PRIVATE) validPrivate(temporary) else validPublic(temporary)
        if (!valid) {
            temporary.delete()
            error("所选文件不是有效的 ${if (part == AdbKeyPart.PRIVATE) "ADB 私钥" else "ADB 公钥"}")
        }

        if (destination.exists() && !destination.delete()) error("无法替换 ${destination.name}")
        if (!temporary.renameTo(destination)) error("无法安装 ${destination.name}")
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
