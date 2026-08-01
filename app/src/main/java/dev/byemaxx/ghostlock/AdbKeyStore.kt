package com.anchor.bootstrap

import android.content.Context
import android.net.Uri
import android.util.Base64
import java.io.File
import java.io.FileOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateCrtKey

enum class AdbKeyPart { PRIVATE, PUBLIC }

enum class AdbKeyStatus(val description: String) {
    MISSING_BOTH("ADB key pair is being created for this app."),
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

    /** Creates a device-local key only for a brand-new installation.  Imported
     * or partially present keys are never overwritten. */
    fun ensureGenerated(): Result<Unit> = runCatching {
        if (status() != AdbKeyStatus.MISSING_BOTH) return@runCatching
        check(directory.isDirectory || directory.mkdirs()) { "Unable to create ADB key directory" }

        val key = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val privateKey = key.private as? RSAPrivateCrtKey ?: error("Generated key is not RSA CRT")
        val privateTemporary = File(directory, "adbkey.new")
        val publicTemporary = File(directory, "adbkey.pub.new")
        privateTemporary.delete()
        publicTemporary.delete()
        try {
            privateTemporary.writeText(toPem(privateKey), Charsets.US_ASCII)
            publicTemporary.writeText(toAdbPublicKey(privateKey), Charsets.US_ASCII)
            check(privateTemporary.renameTo(this.privateKey)) { "Unable to install adbkey" }
            check(publicTemporary.renameTo(this.publicKey)) { "Unable to install adbkey.pub" }
            this.privateKey.setReadable(true, true)
            this.privateKey.setWritable(true, true)
            this.publicKey.setReadable(true, true)
            this.publicKey.setWritable(false, true)
        } finally {
            privateTemporary.delete()
            publicTemporary.delete()
        }
        check(status() == AdbKeyStatus.READY) { "Generated ADB key pair did not validate" }
    }

    private fun validPrivate(file: File): Boolean = runCatching {
        val text = file.readText(Charsets.US_ASCII)
        text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----")
    }.getOrDefault(false)

    private fun validPublic(file: File): Boolean = runCatching {
        val firstToken = file.readText(Charsets.US_ASCII).trim().substringBefore(' ')
        firstToken.length > 100 && firstToken.matches(Regex("[A-Za-z0-9+/=]+"))
    }.getOrDefault(false)

    private fun toPem(key: RSAPrivateCrtKey): String {
        val der = derSequence(
            derInteger(BigInteger.ZERO), derInteger(key.modulus), derInteger(key.publicExponent),
            derInteger(key.privateExponent), derInteger(key.primeP), derInteger(key.primeQ),
            derInteger(key.primeExponentP), derInteger(key.primeExponentQ),
            derInteger(key.crtCoefficient),
        )
        val body = Base64.encodeToString(der, Base64.NO_WRAP).chunked(64).joinToString("\n")
        return "-----BEGIN RSA PRIVATE KEY-----\n$body\n-----END RSA PRIVATE KEY-----\n"
    }

    private fun toAdbPublicKey(key: RSAPrivateCrtKey): String {
        val wordCount = 64
        val wordBits = wordCount * 32
        val two32 = BigInteger.ONE.shiftLeft(32)
        val mask = two32.subtract(BigInteger.ONE)
        val n0inv = two32.subtract(key.modulus.and(mask).modInverse(two32)).and(mask)
        val rr = BigInteger.ONE.shiftLeft(wordBits * 2).mod(key.modulus)
        val encoded = ByteBuffer.allocate(4 + 4 + wordCount * 4 * 2 + 4)
            .order(ByteOrder.LITTLE_ENDIAN)
        encoded.putInt(wordCount)
        putLittleEndianWords(encoded, n0inv, 1, mask)
        putLittleEndianWords(encoded, key.modulus, wordCount, mask)
        putLittleEndianWords(encoded, rr, wordCount, mask)
        encoded.putInt(key.publicExponent.toInt())
        return Base64.encodeToString(encoded.array(), Base64.NO_WRAP) + " anchor@localhost\n"
    }

    private fun putLittleEndianWords(buffer: ByteBuffer, value: BigInteger, words: Int, mask: BigInteger) {
        repeat(words) { index -> buffer.putInt(value.shiftRight(index * 32).and(mask).toInt()) }
    }

    private fun derInteger(value: BigInteger): ByteArray {
        val body = value.toByteArray()
        return byteArrayOf(0x02) + derLength(body.size) + body
    }

    private fun derSequence(vararg fields: ByteArray): ByteArray {
        val body = fields.fold(ByteArray(0)) { result, field -> result + field }
        return byteArrayOf(0x30) + derLength(body.size) + body
    }

    private fun derLength(length: Int): ByteArray = when {
        length < 128 -> byteArrayOf(length.toByte())
        length < 256 -> byteArrayOf(0x81.toByte(), length.toByte())
        else -> byteArrayOf(0x82.toByte(), (length shr 8).toByte(), length.toByte())
    }
}
