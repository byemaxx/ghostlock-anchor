package com.anchor.bootstrap

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

/** Requests normal Android ADB consent; never opens a remote service. */
internal object AdbAuthorization {
    fun request(socket: Socket, privatePem: String, publicKey: String, port: Int = 5555,
                waiting: () -> Unit) {
        val der = Base64.getMimeDecoder().decode(privatePem.lineSequence()
            .filter { !it.startsWith("-----") }.joinToString(""))
        val encoded = if (privatePem.contains("BEGIN RSA PRIVATE KEY")) {
            sequence(byteArrayOf(2, 1, 0) +
                byteArrayOf(0x30, 0x0d, 6, 9, 0x2a, 0x86.toByte(), 0x48, 0x86.toByte(),
                    0xf7.toByte(), 0x0d, 1, 1, 1, 5, 0) + tlv(4, der))
        } else der
        val key = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(encoded))
        val publicPayload = publicKey.trim().toByteArray(Charsets.US_ASCII) + byteArrayOf(0)
        require(publicPayload.size <= 4096) { "Invalid ADB public key" }
        socket.connect(InetSocketAddress("127.0.0.1", port), 3_000)
        val deadline = System.nanoTime() + 120_000_000_000L
        val input = DataInputStream(socket.getInputStream())
        val output = DataOutputStream(socket.getOutputStream())
        fun send(command: String, arg0: Int, arg1: Int, payload: ByteArray) {
            val commandInt = ByteBuffer.wrap(command.toByteArray(Charsets.US_ASCII))
                .order(ByteOrder.LITTLE_ENDIAN).int
            val header = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(commandInt).putInt(arg0).putInt(arg1).putInt(payload.size)
                .putInt(payload.sumOf { it.toInt() and 255 }).putInt(commandInt.inv()).array()
            output.write(header)
            output.write(payload)
            output.flush()
        }
        fun receive(): Pair<String, Pair<Int, ByteArray>> {
            val header = ByteArray(24)
            fun readFully(bytes: ByteArray) {
                var offset = 0
                while (offset < bytes.size) {
                    val remaining = (deadline - System.nanoTime()) / 1_000_000
                    check(remaining > 0) { "ADB authorization timed out" }
                    socket.soTimeout = remaining.coerceAtMost(Int.MAX_VALUE.toLong()).toInt().coerceAtLeast(1)
                    val count = input.read(bytes, offset, bytes.size - offset)
                    check(count > 0) { "ADB disconnected before authorization completed" }
                    offset += count
                }
            }
            readFully(header)
            val fields = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
            val command = fields.int
            val arg0 = fields.int
            fields.int
            val length = fields.int
            fields.int
            check(fields.int == command.inv() && length in 0..4096) { "Invalid ADB response" }
            val payload = ByteArray(length)
            readFully(payload)
            return String(header, 0, 4, Charsets.US_ASCII) to (arg0 to payload)
        }
        send("CNXN", 0x01000001, 4096, "host::\u0000".toByteArray())
        var response = receive()
        if (response.first == "AUTH" && response.second.first == 1) {
            val token = response.second.second
            require(token.size == 20) { "Invalid ADB challenge" }
            // ADB supplies an existing SHA-1 digest, so sign its DigestInfo without hashing twice.
            val digestInfo = byteArrayOf(0x30, 0x21, 0x30, 9, 6, 5, 0x2b, 0x0e, 3, 2, 0x1a, 5, 0, 4, 0x14)
            val signature = Signature.getInstance("NONEwithRSA").run {
                initSign(key)
                update(digestInfo + token)
                sign()
            }
            send("AUTH", 2, 0, signature)
            response = receive()
            if (response.first == "AUTH" && response.second.first == 1) {
                waiting()
                send("AUTH", 3, 0, publicPayload)
                response = receive()
            }
        }
        check(response.first == "CNXN") { "ADB authorization was not accepted" }
    }

    private fun sequence(bytes: ByteArray) = tlv(0x30, bytes)
    private fun tlv(tag: Int, bytes: ByteArray): ByteArray {
        val length = if (bytes.size < 128) byteArrayOf(bytes.size.toByte())
            else byteArrayOf(0x82.toByte(), (bytes.size shr 8).toByte(), bytes.size.toByte())
        return byteArrayOf(tag.toByte()) + length + bytes
    }
}
