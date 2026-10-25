package com.anchor.bootstrap

import org.junit.Assert.*
import org.junit.Test
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPrivateCrtKey
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class AdbAuthorizationTest {
    private fun packet(command: String, arg: Int = 0, payload: ByteArray = byteArrayOf()): ByteArray {
        val cmd = ByteBuffer.wrap(command.toByteArray()).order(ByteOrder.LITTLE_ENDIAN).int
        return ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN).putInt(cmd).putInt(arg)
            .putInt(0).putInt(payload.size).putInt(payload.sumOf { it.toInt() and 255 })
            .putInt(cmd.inv()).array() + payload
    }

    private fun read(socket: Socket): Pair<String, ByteArray> {
        val input = java.io.DataInputStream(socket.getInputStream())
        val header = ByteArray(24).also(input::readFully)
        val length = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN).getInt(12)
        return String(header, 0, 4) to ByteArray(length).also(input::readFully)
    }

    private fun pem(label: String, bytes: ByteArray) =
        "-----BEGIN $label-----\n${Base64.getEncoder().encodeToString(bytes)}\n-----END $label-----"

    private fun der(tag: Int, bytes: ByteArray): ByteArray {
        val length = if (bytes.size < 128) byteArrayOf(bytes.size.toByte())
            else byteArrayOf(0x82.toByte(), (bytes.size shr 8).toByte(), bytes.size.toByte())
        return byteArrayOf(tag.toByte()) + length + bytes
    }

    private fun exercise(publicConsent: Boolean) {
        val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val privatePem = if (publicConsent) {
            val k = pair.private as RSAPrivateCrtKey
            val values = listOf(java.math.BigInteger.ZERO, k.modulus, k.publicExponent,
                k.privateExponent, k.primeP, k.primeQ, k.primeExponentP, k.primeExponentQ, k.crtCoefficient)
            pem("RSA PRIVATE KEY", der(0x30, values.fold(byteArrayOf()) { all, n -> all + der(2, n.toByteArray()) }))
        } else pem("PRIVATE KEY", pair.private.encoded)
        val executor = Executors.newSingleThreadExecutor()
        ServerSocket(0).use { server ->
            val future = executor.submit<Unit> {
                server.accept().use { peer ->
                    peer.soTimeout = 5_000
                    assertEquals("CNXN", read(peer).first)
                    val token = ByteArray(20) { it.toByte() }
                    peer.getOutputStream().write(packet("AUTH", 1, token))
                    val signed = read(peer)
                    assertEquals("AUTH", signed.first)
                    val prefix = byteArrayOf(0x30, 0x21, 0x30, 9, 6, 5, 0x2b, 0x0e, 3, 2, 0x1a, 5, 0, 4, 0x14)
                    assertTrue(Signature.getInstance("NONEwithRSA").run {
                        initVerify(pair.public); update(prefix + token); verify(signed.second)
                    })
                    if (publicConsent) {
                        peer.getOutputStream().write(packet("AUTH", 1, token))
                        val offered = read(peer)
                        assertEquals("AUTH", offered.first)
                        assertArrayEquals("test-public-key\u0000".toByteArray(), offered.second)
                    }
                    // Fragment the reply to verify TCP reads are not treated as whole packets.
                    packet("CNXN").forEach { peer.getOutputStream().write(it.toInt() and 255); peer.getOutputStream().flush() }
                    assertEquals(-1, peer.getInputStream().read()) // No OPEN or remote command.
                }
            }
            var waiting = false
            try {
                Socket().use { AdbAuthorization.request(it, privatePem, "test-public-key", server.localPort) { waiting = true } }
                assertEquals(publicConsent, waiting)
                future.get(10, TimeUnit.SECONDS)
            } finally { executor.shutdownNow() }
        }
    }

    @Test fun trustedKeyAuthenticatesWithoutPromptOrRemoteCommand() = exercise(false)
    @Test fun localPkcs1KeyRequestsConsentAndHandlesFragmentedReply() = exercise(true)

    @Test fun malformedReplyIsRejected() {
        val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        ServerSocket(0).use { server ->
            val executor = Executors.newSingleThreadExecutor()
            val future = executor.submit {
                server.accept().use { peer ->
                    read(peer)
                    peer.getOutputStream().write(packet("CNXN").also { it[20] = (it[20].toInt() xor 1).toByte() })
                }
            }
            try {
                Socket().use { AdbAuthorization.request(it, pem("PRIVATE KEY", pair.private.encoded), "public", server.localPort) {} }
                fail("Malformed header accepted")
            } catch (expected: IllegalStateException) {
                assertEquals("Invalid ADB response", expected.message)
            } finally { future.get(5, TimeUnit.SECONDS); executor.shutdownNow() }
        }
    }
}
