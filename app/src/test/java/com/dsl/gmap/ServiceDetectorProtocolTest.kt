package com.dsl.gmap

import com.dsl.gmap.scanner.engine.ServiceDetector
import com.dsl.gmap.scanner.model.PortScanResult
import com.dsl.gmap.scanner.model.PortState
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.ByteBuffer
import java.nio.ByteOrder

class ServiceDetectorProtocolTest {
    @Test
    fun identifiesSmb2DialectAndSigningMode() = runBlocking {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val worker = Thread {
                server.accept().use { socket ->
                    val input = socket.getInputStream()
                    val request = ByteArray(112)
                    var offset = 0
                    while (offset < request.size) {
                        val count = input.read(request, offset, request.size - offset)
                        if (count < 0) return@use
                        offset += count
                    }

                    val response = ByteArray(78)
                    response[0] = 0
                    response[1] = 0
                    response[2] = 0
                    response[3] = 74
                    response[4] = 0xfe.toByte()
                    response[5] = 'S'.code.toByte()
                    response[6] = 'M'.code.toByte()
                    response[7] = 'B'.code.toByte()
                    val buffer = ByteBuffer.wrap(response).order(ByteOrder.LITTLE_ENDIAN)
                    buffer.putShort(68, 65)
                    buffer.putShort(70, 3)
                    buffer.putShort(72, 0x0302)
                    socket.getOutputStream().write(response)
                    socket.getOutputStream().flush()
                }
            }
            worker.start()

            val result = ServiceDetector(smbPorts = setOf(server.localPort)).identify(
                address = server.inetAddress,
                originalTarget = "127.0.0.1",
                openPorts = listOf(PortScanResult(server.localPort, PortState.OPEN)),
                timeoutMs = 1000
            ).single()

            worker.join(2000)
            assertEquals("SMB", result.fingerprint?.service)
            assertTrue(result.fingerprint?.additionalInfo.orEmpty().contains("3.0.2"))
            assertTrue(result.fingerprint?.additionalInfo.orEmpty().contains("signing: required"))
        }
    }

    @Test
    fun identifiesRdpNegotiatedSecurityProtocol() = runBlocking {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val worker = Thread {
                server.accept().use { socket ->
                    val request = ByteArray(19)
                    var offset = 0
                    while (offset < request.size) {
                        val count = socket.getInputStream().read(request, offset, request.size - offset)
                        if (count < 0) return@use
                        offset += count
                    }
                    val response = byteArrayOf(
                        0x03, 0x00, 0x00, 0x13,
                        0x06, 0xd0.toByte(), 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00
                    )
                    socket.getOutputStream().write(response)
                    socket.getOutputStream().flush()
                }
            }
            worker.start()

            val result = ServiceDetector(rdpPorts = setOf(server.localPort)).identify(
                address = server.inetAddress,
                originalTarget = "127.0.0.1",
                openPorts = listOf(PortScanResult(server.localPort, PortState.OPEN)),
                timeoutMs = 1000
            ).single()

            worker.join(2000)
            assertEquals("RDP", result.fingerprint?.service)
            assertTrue(result.fingerprint?.additionalInfo.orEmpty().contains("CredSSP"))
        }
    }
}
