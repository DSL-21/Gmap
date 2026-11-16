package com.dsl.gmap

import com.dsl.gmap.scanner.engine.UdpProbeScanner
import com.dsl.gmap.scanner.model.UdpPortState
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

class UdpProbeScannerTest {
    @Test
    fun detectsUdpServiceThatReplies() = runBlocking {
        DatagramSocket(0, InetAddress.getLoopbackAddress()).use { server ->
            server.soTimeout = 3000
            val worker = Thread {
                val request = DatagramPacket(ByteArray(2048), 2048)
                server.receive(request)
                val responseBytes = byteArrayOf(0x47, 0x4d, 0x41, 0x50)
                server.send(DatagramPacket(responseBytes, responseBytes.size, request.address, request.port))
            }
            worker.start()

            val result = UdpProbeScanner().scan(
                address = InetAddress.getLoopbackAddress(),
                startPort = server.localPort,
                endPort = server.localPort,
                timeoutMs = 1000
            ).single()

            worker.join(3000)
            assertEquals(UdpPortState.OPEN, result.state)
            assertEquals(4, result.responseBytes)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsRangesAbove512Ports() {
        runBlocking {
            UdpProbeScanner().scan(
                address = InetAddress.getLoopbackAddress(),
                startPort = 1,
                endPort = 513
            )
            Unit
        }
    }
}
