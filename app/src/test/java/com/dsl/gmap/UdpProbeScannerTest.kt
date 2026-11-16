package com.dsl.gmap

import com.dsl.gmap.scanner.engine.UdpProbeScanner
import com.dsl.gmap.scanner.model.UdpPortState
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicReference

class UdpProbeScannerTest {
    @Test
    fun detectsUdpServiceThatReplies() = runBlocking {
        val loopback = InetAddress.getByName("127.0.0.1")
        DatagramSocket(0, loopback).use { server ->
            server.soTimeout = 5000
            val workerFailure = AtomicReference<Throwable?>(null)
            val worker = Thread {
                try {
                    val request = DatagramPacket(ByteArray(128), 128)
                    server.receive(request)
                    assertEquals(4, request.length)
                    val responseBytes = byteArrayOf(0x47, 0x4d, 0x41, 0x50)
                    server.send(DatagramPacket(responseBytes, responseBytes.size, request.address, request.port))
                } catch (failure: Throwable) {
                    workerFailure.set(failure)
                }
            }
            worker.start()

            val result = UdpProbeScanner(
                probePayloadOverride = { byteArrayOf(0x47, 0x4d, 0x41, 0x50) }
            ).scan(
                address = loopback,
                startPort = server.localPort,
                endPort = server.localPort,
                timeoutMs = 4000
            ).single()

            worker.join(5000)
            assertFalse("UDP responder thread did not finish", worker.isAlive)
            workerFailure.get()?.let { throw AssertionError("UDP echo server failed", it) }
            assertEquals(UdpPortState.OPEN, result.state)
            assertEquals(4, result.responseBytes)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsRangesAbove512Ports() {
        runBlocking {
            UdpProbeScanner().scan(
                address = InetAddress.getByName("127.0.0.1"),
                startPort = 1,
                endPort = 513
            )
            Unit
        }
    }
}
