package com.dsl.gmap

import com.dsl.gmap.scanner.engine.UdpProbeScanner
import com.dsl.gmap.scanner.model.UdpPortState
import com.dsl.gmap.scanner.model.UdpScanSettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class UdpProbeScannerTest {
    private val loopback = InetAddress.getByName("127.0.0.1")

    @Test
    fun detectsUdpServiceThatReplies() = runBlocking {
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
                settings = UdpScanSettings(
                    timeoutMs = 4000,
                    maxRetries = 0,
                    maxConcurrentProbes = 4,
                    adaptiveConcurrency = false
                )
            ).single()

            worker.join(5000)
            assertFalse("UDP responder thread did not finish", worker.isAlive)
            workerFailure.get()?.let { throw AssertionError("UDP echo server failed", it) }
            assertEquals(UdpPortState.OPEN, result.state)
            assertEquals(4, result.responseBytes)
            assertEquals(1, result.attempts)
            assertTrue(result.responsePreview?.isNotBlank() == true)
        }
    }

    @Test
    fun retriesSilentProbeAndDetectsLateResponse() = runBlocking {
        DatagramSocket(0, loopback).use { server ->
            server.soTimeout = 5000
            val workerFailure = AtomicReference<Throwable?>(null)
            val worker = Thread {
                try {
                    repeat(2) { attempt ->
                        val request = DatagramPacket(ByteArray(128), 128)
                        server.receive(request)
                        if (attempt == 1) {
                            val response = byteArrayOf(0x55, 0x44)
                            server.send(DatagramPacket(response, response.size, request.address, request.port))
                        }
                    }
                } catch (failure: Throwable) {
                    workerFailure.set(failure)
                }
            }
            worker.start()

            val result = UdpProbeScanner(
                probePayloadOverride = { byteArrayOf(0x01) }
            ).scan(
                address = loopback,
                startPort = server.localPort,
                endPort = server.localPort,
                settings = UdpScanSettings(
                    timeoutMs = 200,
                    maxRetries = 1,
                    maxConcurrentProbes = 4,
                    adaptiveConcurrency = false
                )
            ).single()

            worker.join(5000)
            workerFailure.get()?.let { throw AssertionError("UDP retry responder failed", it) }
            assertEquals(UdpPortState.OPEN, result.state)
            assertEquals(2, result.attempts)
        }
    }

    @Test
    fun cancellationClosesOutstandingDatagramChannelPromptly() = runBlocking {
        DatagramSocket(0, loopback).use { server ->
            server.soTimeout = 3000
            val received = CountDownLatch(1)
            val worker = Thread {
                try {
                    val request = DatagramPacket(ByteArray(32), 32)
                    server.receive(request)
                    received.countDown()
                } catch (_: Exception) {
                    // The test owns the socket lifecycle.
                }
            }
            worker.start()

            val job = launch(Dispatchers.Default) {
                UdpProbeScanner(probePayloadOverride = { byteArrayOf(0x01) }).scan(
                    address = loopback,
                    startPort = server.localPort,
                    endPort = server.localPort,
                    settings = UdpScanSettings(
                        timeoutMs = 5000,
                        maxRetries = 0,
                        maxConcurrentProbes = 4,
                        adaptiveConcurrency = false
                    )
                )
            }

            assertTrue("Probe was not sent to the local UDP listener", received.await(2, TimeUnit.SECONDS))
            val cancelStarted = System.nanoTime()
            job.cancelAndJoin()
            val cancellationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - cancelStarted)
            assertTrue("Cancellation took too long: " + cancellationMs + " ms", cancellationMs < 1000)
            worker.join(1000)
        }
    }

    @Test
    fun returnsOneFinalResultForEveryRequestedPort() = runBlocking {
        val scanner = UdpProbeScanner(probePayloadOverride = { byteArrayOf(0x00) })
        val results = scanner.scan(
            address = loopback,
            startPort = 40100,
            endPort = 40102,
            settings = UdpScanSettings(
                timeoutMs = 150,
                maxRetries = 0,
                maxConcurrentProbes = 4,
                adaptiveConcurrency = false
            )
        )

        assertEquals(listOf(40100, 40101, 40102), results.map { it.port })
        assertEquals(3, results.map { it.port }.distinct().size)
    }

    @Test
    fun marksProtocolsWithoutSafeUnicastProbeAsNotTested() = runBlocking {
        val result = UdpProbeScanner().scan(
            address = loopback,
            startPort = 161,
            endPort = 161
        ).single()

        assertEquals(UdpPortState.NOT_TESTED, result.state)
        assertEquals(0, result.attempts)
        assertTrue(result.detail.orEmpty().contains("community"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsRangesAbove4096Ports() {
        runBlocking {
            UdpProbeScanner().scan(
                address = loopback,
                startPort = 1,
                endPort = 4097
            )
            Unit
        }
    }
}
