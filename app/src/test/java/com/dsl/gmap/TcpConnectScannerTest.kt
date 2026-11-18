package com.dsl.gmap

import com.dsl.gmap.scanner.engine.TcpConnectScanner
import com.dsl.gmap.scanner.model.PortState
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicInteger

class TcpConnectScannerTest {

    @Test
    fun scannerHasStrictMobileConcurrencyCeiling() {
        assertEquals(32, TcpConnectScanner.MAX_CONCURRENT_PROBES)
        assertTrue(TcpConnectScanner.MIN_CONCURRENT_PROBES in 1..TcpConnectScanner.MAX_CONCURRENT_PROBES)
    }


    @Test
    fun detectsListeningTcpPort() = runBlocking {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val progressCallbacks = AtomicInteger(0)
            val results = TcpConnectScanner().scan(
                address = server.inetAddress,
                startPort = server.localPort,
                endPort = server.localPort,
                timeoutMs = 500
            ) { progress, result ->
                progressCallbacks.incrementAndGet()
                assertEquals(1, progress.completed)
                assertEquals(1, progress.total)
                assertEquals(PortState.OPEN, result.state)
            }

            assertEquals(1, results.size)
            assertEquals(server.localPort, results.single().port)
            assertEquals(PortState.OPEN, results.single().state)
            assertTrue(progressCallbacks.get() >= 1)
        }
    }

    @Test
    fun returnsExactlyOneResultForEveryPortInRequestedRange() = runBlocking {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val first = server.localPort - 1
            val last = server.localPort + 1
            val results = TcpConnectScanner().scan(
                address = InetAddress.getLoopbackAddress(),
                startPort = first,
                endPort = last,
                timeoutMs = 500
            )

            assertEquals(3, results.size)
            assertEquals((first..last).toList(), results.map { it.port }.sorted())
            assertEquals(results.size, results.map { it.port }.distinct().size)
            assertEquals(PortState.OPEN, results.single { it.port == server.localPort }.state)
        }
    }

    @Test
    fun detectsRefusedTcpConnectionAsClosed() = runBlocking {
        val closedPort = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use {
            it.localPort
        }

        val results = TcpConnectScanner().scan(
            address = InetAddress.getLoopbackAddress(),
            startPort = closedPort,
            endPort = closedPort,
            timeoutMs = 500
        )

        assertEquals(1, results.size)
        assertEquals(PortState.CLOSED, results.single().state)
    }
}
