package com.dsl.gmap

import com.dsl.gmap.scanner.engine.ServiceDetector
import com.dsl.gmap.scanner.model.PortScanResult
import com.dsl.gmap.scanner.model.PortState
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets

class ServiceDetectorTest {

    @Test
    fun identifiesHttpStatusAndServerHeaderOnCustomPort() = runBlocking {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val serverThread = Thread {
                server.accept().use { client ->
                    client.soTimeout = 2000
                    val reader = BufferedReader(InputStreamReader(client.getInputStream(), StandardCharsets.US_ASCII))
                    while (reader.readLine()?.isNotEmpty() == true) {
                        // Consume the HEAD request headers.
                    }
                    val lineBreak = 13.toChar().toString() + 10.toChar()
                    val response = listOf(
                        "HTTP/1.1 200 OK",
                        "Server: Gmap-Test-Server",
                        "Content-Length: 0",
                        "Connection: close"
                    ).joinToString(separator = lineBreak, postfix = lineBreak + lineBreak)
                    client.getOutputStream().write(response.toByteArray(StandardCharsets.US_ASCII))
                    client.getOutputStream().flush()
                }
            }
            serverThread.start()

            val result = ServiceDetector(httpPorts = setOf(server.localPort), tlsPorts = emptySet())
                .identify(
                    address = server.inetAddress,
                    originalTarget = "localhost",
                    openPorts = listOf(
                        PortScanResult(
                            port = server.localPort,
                            state = PortState.OPEN,
                            serviceHint = "HTTP"
                        )
                    ),
                    timeoutMs = 1000
                )
                .single()

            serverThread.join(2000)
            assertEquals(PortState.OPEN, result.state)
            assertEquals("HTTP", result.fingerprint?.service)
            assertTrue(result.fingerprint?.banner.orEmpty().contains("200 OK"))
            assertEquals("Gmap-Test-Server", result.fingerprint?.serverHeader)
        }
    }
}
