package com.dsl.gmap

import com.dsl.gmap.web.FindingSeverity
import com.dsl.gmap.web.WebAuditEngine
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets

class WebAuditEngineTest {
    @Test
    fun checksHttpHeadersWithoutDownloadingPageBody() = runBlocking {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val worker = Thread {
                server.accept().use { socket ->
                    socket.soTimeout = 3000
                    val reader = BufferedReader(InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII))
                    while (reader.readLine()?.isNotEmpty() == true) Unit
                    val response = listOf(
                        "HTTP/1.1 200 OK",
                        "Server: TestServer/1.0",
                        "Content-Type: text/html",
                        "Content-Length: 0",
                        "Connection: close"
                    ).joinToString("\r\n", postfix = "\r\n\r\n")
                    socket.getOutputStream().write(response.toByteArray(StandardCharsets.US_ASCII))
                    socket.getOutputStream().flush()
                }
            }
            worker.start()

            val result = WebAuditEngine().scan("http://127.0.0.1:${server.localPort}/")
            worker.join(3000)

            assertEquals(200, result.httpStatus)
            assertEquals("127.0.0.1", result.host)
            assertTrue(result.findings.any { it.title == "HTTP without TLS" && it.severity == FindingSeverity.MEDIUM })
            assertTrue(result.findings.any { it.title == "Content Security Policy missing" })
            assertTrue(result.findings.any { it.title == "Server header disclosed" })
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsUnsupportedSchemes() {
        runBlocking {
            WebAuditEngine().scan("ftp://example.com")
            Unit
        }
    }
}
