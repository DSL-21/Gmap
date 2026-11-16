package com.dsl.gmap

import com.dsl.gmap.web.FindingSeverity
import com.dsl.gmap.web.WebAuditEngine
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets

class WebAuditEngineTest {
    @Test
    fun checksHttpHeadersAndResourcePathsWithoutDownloadingPageBody() = runBlocking {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val worker = Thread {
                repeat(5) {
                    server.accept().use { socket ->
                        socket.soTimeout = 3000
                        val request = readRequest(socket.getInputStream())
                        val path = request.substringAfter(" ").substringBefore(" ")
                        val status = if (path == "/.well-known/security.txt" || path == "/robots.txt" ||
                            path == "/openapi.json" || path == "/.git/HEAD"
                        ) 404 else 200
                        respond(socket, status, listOf("Server: TestServer/1.0", "Content-Type: text/html"))
                    }
                }
            }
            worker.start()

            val result = WebAuditEngine().scan("http://127.0.0.1:${server.localPort}/")
            worker.join(4000)

            assertEquals(200, result.httpStatus)
            assertEquals("127.0.0.1", result.host)
            assertTrue(result.findings.any { it.title == "HTTP without TLS" && it.severity == FindingSeverity.MEDIUM })
            assertTrue(result.findings.any { it.title == "Content Security Policy missing" })
            assertTrue(result.findings.any { it.title == "Server header disclosed" })
            assertEquals(4, result.resources.size)
            assertEquals(1, result.redirectChain.size)
        }
    }

    @Test
    fun fallsBackToGetAndDetectsCredentialedCorsReflection() = runBlocking {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val worker = Thread {
                repeat(6) { index ->
                    server.accept().use { socket ->
                        socket.soTimeout = 3000
                        val request = readRequest(socket.getInputStream())
                        val method = request.substringBefore(" ")
                        val headers = listOf(
                            "Access-Control-Allow-Origin: ${WebAuditEngine.TEST_ORIGIN}",
                            "Access-Control-Allow-Credentials: true"
                        )
                        val status = when {
                            index == 0 && method == "HEAD" -> 405
                            index == 1 && method == "GET" -> 200
                            else -> 404
                        }
                        respond(socket, status, headers)
                    }
                }
            }
            worker.start()

            val result = WebAuditEngine().scan("http://127.0.0.1:${server.localPort}/")
            worker.join(4000)

            assertTrue(result.usedGetFallback)
            assertEquals(200, result.httpStatus)
            assertTrue(result.findings.any {
                it.title == "Credentialed CORS origin reflection" && it.severity == FindingSeverity.HIGH
            })
        }
    }

    @Test
    fun identifiesExposedGitHeadMetadata() = runBlocking {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val worker = Thread {
                repeat(6) {
                    server.accept().use { socket ->
                        socket.soTimeout = 3000
                        val request = readRequest(socket.getInputStream())
                        val path = request.substringAfter(" ").substringBefore(" ")
                        val method = request.substringBefore(" ")
                        if (path == "/.git/HEAD" && method == "GET") {
                            respond(socket, 200, listOf("Content-Type: text/plain"), "ref: refs/heads/main\n")
                        } else {
                            respond(socket, if (path == "/.git/HEAD") 200 else 404, emptyList())
                        }
                    }
                }
            }
            worker.start()

            val result = WebAuditEngine().scan("http://127.0.0.1:${server.localPort}/")
            worker.join(4000)

            assertTrue(result.resources.any { it.path == "/.git/HEAD" && it.sensitiveExposure })
            assertTrue(result.findings.any {
                it.title == "Git repository metadata exposed" && it.severity == FindingSeverity.HIGH
            })
        }
    }

    @Test
    fun followsSameHostRedirects() = runBlocking {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val worker = Thread {
                repeat(6) { index ->
                    server.accept().use { socket ->
                        socket.soTimeout = 3000
                        val request = readRequest(socket.getInputStream())
                        val status = if (index == 0) 302 else if (index == 1) 200 else 404
                        val headers = if (index == 0) listOf("Location: /final") else emptyList()
                        respond(socket, status, headers)
                    }
                }
            }
            worker.start()

            val result = WebAuditEngine().scan("http://127.0.0.1:${server.localPort}/start")
            worker.join(4000)

            assertEquals(2, result.redirectChain.size)
            assertTrue(result.finalUrl.endsWith("/final"))
            assertEquals(200, result.httpStatus)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsUnsupportedSchemes() {
        runBlocking {
            WebAuditEngine().scan("ftp://example.com")
            Unit
        }
    }

    private fun readRequest(input: java.io.InputStream): String {
        val bytes = StringBuilder()
        var matched = 0
        while (matched < 4) {
            val value = input.read()
            if (value < 0) break
            bytes.append(value.toChar())
            matched = if (bytes.toString().endsWith("\r\n\r\n") || bytes.toString().endsWith("\n\n")) 4 else 0
        }
        return bytes.toString()
    }

    private fun respond(
        socket: java.net.Socket,
        status: Int,
        headers: List<String>,
        body: String = ""
    ) {
        val reason = when (status) {
            200 -> "OK"
            302 -> "Found"
            404 -> "Not Found"
            405 -> "Method Not Allowed"
            else -> "Response"
        }
        val bodyBytes = body.toByteArray(StandardCharsets.UTF_8)
        val allHeaders = headers.filterNot { it.startsWith("Content-Length:", ignoreCase = true) } +
            "Content-Length: ${bodyBytes.size}" +
            "Connection: close"
        val response = "HTTP/1.1 ${status} ${reason}\r\n" +
            allHeaders.joinToString("\r\n") +
            "\r\n\r\n" + body
        socket.getOutputStream().write(response.toByteArray(StandardCharsets.UTF_8))
        socket.getOutputStream().flush()
    }
}
