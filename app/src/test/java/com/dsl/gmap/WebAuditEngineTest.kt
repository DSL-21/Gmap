package com.dsl.gmap

import com.dsl.gmap.web.FindingSeverity
import com.dsl.gmap.web.WebAuditEngine
import com.dsl.gmap.web.WebHostResolver
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

class WebAuditEngineTest {

    @Test
    fun redactsCookieValuesAndDropsQueryParameters() = runBlocking {
        val secret = "SUPER_SECRET_SESSION_TOKEN"
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val requests = java.util.concurrent.CopyOnWriteArrayList<String>()
            val worker = Thread {
                repeat(7) {
                    server.accept().use { socket ->
                        socket.soTimeout = 3000
                        val request = readRequest(socket.getInputStream())
                        requests += request
                        respond(socket, 200, listOf("Set-Cookie: session=$secret; Path=/; Secure; HttpOnly; SameSite=Lax"))
                    }
                }
            }
            worker.start()
            val result = WebAuditEngine().scan("http://127.0.0.1:${server.localPort}/path?token=$secret")
            worker.join(4000)
            assertTrue(requests.isNotEmpty())
            assertTrue(requests.first().contains(" /path HTTP/"))
            assertTrue(requests.none { it.contains(secret) })
            assertTrue(!result.url.contains(secret))
            assertTrue(!result.finalUrl.contains(secret))
            assertTrue(result.responseHeaders.values.flatten().none { it.contains(secret) })
            assertTrue(result.findings.none { it.evidence.contains(secret) })
            assertTrue(result.responseHeaders.entries
                .filter { it.key.equals("Set-Cookie", ignoreCase = true) }
                .flatMap { it.value }
                .any { it.contains("<redacted>") && it.contains("HttpOnly") })
        }
    }

    @Test
    fun doesNotFollowSameHostRedirectToAnotherPort() = runBlocking {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { redirectTarget ->
            ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { origin ->
                val worker = Thread {
                    repeat(7) { index ->
                        origin.accept().use { socket ->
                            socket.soTimeout = 3000
                            readRequest(socket.getInputStream())
                            if (index == 0) {
                                respond(socket, 302, listOf("Location: http://127.0.0.1:${redirectTarget.localPort}/next"))
                            } else {
                                respond(socket, 404, emptyList())
                            }
                        }
                    }
                }
                worker.start()
                val result = WebAuditEngine().scan("http://127.0.0.1:${origin.localPort}/start")
                worker.join(4000)
                assertEquals(1, result.redirectChain.size)
                redirectTarget.soTimeout = 150
                val followed = runCatching { redirectTarget.accept() }.isSuccess
                assertTrue("Web audit followed a redirect to a different port", !followed)
            }
        }
    }

    @Test
    fun checksHttpHeadersAndResourcePathsWithoutDownloadingPageBody() = runBlocking {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val worker = Thread {
                repeat(7) {
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
            assertEquals(6, result.resources.size)
            assertEquals(1, result.redirectChain.size)
        }
    }

    @Test
    fun fallsBackToGetAndDetectsCredentialedCorsReflection() = runBlocking {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val worker = Thread {
                repeat(8) { index ->
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
                it.title == "Credentialed CORS origin reflection" && it.severity == FindingSeverity.MEDIUM
            })
        }
    }

    @Test
    fun identifiesExposedGitHeadMetadata() = runBlocking {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val worker = Thread {
                repeat(8) {
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
                repeat(8) { index ->
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


    @Test
    fun hostnameRequestsUseOnlyThePinnedDnsAnswer() = runBlocking {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val requests = java.util.concurrent.CopyOnWriteArrayList<String>()
            val worker = Thread {
                repeat(7) {
                    server.accept().use { socket ->
                        socket.soTimeout = 3000
                        requests += readRequest(socket.getInputStream())
                        respond(socket, 404, emptyList())
                    }
                }
            }
            worker.start()

            val resolverCalls = AtomicInteger()
            val pinnedAddress = InetAddress.getLoopbackAddress()
            val engine = WebAuditEngine(WebHostResolver { host ->
                assertEquals("pinned.test", host)
                resolverCalls.incrementAndGet()
                listOf(pinnedAddress)
            })
            val result = engine.scan("http://pinned.test:${server.localPort}/")
            worker.join(4000)

            assertEquals(1, resolverCalls.get())
            assertEquals(listOf(pinnedAddress.hostAddress), result.resolvedAddresses)
            assertEquals(7, result.requestCount)
            assertTrue(requests.first().contains("Host: pinned.test"))
            assertTrue(requests.size == 7)
        }
    }

    @Test
    fun keepsEncodedPathEscapesAndDropsInitialQuery() = runBlocking {
        val secret = "DO_NOT_SEND_QUERY_VALUE"
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val requests = java.util.concurrent.CopyOnWriteArrayList<String>()
            val worker = Thread {
                repeat(7) {
                    server.accept().use { socket ->
                        socket.soTimeout = 3000
                        requests += readRequest(socket.getInputStream())
                        respond(socket, 404, emptyList())
                    }
                }
            }
            worker.start()

            val result = WebAuditEngine().scan(
                "http://127.0.0.1:${server.localPort}/encoded%2Fsegment?token=$secret"
            )
            worker.join(4000)

            assertTrue(requests.first().contains(" /encoded%2Fsegment HTTP/"))
            assertTrue(requests.none { it.contains(secret) })
            assertTrue(!result.url.contains(secret))
        }
    }

    @Test
    fun stripsQueryFromSameHostRedirectBeforeFollowing() = runBlocking {
        val secret = "REDIRECT_QUERY_SECRET"
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val requests = java.util.concurrent.CopyOnWriteArrayList<String>()
            val worker = Thread {
                repeat(8) { index ->
                    server.accept().use { socket ->
                        socket.soTimeout = 3000
                        val request = readRequest(socket.getInputStream())
                        requests += request
                        if (index == 0) {
                            respond(socket, 302, listOf("Location: /next?token=$secret"))
                        } else {
                            respond(socket, if (index == 1) 200 else 404, emptyList())
                        }
                    }
                }
            }
            worker.start()

            val result = WebAuditEngine().scan("http://127.0.0.1:${server.localPort}/start")
            worker.join(4000)

            assertEquals(2, result.redirectChain.size)
            assertTrue(requests.any { it.contains(" /next HTTP/") })
            assertTrue(requests.none { it.contains(secret) })
            assertTrue(result.redirectChain.none { it.contains(secret) })
        }
    }

    @Test
    fun cancellingAuditCancelsTheActiveHttpCallPromptly() = runBlocking {
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { server ->
            val connected = CountDownLatch(1)
            val headersRead = CountDownLatch(1)
            val serverFailure = AtomicReference<Throwable?>()
            val scanFailure = AtomicReference<Throwable?>()
            val worker = Thread {
                try {
                    server.accept().use { socket ->
                        connected.countDown()
                        socket.soTimeout = 3000
                        val request = readRequest(socket.getInputStream())
                        if (request.isNotBlank()) headersRead.countDown()
                        Thread.sleep(5000)
                    }
                } catch (failure: Throwable) {
                    serverFailure.set(failure)
                }
            }
            worker.start()

            val job = async(kotlinx.coroutines.Dispatchers.IO) {
                WebAuditEngine().scan("http://127.0.0.1:${server.localPort}/slow")
            }
            job.invokeOnCompletion { failure ->
                if (failure != null) scanFailure.set(failure)
            }

            val connectionAccepted = connected.await(5, TimeUnit.SECONDS)
            val requestHeadersReceived = connectionAccepted &&
                headersRead.await(3, TimeUnit.SECONDS)
            if (!requestHeadersReceived) {
                val diagnostic = "Connection accepted=$connectionAccepted; " +
                    "serverFailure=${serverFailure.get()?.javaClass?.simpleName}: ${serverFailure.get()?.message}; " +
                    "scanFailure=${scanFailure.get()?.javaClass?.simpleName}: ${scanFailure.get()?.message}; " +
                    "scanCompleted=${job.isCompleted}"
                job.cancelAndJoin()
                assertTrue("The server did not receive a complete HTTP request. $diagnostic", requestHeadersReceived)
            }

            val started = System.nanoTime()
            job.cancelAndJoin()
            val elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)

            assertTrue("Cancellation took ${elapsedMs}ms", elapsedMs < 3500)
            worker.interrupt()
            worker.join(1000)
        }
    }

    @Test
    fun doesNotApplyHtmlDocumentHeaderChecksToJsonApis() = runBlocking {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val worker = Thread {
                repeat(7) {
                    server.accept().use { socket ->
                        socket.soTimeout = 3000
                        readRequest(socket.getInputStream())
                        respond(socket, 200, listOf("Content-Type: application/json"))
                    }
                }
            }
            worker.start()

            val result = WebAuditEngine().scan("http://127.0.0.1:" + server.localPort + "/api/status")
            worker.join(4000)

            assertTrue(result.findings.none {
                it.title in setOf(
                    "Content Security Policy missing",
                    "Clickjacking protection not detected",
                    "Referrer Policy not set",
                    "Permissions Policy not set",
                    "Cross-Origin-Opener-Policy not set"
                )
            })
        }
    }

    @Test
    fun unsafeInlineInStyleOnlyDirectiveDoesNotTriggerScriptCspFinding() = runBlocking {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val worker = Thread {
                repeat(7) {
                    server.accept().use { socket ->
                        socket.soTimeout = 3000
                        readRequest(socket.getInputStream())
                        respond(
                            socket,
                            200,
                            listOf(
                                "Content-Type: text/html; charset=utf-8",
                                "Content-Security-Policy: default-src 'self'; style-src 'unsafe-inline'"
                            )
                        )
                    }
                }
            }
            worker.start()

            val result = WebAuditEngine().scan("http://127.0.0.1:" + server.localPort + "/")
            worker.join(4000)

            assertTrue(result.findings.none {
                it.title == "CSP allows unsafe-inline"
            })
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
