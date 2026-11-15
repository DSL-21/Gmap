package com.dsl.gmap.scanner.engine

import com.dsl.gmap.scanner.model.PortScanResult
import com.dsl.gmap.scanner.model.ServiceFingerprint
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Performs lightweight, read-only application-layer identification on TCP ports
 * already confirmed OPEN by the connect scanner.
 *
 * This is deliberately not a vulnerability exploit engine. Probes are limited
 * to greetings, HTTP HEAD, Redis PING and the PostgreSQL SSL negotiation byte.
 * A small worker pool avoids creating one coroutine per open port.
 */
class ServiceDetector(
    private val workerCount: Int = DEFAULT_WORKERS,
    private val httpPorts: Set<Int> = DEFAULT_HTTP_PORTS,
    private val tlsPorts: Set<Int> = DEFAULT_TLS_PORTS
) {
    suspend fun identify(
        address: InetAddress,
        originalTarget: String,
        openPorts: List<PortScanResult>,
        timeoutMs: Int
    ): List<PortScanResult> = coroutineScope {
        if (openPorts.isEmpty()) return@coroutineScope emptyList()

        val identified = arrayOfNulls<PortScanResult>(openPorts.size)
        val nextIndex = AtomicInteger(0)
        val workers = minOf(workerCount.coerceAtLeast(1), openPorts.size)

        List(workers) {
            async(Dispatchers.IO) {
                while (true) {
                    currentCoroutineContext().ensureActive()
                    val index = nextIndex.getAndIncrement()
                    if (index >= openPorts.size) break
                    identified[index] = identifyOne(
                        address = address,
                        originalTarget = originalTarget,
                        result = openPorts[index],
                        timeoutMs = timeoutMs
                    )
                }
            }
        }.awaitAll()

        identified.mapIndexed { index, result -> result ?: openPorts[index] }
    }

    private fun identifyOne(
        address: InetAddress,
        originalTarget: String,
        result: PortScanResult,
        timeoutMs: Int
    ): PortScanResult {
        return try {
            when (result.port) {
                22 -> identifyGreeting(address, result, timeoutMs, "SSH")
                21 -> identifyGreeting(address, result, timeoutMs, "FTP")
                25 -> identifyGreeting(address, result, timeoutMs, "SMTP")
                110 -> identifyGreeting(address, result, timeoutMs, "POP3")
                143 -> identifyGreeting(address, result, timeoutMs, "IMAP")
                5900 -> identifyGreeting(address, result, timeoutMs, "VNC")
                3306 -> identifyMysql(address, result, timeoutMs)
                in httpPorts -> identifyHttp(address, originalTarget, result, timeoutMs)
                in tlsPorts -> identifyTls(address, originalTarget, result, timeoutMs)
                5432 -> identifyPostgres(address, result, timeoutMs)
                6379 -> identifyRedis(address, result, timeoutMs)
                else -> result
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (exception: Exception) {
            // The TCP port remains OPEN even when an application-layer probe
            // is unsupported, silent, or rejects the identification request.
            result.copy(
                fingerprint = ServiceFingerprint(
                    service = result.serviceHint ?: "Unknown TCP service",
                    banner = "Service probe unavailable: ${safeMessage(exception)}"
                )
            )
        }
    }

    private fun identifyGreeting(
        address: InetAddress,
        result: PortScanResult,
        timeoutMs: Int,
        service: String
    ): PortScanResult {
        val banner = Socket().use { socket ->
            connect(socket, address, result.port, timeoutMs)
            readLine(socket, MAX_BANNER_BYTES)
        } ?: return result.copy(
            serviceHint = service,
            fingerprint = ServiceFingerprint(service = service, banner = "No greeting received.")
        )

        val cleaned = sanitize(banner)
        val detectedService = when {
            service == "SSH" && cleaned.startsWith("SSH-") -> "SSH"
            service == "FTP" && cleaned.startsWith("220") -> "FTP"
            service == "SMTP" && cleaned.startsWith("220") -> "SMTP"
            else -> service
        }
        return result.copy(
            serviceHint = detectedService,
            fingerprint = ServiceFingerprint(service = detectedService, banner = cleaned)
        )
    }

    private fun identifyHttp(
        address: InetAddress,
        originalTarget: String,
        result: PortScanResult,
        timeoutMs: Int
    ): PortScanResult {
        val response = Socket().use { socket ->
            connect(socket, address, result.port, timeoutMs)
            socket.soTimeout = timeoutMs.coerceIn(300, MAX_TIMEOUT_MS)
            val hostHeader = originalTarget.takeIf { it.isNotBlank() } ?: address.hostAddress.orEmpty()
            val request = "HEAD / HTTP/1.0\r\nHost: $hostHeader\r\nUser-Agent: Gmap-Scanner\r\nConnection: close\r\n\r\n"
            socket.getOutputStream().write(request.toByteArray(StandardCharsets.US_ASCII))
            socket.getOutputStream().flush()
            readHttpHeaders(socket)
        }

        val status = response.firstOrNull().orEmpty()
        val server = response.firstOrNull {
            it.startsWith("Server:", ignoreCase = true)
        }?.substringAfter(':')?.trim()?.take(200)
        val poweredBy = response.firstOrNull {
            it.startsWith("X-Powered-By:", ignoreCase = true)
        }?.substringAfter(':')?.trim()?.take(200)

        return result.copy(
            serviceHint = "HTTP",
            fingerprint = ServiceFingerprint(
                service = "HTTP",
                banner = status.ifBlank { "HTTP endpoint responded without a status line." },
                serverHeader = server,
                additionalInfo = poweredBy?.let { "X-Powered-By: $it" }
            )
        )
    }

    private fun identifyTls(
        address: InetAddress,
        originalTarget: String,
        result: PortScanResult,
        timeoutMs: Int
    ): PortScanResult {
        val host = originalTarget.takeIf { it.isNotBlank() } ?: address.hostAddress.orEmpty()
        val details = Socket().use { plain ->
            connect(plain, address, result.port, timeoutMs)
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            factory.createSocket(plain, host, result.port, true).use { ssl ->
                ssl.soTimeout = timeoutMs.coerceIn(300, MAX_TIMEOUT_MS)
                val parameters = ssl.sslParameters
                parameters.endpointIdentificationAlgorithm = "HTTPS"
                ssl.sslParameters = parameters
                ssl.startHandshake()

                val certificate = ssl.session.peerCertificates.firstOrNull() as? X509Certificate
                val hostHeader = originalTarget.takeIf { it.isNotBlank() } ?: address.hostAddress.orEmpty()
                val httpHeaders = try {
                    val request = "HEAD / HTTP/1.0\\r\\nHost: $hostHeader\\r\\nUser-Agent: Gmap-Scanner\\r\\nConnection: close\\r\\n\\r\\n"
                    ssl.getOutputStream().write(request.toByteArray(StandardCharsets.US_ASCII))
                    ssl.getOutputStream().flush()
                    readHttpHeaders(ssl)
                } catch (_: IOException) {
                    emptyList()
                }
                TlsDetails(
                    protocol = ssl.session.protocol,
                    cipher = ssl.session.cipherSuite,
                    subject = certificate?.subjectX500Principal?.name,
                    issuer = certificate?.issuerX500Principal?.name,
                    expiresAt = certificate?.notAfter?.time,
                    httpStatus = httpHeaders.firstOrNull(),
                    httpServer = httpHeaders.firstOrNull { it.startsWith("Server:", ignoreCase = true) }
                        ?.substringAfter(':')?.trim()?.take(200)
                )
            }
        }

        return result.copy(
            serviceHint = "HTTPS / TLS",
            fingerprint = ServiceFingerprint(
                service = "TLS",
                banner = details.httpStatus,
                serverHeader = details.httpServer,
                tlsVersion = details.protocol,
                cipherSuite = details.cipher,
                certificateSubject = details.subject,
                certificateIssuer = details.issuer,
                certificateExpiresAtEpochMs = details.expiresAt
            )
        )
    }

    private fun identifyMysql(
        address: InetAddress,
        result: PortScanResult,
        timeoutMs: Int
    ): PortScanResult {
        val banner = Socket().use { socket ->
            connect(socket, address, result.port, timeoutMs)
            socket.soTimeout = timeoutMs.coerceIn(300, MAX_TIMEOUT_MS)
            val packet = readMysqlGreeting(socket)
            if (packet.isEmpty() || packet[0].toInt() != 10) null
            else {
                val version = packet.copyOfRange(1, packet.size)
                    .takeWhile { it.toInt() != 0 }
                    .toByteArray()
                    .toString(StandardCharsets.US_ASCII)
                version.takeIf { it.isNotBlank() }
            }
        }

        return result.copy(
            serviceHint = "MySQL",
            fingerprint = ServiceFingerprint(
                service = "MySQL",
                banner = banner?.let { "Server version: $it" } ?: "MySQL greeting detected."
            )
        )
    }

    private fun identifyRedis(
        address: InetAddress,
        result: PortScanResult,
        timeoutMs: Int
    ): PortScanResult {
        val response = Socket().use { socket ->
            connect(socket, address, result.port, timeoutMs)
            socket.soTimeout = timeoutMs.coerceIn(300, MAX_TIMEOUT_MS)
            socket.getOutputStream().write(("*1\r\n" + "$" + "4\r\nPING\r\n").toByteArray(StandardCharsets.US_ASCII))
            socket.getOutputStream().flush()
            readLine(socket, MAX_BANNER_BYTES)
        }?.let(::sanitize)

        return result.copy(
            serviceHint = "Redis",
            fingerprint = ServiceFingerprint(
                service = "Redis",
                banner = response ?: "No PING response received."
            )
        )
    }

    private fun identifyPostgres(
        address: InetAddress,
        result: PortScanResult,
        timeoutMs: Int
    ): PortScanResult {
        val response = Socket().use { socket ->
            connect(socket, address, result.port, timeoutMs)
            socket.soTimeout = timeoutMs.coerceIn(300, MAX_TIMEOUT_MS)
            // PostgreSQL SSLRequest: length 8 followed by the protocol magic.
            socket.getOutputStream().write(byteArrayOf(0, 0, 0, 8, 4, 210.toByte(), 22, 47))
            socket.getOutputStream().flush()
            socket.getInputStream().read()
        }

        val banner = when (response) {
            'S'.code -> "PostgreSQL accepted TLS negotiation."
            'N'.code -> "PostgreSQL declined TLS negotiation."
            -1 -> "No PostgreSQL negotiation response."
            else -> "Unexpected negotiation response."
        }
        return result.copy(
            serviceHint = "PostgreSQL",
            fingerprint = ServiceFingerprint(service = "PostgreSQL", banner = banner)
        )
    }

    private fun connect(socket: Socket, address: InetAddress, port: Int, timeoutMs: Int) {
        val safeTimeout = timeoutMs.coerceIn(300, MAX_TIMEOUT_MS)
        socket.connect(InetSocketAddress(address, port), safeTimeout)
        socket.soTimeout = safeTimeout
    }

    private fun readLine(socket: Socket, maxBytes: Int): String? {
        val output = ByteArrayOutputStream()
        val input = socket.getInputStream()
        while (output.size() < maxBytes) {
            val value = input.read()
            if (value < 0 || value == '\n'.code) break
            if (value != '\r'.code) output.write(value)
        }
        return output.toString(StandardCharsets.UTF_8.name()).takeIf { it.isNotBlank() }
    }

    private fun readMysqlGreeting(socket: Socket): ByteArray {
        val input = socket.getInputStream()
        val header = ByteArray(4)
        readFully(input, header)
        val payloadLength = (header[0].toInt() and 0xff) or
            ((header[1].toInt() and 0xff) shl 8) or
            ((header[2].toInt() and 0xff) shl 16)
        if (payloadLength <= 0) return byteArrayOf()
        val payload = ByteArray(minOf(payloadLength, 252))
        readFully(input, payload)
        return payload
    }

    private fun readFully(input: java.io.InputStream, target: ByteArray) {
        var offset = 0
        while (offset < target.size) {
            val count = input.read(target, offset, target.size - offset)
            if (count < 0) throw IOException("Incomplete service greeting.")
            offset += count
        }
    }

    private fun readHttpHeaders(socket: Socket): List<String> {
        val input = socket.getInputStream()
        val headers = ArrayList<String>()
        var current = ByteArrayOutputStream()
        var totalBytes = 0
        while (totalBytes < MAX_HTTP_HEADER_BYTES && headers.size < MAX_HTTP_HEADERS) {
            val value = input.read()
            if (value < 0) break
            totalBytes++
            if (value == '\n'.code) {
                val line = current.toString(StandardCharsets.ISO_8859_1.name()).trim()
                if (line.isEmpty()) break
                headers += line
                current = ByteArrayOutputStream()
            } else if (value != '\r'.code) {
                current.write(value)
            }
        }
        return headers
    }

    private fun sanitize(value: String): String =
        value.filter { it == '\t' || it >= ' ' }.take(240)

    private fun safeMessage(exception: Exception): String =
        exception.message?.filter { it == '\t' || it >= ' ' }?.take(120) ?: exception.javaClass.simpleName

    private data class TlsDetails(
        val protocol: String,
        val cipher: String,
        val subject: String?,
        val issuer: String?,
        val expiresAt: Long?,
        val httpStatus: String?,
        val httpServer: String?
    )

    companion object {
        const val DEFAULT_WORKERS = 8
        private val DEFAULT_HTTP_PORTS = setOf(80, 8000, 8008, 8080, 8888)
        private val DEFAULT_TLS_PORTS = setOf(443, 8443, 9443)
        private const val MAX_TIMEOUT_MS = 4000
        private const val MAX_BANNER_BYTES = 512
        private const val MAX_HTTP_HEADER_BYTES = 4096
        private const val MAX_HTTP_HEADERS = 40
    }
}
