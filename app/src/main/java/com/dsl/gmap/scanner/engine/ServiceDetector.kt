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
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicInteger
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
    private val tlsPorts: Set<Int> = DEFAULT_TLS_PORTS,
    private val smbPorts: Set<Int> = DEFAULT_SMB_PORTS,
    private val rdpPorts: Set<Int> = DEFAULT_RDP_PORTS
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
            val identified = when (result.port) {
                22 -> identifyGreeting(address, result, timeoutMs, "SSH")
                21 -> identifyGreeting(address, result, timeoutMs, "FTP")
                23 -> identifyGreeting(address, result, timeoutMs, "Telnet")
                25, 587 -> identifyGreeting(address, result, timeoutMs, "SMTP")
                110 -> identifyGreeting(address, result, timeoutMs, "POP3")
                143 -> identifyGreeting(address, result, timeoutMs, "IMAP")
                465, 990, 993, 995 -> identifyTls(address, originalTarget, result, timeoutMs)
                5900 -> identifyVnc(address, result, timeoutMs)
                in smbPorts -> identifySmb(address, result, timeoutMs)
                in rdpPorts -> identifyRdp(address, result, timeoutMs)
                3306 -> identifyMysql(address, result, timeoutMs)
                in httpPorts -> identifyHttp(address, originalTarget, result, timeoutMs)
                in tlsPorts -> identifyTls(address, originalTarget, result, timeoutMs)
                5432 -> identifyPostgres(address, result, timeoutMs)
                6379 -> identifyRedis(address, result, timeoutMs)
                else -> result.copy(
                    serviceHint = result.serviceHint ?: WELL_KNOWN_TCP_SERVICES[result.port]
                )
            }
            val fingerprint = identified.fingerprint
            if (fingerprint == null) identified
            else identified.copy(
                fingerprint = fingerprint.copy(
                    software = SoftwareFingerprintParser.identify(fingerprint)
                )
            )
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
            (factory.createSocket(plain, host, result.port, true) as SSLSocket).use { ssl ->
                ssl.soTimeout = timeoutMs.coerceIn(300, MAX_TIMEOUT_MS)
                val parameters = ssl.sslParameters
                parameters.endpointIdentificationAlgorithm = "HTTPS"
                ssl.sslParameters = parameters
                ssl.startHandshake()

                val certificate = ssl.session.peerCertificates.firstOrNull() as? X509Certificate
                val hostHeader = originalTarget.takeIf { it.isNotBlank() } ?: address.hostAddress.orEmpty()
                val httpHeaders = try {
                    val request = "HEAD / HTTP/1.0\r\nHost: $hostHeader\r\nUser-Agent: Gmap-Scanner\r\nConnection: close\r\n\r\n"
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

    private fun identifySmb(
        address: InetAddress,
        result: PortScanResult,
        timeoutMs: Int
    ): PortScanResult {
        val details = Socket().use { socket ->
            connect(socket, address, result.port, timeoutMs)
            val request = smb2NegotiateRequest()
            socket.getOutputStream().write(request)
            socket.getOutputStream().flush()

            val input = socket.getInputStream()
            val netbios = ByteArray(4)
            readFully(input, netbios)
            val payloadLength = ((netbios[1].toInt() and 0xff) shl 16) or
                ((netbios[2].toInt() and 0xff) shl 8) or
                (netbios[3].toInt() and 0xff)
            if (payloadLength !in MIN_SMB_RESPONSE_BYTES..MAX_SMB_RESPONSE_BYTES) {
                throw IOException("Unexpected SMB response length.")
            }

            val packet = ByteArray(payloadLength + 4)
            netbios.copyInto(packet, 0)
            readFully(input, packet, 4, payloadLength)
            parseSmb2NegotiateResponse(packet)
        }

        val service = "SMB"
        val dialect = details.dialect ?: "SMB negotiation response"
        val signing = when {
            details.securityMode and SMB_SIGNING_REQUIRED != 0 -> "required"
            details.securityMode and SMB_SIGNING_ENABLED != 0 -> "supported"
            else -> "not advertised"
        }
        return result.copy(
            serviceHint = service,
            fingerprint = ServiceFingerprint(
                service = service,
                banner = "SMB2 negotiate response",
                additionalInfo = "Dialect: $dialect · Message signing: $signing"
            )
        )
    }

    private fun smb2NegotiateRequest(): ByteArray {
        val dialects = shortArrayOf(
            SMB_DIALECT_202,
            SMB_DIALECT_210,
            SMB_DIALECT_300,
            SMB_DIALECT_302
        )
        val payloadLength = SMB2_HEADER_BYTES + SMB2_NEGOTIATE_FIXED_BYTES + dialects.size * 2
        val packet = ByteBuffer.allocate(payloadLength + NETBIOS_HEADER_BYTES)
            .order(ByteOrder.BIG_ENDIAN)

        packet.put(0)
        packet.put(((payloadLength shr 16) and 0xff).toByte())
        packet.put(((payloadLength shr 8) and 0xff).toByte())
        packet.put((payloadLength and 0xff).toByte())

        // SMB2 header, with a NEGOTIATE command and no session state.
        packet.put(SMB2_PROTOCOL_ID)
        packet.order(ByteOrder.LITTLE_ENDIAN)
        packet.putShort(SMB2_HEADER_BYTES.toShort())
        packet.putShort(0)
        packet.putInt(0)
        packet.putShort(0) // NEGOTIATE
        packet.putShort(1)
        packet.putInt(0)
        packet.putInt(0)
        packet.putLong(1)
        packet.putInt(0)
        packet.putInt(0)
        packet.putLong(0)
        packet.put(ByteArray(16))

        // SMB2 NEGOTIATE request body (36 bytes) followed by dialects.
        packet.putShort(36)
        packet.putShort(dialects.size.toShort())
        packet.putShort(SMB_SIGNING_ENABLED.toShort())
        packet.putShort(0)
        packet.putInt(0)
        packet.put(SMB_CLIENT_GUID)
        packet.putInt(0)
        packet.putShort(0)
        packet.putShort(0)
        dialects.forEach(packet::putShort)
        return packet.array()
    }

    private fun parseSmb2NegotiateResponse(packet: ByteArray): Smb2Details {
        if (packet.size < NETBIOS_HEADER_BYTES + SMB2_HEADER_BYTES + 6 ||
            packet[4] != 0xfe.toByte() ||
            packet[5] != 'S'.code.toByte() ||
            packet[6] != 'M'.code.toByte() ||
            packet[7] != 'B'.code.toByte()
        ) {
            throw IOException("The endpoint did not return an SMB2 negotiate response.")
        }

        val buffer = ByteBuffer.wrap(packet).order(ByteOrder.LITTLE_ENDIAN)
        val status = buffer.getInt(NETBIOS_HEADER_BYTES + SMB2_STATUS_OFFSET)
        if (status != 0) throw IOException("SMB negotiate returned status 0x" + status.toUInt().toString(16))

        val securityMode = buffer.getShort(NETBIOS_HEADER_BYTES + SMB2_HEADER_BYTES + 2)
            .toInt() and 0xffff
        val dialectCode = buffer.getShort(NETBIOS_HEADER_BYTES + SMB2_HEADER_BYTES + 4)
            .toInt() and 0xffff
        val dialect = when (dialectCode) {
            SMB_DIALECT_202.toInt() -> "2.0.2"
            SMB_DIALECT_210.toInt() -> "2.1"
            SMB_DIALECT_300.toInt() -> "3.0"
            SMB_DIALECT_302.toInt() -> "3.0.2"
            0x0311 -> "3.1.1"
            else -> "Unknown (0x" + dialectCode.toString(16) + ")"
        }
        return Smb2Details(dialect, securityMode)
    }

    private fun identifyRdp(
        address: InetAddress,
        result: PortScanResult,
        timeoutMs: Int
    ): PortScanResult {
        val response = Socket().use { socket ->
            connect(socket, address, result.port, timeoutMs)
            socket.getOutputStream().write(RDP_CONNECTION_REQUEST)
            socket.getOutputStream().flush()

            val input = socket.getInputStream()
            val header = ByteArray(4)
            readFully(input, header)
            val packetLength = ((header[2].toInt() and 0xff) shl 8) or
                (header[3].toInt() and 0xff)
            if (packetLength !in 11..MAX_RDP_RESPONSE_BYTES) {
                throw IOException("Unexpected RDP negotiation response length.")
            }
            val packet = ByteArray(packetLength)
            header.copyInto(packet, 0)
            readFully(input, packet, 4, packetLength - 4)
            packet
        }

        val info = if (response.size >= 19 && response[11] == RDP_NEGOTIATION_RESPONSE) {
            val selectedProtocol = ByteBuffer.wrap(response, 15, 4)
                .order(ByteOrder.LITTLE_ENDIAN).int
            when (selectedProtocol) {
                0 -> "Standard RDP security"
                1 -> "TLS security"
                2 -> "CredSSP / Network Level Authentication"
                4 -> "RDSTLS"
                8 -> "CredSSP Extended"
                else -> "Unknown protocol ($selectedProtocol)"
            }
        } else if (response.size >= 15 && response[11] == RDP_NEGOTIATION_FAILURE) {
            "Negotiation refused (code " + (response[15].toInt() and 0xff) + ")"
        } else {
            "RDP endpoint responded with an unrecognized negotiation packet."
        }

        return result.copy(
            serviceHint = "RDP",
            fingerprint = ServiceFingerprint(
                service = "RDP",
                banner = "Remote Desktop Protocol negotiation",
                additionalInfo = info
            )
        )
    }

    private fun identifyVnc(
        address: InetAddress,
        result: PortScanResult,
        timeoutMs: Int
    ): PortScanResult {
        val banner = Socket().use { socket ->
            connect(socket, address, result.port, timeoutMs)
            val greeting = ByteArray(12)
            readFully(socket.getInputStream(), greeting)
            sanitize(greeting.toString(StandardCharsets.US_ASCII))
        }
        val isVnc = banner.startsWith("RFB ")
        val service = if (isVnc) "VNC" else result.serviceHint ?: "Unknown TCP service"
        return result.copy(
            serviceHint = service,
            fingerprint = ServiceFingerprint(
                service = service,
                banner = banner
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
        readFully(input, target, 0, target.size)
    }

    private fun readFully(input: java.io.InputStream, target: ByteArray, start: Int, length: Int) {
        var offset = start
        val end = start + length
        while (offset < end) {
            val count = input.read(target, offset, end - offset)
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

    private data class Smb2Details(
        val dialect: String?,
        val securityMode: Int
    )

    companion object {
        const val DEFAULT_WORKERS = 8
        private val DEFAULT_HTTP_PORTS = setOf(80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8880, 8888, 9000)
        private val DEFAULT_TLS_PORTS = setOf(443, 465, 990, 993, 995, 5001, 6443, 8443, 9443, 10443)
        private val WELL_KNOWN_TCP_SERVICES = mapOf(
            20 to "FTP data", 21 to "FTP", 22 to "SSH", 23 to "Telnet",
            25 to "SMTP", 53 to "DNS", 80 to "HTTP", 88 to "Kerberos",
            110 to "POP3", 111 to "RPCbind", 135 to "MS RPC", 139 to "NetBIOS",
            143 to "IMAP", 179 to "BGP", 389 to "LDAP", 443 to "HTTPS",
            445 to "SMB", 465 to "SMTPS", 500 to "IPsec/IKE", 515 to "LPD",
            548 to "AFP", 554 to "RTSP", 587 to "SMTP submission", 631 to "IPP",
            636 to "LDAPS", 873 to "rsync", 902 to "VMware", 990 to "FTPS",
            993 to "IMAPS", 995 to "POP3S", 1080 to "SOCKS proxy", 1194 to "OpenVPN",
            1433 to "Microsoft SQL Server", 1521 to "Oracle DB", 1723 to "PPTP",
            1883 to "MQTT", 1900 to "SSDP", 2049 to "NFS", 2375 to "Docker API",
            2376 to "Docker API TLS", 3000 to "HTTP application", 3306 to "MySQL",
            3389 to "RDP", 3478 to "STUN", 3690 to "Subversion", 5000 to "HTTP/API",
            5001 to "HTTPS/API", 5060 to "SIP", 5432 to "PostgreSQL", 5672 to "AMQP",
            5900 to "VNC", 5985 to "WinRM", 5986 to "WinRM HTTPS", 6379 to "Redis",
            6443 to "Kubernetes API", 6667 to "IRC", 7001 to "WebLogic",
            8000 to "HTTP alternate", 8008 to "HTTP alternate", 8080 to "HTTP proxy",
            8081 to "HTTP alternate", 8443 to "HTTPS alternate", 8888 to "HTTP alternate",
            9000 to "HTTP/application", 9042 to "Cassandra", 9092 to "Kafka",
            9200 to "Elasticsearch", 9300 to "Elasticsearch transport", 9418 to "Git",
            10000 to "Webmin", 11211 to "Memcached", 27017 to "MongoDB"
        )
        private val DEFAULT_SMB_PORTS = setOf(445)
        private val DEFAULT_RDP_PORTS = setOf(3389)
        private const val NETBIOS_HEADER_BYTES = 4
        private const val SMB2_HEADER_BYTES = 64
        private const val SMB2_NEGOTIATE_FIXED_BYTES = 36
        private const val SMB2_STATUS_OFFSET = 8
        private const val MIN_SMB_RESPONSE_BYTES = 70
        private const val MAX_SMB_RESPONSE_BYTES = 4096
        private const val SMB_SIGNING_ENABLED = 0x0001
        private const val SMB_SIGNING_REQUIRED = 0x0002
        private const val SMB_DIALECT_202: Short = 0x0202
        private const val SMB_DIALECT_210: Short = 0x0210
        private const val SMB_DIALECT_300: Short = 0x0300
        private const val SMB_DIALECT_302: Short = 0x0302
        private val SMB2_PROTOCOL_ID = byteArrayOf(0xfe.toByte(), 0x53, 0x4d, 0x42)
        private val SMB_CLIENT_GUID = byteArrayOf(
            0x47, 0x4d, 0x41, 0x50, 0x2d, 0x53, 0x43, 0x41,
            0x4e, 0x4e, 0x45, 0x52, 0x2d, 0x30, 0x30, 0x31
        )
        private val RDP_CONNECTION_REQUEST = byteArrayOf(
            0x03, 0x00, 0x00, 0x13,
            0x0e, 0xe0.toByte(), 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00
        )
        private const val RDP_NEGOTIATION_RESPONSE: Byte = 0x02
        private const val RDP_NEGOTIATION_FAILURE: Byte = 0x03
        private const val MAX_RDP_RESPONSE_BYTES = 4096
        private const val MAX_TIMEOUT_MS = 4000
        private const val MAX_BANNER_BYTES = 512
        private const val MAX_HTTP_HEADER_BYTES = 4096
        private const val MAX_HTTP_HEADERS = 40
    }
}
