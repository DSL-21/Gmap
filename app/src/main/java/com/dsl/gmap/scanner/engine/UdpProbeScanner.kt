package com.dsl.gmap.scanner.engine

import com.dsl.gmap.scanner.model.UdpPortScanResult
import com.dsl.gmap.scanner.model.UdpPortState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.PortUnreachableException
import java.net.SocketException
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Rootless UDP probing using ordinary DatagramSocket APIs.
 *
 * A received datagram confirms an open UDP service. An ICMP port-unreachable
 * surfaced by Android is classified CLOSED. A silent probe remains OPEN_FILTERED:
 * absence of a UDP response cannot distinguish an open service from packet filtering.
 */
class UdpProbeScanner {
    suspend fun scan(
        address: InetAddress,
        startPort: Int,
        endPort: Int,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS,
        onProgress: (completed: Int, total: Int, latest: UdpPortScanResult) -> Unit = { _, _, _ -> }
    ): List<UdpPortScanResult> = withContext(Dispatchers.IO) {
        require(startPort in 1..65535) { "Start port must be between 1 and 65535." }
        require(endPort in startPort..65535) { "End port must be between start port and 65535." }
        require(endPort - startPort + 1 <= MAX_PORTS_PER_SCAN) {
            "UDP scans are limited to $MAX_PORTS_PER_SCAN ports per run."
        }
        require(timeoutMs in 100..5000) { "UDP timeout must be between 100 and 5000 ms." }

        val ports = startPort..endPort
        val semaphore = Semaphore(MAX_CONCURRENT_PROBES)
        val completed = AtomicInteger(0)

        coroutineScope {
            ports.map { port ->
                async(Dispatchers.IO) {
                    semaphore.withPermit {
                        val result = probe(address, port, timeoutMs)
                        val done = completed.incrementAndGet()
                        onProgress(done, ports.count(), result)
                        result
                    }
                }
            }.awaitAll().sortedBy { it.port }
        }
    }

    private fun probe(address: InetAddress, port: Int, timeoutMs: Int): UdpPortScanResult {
        val payload = payloadFor(port)
        val startedAt = System.nanoTime()

        return try {
            DatagramSocket().use { socket ->
                socket.soTimeout = timeoutMs
                socket.connect(InetSocketAddress(address, port))
                val outbound = DatagramPacket(payload, payload.size, address, port)
                socket.send(outbound)

                val buffer = ByteArray(MAX_RESPONSE_BYTES)
                val inbound = DatagramPacket(buffer, buffer.size)
                socket.receive(inbound)

                UdpPortScanResult(
                    port = port,
                    state = UdpPortState.OPEN,
                    latencyMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt),
                    responseBytes = inbound.length,
                    serviceHint = serviceHint(port),
                    detail = if (inbound.length > 0) "UDP response received." else "Empty UDP response received."
                )
            }
        } catch (_: SocketTimeoutException) {
            UdpPortScanResult(
                port = port,
                state = UdpPortState.OPEN_FILTERED,
                latencyMs = timeoutMs.toLong(),
                serviceHint = serviceHint(port),
                detail = "No UDP response before timeout; the port may be open or filtered."
            )
        } catch (_: PortUnreachableException) {
            UdpPortScanResult(
                port = port,
                state = UdpPortState.CLOSED,
                latencyMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt),
                serviceHint = serviceHint(port),
                detail = "ICMP port-unreachable was reported by the network stack."
            )
        } catch (exception: SocketException) {
            val message = exception.message.orEmpty()
            if (message.contains("port unreachable", ignoreCase = true) ||
                message.contains("econnrefused", ignoreCase = true)
            ) {
                UdpPortScanResult(
                    port = port,
                    state = UdpPortState.CLOSED,
                    latencyMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt),
                    serviceHint = serviceHint(port),
                    detail = "The network stack reported the UDP destination as unreachable."
                )
            } else {
                UdpPortScanResult(
                    port = port,
                    state = UdpPortState.ERROR,
                    serviceHint = serviceHint(port),
                    detail = message.ifBlank { "UDP socket error." }
                )
            }
        } catch (exception: IOException) {
            UdpPortScanResult(
                port = port,
                state = UdpPortState.ERROR,
                serviceHint = serviceHint(port),
                detail = exception.message ?: "UDP I/O error."
            )
        } catch (exception: SecurityException) {
            UdpPortScanResult(
                port = port,
                state = UdpPortState.ERROR,
                serviceHint = serviceHint(port),
                detail = "The operating system denied the UDP operation."
            )
        }
    }

    private fun payloadFor(port: Int): ByteArray = when (port) {
        53 -> dnsAQuery()
        123 -> ntpClientRequest()
        1900 -> SSDP_DISCOVERY.toByteArray(StandardCharsets.US_ASCII)
        5353 -> mdnsServiceQuery()
        else -> ByteArray(0)
    }

    private fun dnsAQuery(): ByteArray {
        val name = byteArrayOf(
            7, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(),
            'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            3, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0
        )
        return byteArrayOf(
            0x47, 0x4d, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ) + name + byteArrayOf(0x00, 0x01, 0x00, 0x01)
    }

    private fun ntpClientRequest(): ByteArray =
        ByteArray(48).also { it[0] = 0x1b.toByte() }

    private fun mdnsServiceQuery(): ByteArray {
        val serviceName = byteArrayOf(
            9, '_'.code.toByte(), 's'.code.toByte(), 'e'.code.toByte(), 'r'.code.toByte(),
            'v'.code.toByte(), 'i'.code.toByte(), 'c'.code.toByte(), 'e'.code.toByte(), 's'.code.toByte(),
            7, '_'.code.toByte(), 'd'.code.toByte(), 'n'.code.toByte(), 's'.code.toByte(),
            '-'.code.toByte(), 's'.code.toByte(), 'd'.code.toByte(),
            4, '_'.code.toByte(), 'u'.code.toByte(), 'd'.code.toByte(), 'p'.code.toByte(),
            5, 'l'.code.toByte(), 'o'.code.toByte(), 'c'.code.toByte(), 'a'.code.toByte(), 'l'.code.toByte(),
            0
        )
        return byteArrayOf(0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
            serviceName + byteArrayOf(0, 12, 0, 1)
    }

    private fun serviceHint(port: Int): String? = when (port) {
        53 -> "DNS"
        67, 68 -> "DHCP"
        69 -> "TFTP"
        123 -> "NTP"
        137 -> "NetBIOS Name Service"
        161, 162 -> "SNMP"
        500, 4500 -> "IPsec / IKE"
        1900 -> "SSDP"
        5353 -> "mDNS"
        5355 -> "LLMNR"
        else -> null
    }

    companion object {
        const val DEFAULT_TIMEOUT_MS = 1000
        const val MAX_PORTS_PER_SCAN = 512
        const val MAX_CONCURRENT_PROBES = 48
        private const val MAX_RESPONSE_BYTES = 2048
        private val SSDP_DISCOVERY = listOf(
            "M-SEARCH * HTTP/1.1",
            "HOST: 239.255.255.250:1900",
            "MAN: \"ssdp:discover\"",
            "MX: 1",
            "ST: ssdp:all",
            "",
            ""
        ).joinToString("\r\n")
    }
}
