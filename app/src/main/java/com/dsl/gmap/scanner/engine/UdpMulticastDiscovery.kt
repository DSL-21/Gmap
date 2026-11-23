package com.dsl.gmap.scanner.engine

import android.content.Context
import android.net.wifi.WifiManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets

data class UdpDiscoveryResult(
    val protocol: String,
    val address: String,
    val port: Int,
    val detail: String,
    val responseBytes: Int
)

data class UdpDiscoveryReport(
    val responders: List<UdpDiscoveryResult>,
    val warnings: List<String>
)

/**
 * LAN-only multicast discovery. Kept separate from UDP port scanning because
 * SSDP and mDNS use link-local multicast rather than ordinary unicast probes.
 */
class UdpMulticastDiscovery {
    suspend fun discover(
        context: Context,
        interfaceName: String,
        listenWindowMs: Int = DEFAULT_LISTEN_WINDOW_MS
    ): UdpDiscoveryReport = withContext(Dispatchers.IO) {
        require(interfaceName.isNotBlank()) { "No active network interface is available." }
        require(listenWindowMs in 500..5000) { "Discovery window must be between 500 and 5000 ms." }

        val networkInterface = NetworkInterface.getByName(interfaceName)
            ?: throw IllegalArgumentException("The active network interface could not be found.")
        require(networkInterface.isUp && networkInterface.supportsMulticast()) {
            "The active network interface does not support multicast discovery."
        }

        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        val multicastLock = wifiManager?.createMulticastLock("gmap-udp-multicast-discovery")
        val responders = mutableListOf<UdpDiscoveryResult>()
        val warnings = mutableListOf<String>()

        try {
            if (multicastLock != null && !multicastLock.isHeld) {
                multicastLock.setReferenceCounted(false)
                multicastLock.acquire()
            }

            try {
                responders.addAll(discoverSsdp(networkInterface, listenWindowMs))
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (exception: Exception) {
                warnings.add("SSDP discovery: " + (exception.message ?: exception.javaClass.simpleName))
            }

            try {
                responders.addAll(discoverMdns(networkInterface, listenWindowMs))
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (exception: Exception) {
                warnings.add("mDNS discovery: " + (exception.message ?: exception.javaClass.simpleName))
            }

            UdpDiscoveryReport(
                responders = responders.distinctBy { it.protocol + ":" + it.address + ":" + it.detail },
                warnings = warnings
            )
        } finally {
            if (multicastLock?.isHeld == true) {
                runCatching { multicastLock.release() }
            }
        }
    }

    private suspend fun discoverSsdp(
        networkInterface: NetworkInterface,
        listenWindowMs: Int
    ): List<UdpDiscoveryResult> {
        val group = InetAddress.getByName(SSDP_GROUP)
        val found = mutableListOf<UdpDiscoveryResult>()
        MulticastSocket(null).use { socket ->
            socket.reuseAddress = true
            socket.bind(InetSocketAddress(0))
            socket.networkInterface = networkInterface
            socket.timeToLive = 2
            socket.soTimeout = RECEIVE_SLICE_MS

            val request = SSDP_M_SEARCH.toByteArray(StandardCharsets.US_ASCII)
            socket.send(DatagramPacket(request, request.size, group, SSDP_PORT))

            val deadline = System.nanoTime() + listenWindowMs * 1_000_000L
            while (System.nanoTime() < deadline && found.size < MAX_RESPONDERS) {
                currentCoroutineContext().ensureActive()
                val buffer = ByteArray(MAX_PACKET_BYTES)
                val packet = DatagramPacket(buffer, buffer.size)
                try {
                    socket.receive(packet)
                    val text = String(packet.data, packet.offset, packet.length, StandardCharsets.US_ASCII)
                    if (
                        text.startsWith("HTTP/1.1 200", ignoreCase = true) ||
                        text.startsWith("HTTP/1.0 200", ignoreCase = true)
                    ) {
                        val headers = parseHeaders(text)
                        val details = listOfNotNull(
                            headers["st"]?.let { "ST=" + it.take(100) },
                            headers["server"]?.let { "SERVER=" + it.take(120) },
                            headers["usn"]?.let { "USN=" + it.take(120) }
                        ).joinToString(" · ").ifBlank { "SSDP response received." }
                        found.add(
                            UdpDiscoveryResult(
                                protocol = "SSDP",
                                address = packet.address.hostAddress ?: packet.address.toString(),
                                port = packet.port,
                                detail = details,
                                responseBytes = packet.length
                            )
                        )
                    }
                } catch (_: SocketTimeoutException) {
                    // Poll periodically so coroutine cancellation stays responsive.
                }
            }
        }
        return found
    }

    private suspend fun discoverMdns(
        networkInterface: NetworkInterface,
        listenWindowMs: Int
    ): List<UdpDiscoveryResult> {
        val group = InetAddress.getByName(MDNS_GROUP)
        val endpoint = InetSocketAddress(group, MDNS_PORT)
        val found = mutableListOf<UdpDiscoveryResult>()
        MulticastSocket(null).use { socket ->
            socket.reuseAddress = true
            socket.bind(InetSocketAddress(MDNS_PORT))
            socket.networkInterface = networkInterface
            socket.timeToLive = 255
            socket.soTimeout = RECEIVE_SLICE_MS
            socket.joinGroup(endpoint, networkInterface)

            try {
                val query = UdpProbeCatalog.buildMdnsServiceDiscoveryQuery()
                socket.send(DatagramPacket(query, query.size, group, MDNS_PORT))

                val deadline = System.nanoTime() + listenWindowMs * 1_000_000L
                while (System.nanoTime() < deadline && found.size < MAX_RESPONDERS) {
                    currentCoroutineContext().ensureActive()
                    val buffer = ByteArray(MAX_PACKET_BYTES)
                    val packet = DatagramPacket(buffer, buffer.size)
                    try {
                        socket.receive(packet)
                        if (isMdnsResponse(packet.data, packet.offset, packet.length)) {
                            val answers = unsignedShort(packet.data, packet.offset + 6)
                            val authority = unsignedShort(packet.data, packet.offset + 8)
                            val additional = unsignedShort(packet.data, packet.offset + 10)
                            found.add(
                                UdpDiscoveryResult(
                                    protocol = "mDNS",
                                    address = packet.address.hostAddress ?: packet.address.toString(),
                                    port = packet.port,
                                    detail = "DNS-SD multicast response: " + answers + " answer(s), " +
                                        authority + " authority and " + additional + " additional record(s).",
                                    responseBytes = packet.length
                                )
                            )
                        }
                    } catch (_: SocketTimeoutException) {
                        // Poll periodically so coroutine cancellation stays responsive.
                    }
                }
            } finally {
                runCatching { socket.leaveGroup(endpoint, networkInterface) }
            }
        }
        return found
    }

    private fun parseHeaders(response: String): Map<String, String> =
        response.lineSequence().drop(1).mapNotNull { line ->
            val split = line.indexOf(':')
            if (split <= 0) null
            else line.substring(0, split).trim().lowercase() to line.substring(split + 1).trim()
        }.toMap()

    private fun isMdnsResponse(bytes: ByteArray, offset: Int, length: Int): Boolean {
        if (length < 12) return false
        val flags = unsignedShort(bytes, offset + 2)
        return (flags and 0x8000) != 0
    }

    private fun unsignedShort(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    companion object {
        const val DEFAULT_LISTEN_WINDOW_MS = 1500
        private const val RECEIVE_SLICE_MS = 200
        private const val MAX_PACKET_BYTES = 4096
        private const val MAX_RESPONDERS = 64
        private const val SSDP_GROUP = "239.255.255.250"
        private const val SSDP_PORT = 1900
        private const val MDNS_GROUP = "224.0.0.251"
        private const val MDNS_PORT = 5353
        private val SSDP_M_SEARCH = listOf(
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
