package com.dsl.gmap.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.TimeUnit

data class DiscoveredHost(
    val address: String,
    val openPorts: List<Int>,
    val latencyMs: Long
)

object Ipv4Subnet {
    fun hostAddresses(cidr: String): List<Inet4Address> {
        val parts = cidr.split("/")
        require(parts.size == 2) { "Invalid IPv4 subnet: $cidr" }

        val localAddress = InetAddress.getByName(parts[0]) as? Inet4Address
            ?: throw IllegalArgumentException("IPv4 discovery requires an IPv4 address.")
        val prefix = parts[1].toIntOrNull()
            ?: throw IllegalArgumentException("Invalid subnet prefix.")

        require(prefix in 22..30) {
            "Subnet /$prefix is outside the supported discovery range (/22 to /30)."
        }

        val raw = localAddress.address
        val ipValue = raw.fold(0L) { acc, byte -> (acc shl 8) or (byte.toLong() and 0xffL) }
        val hostBits = 32 - prefix
        val hostMask = (1L shl hostBits) - 1L
        val network = ipValue and (hostMask.inv() and 0xffffffffL)
        val broadcast = network or hostMask

        return (network + 1 until broadcast)
            .filter { it != ipValue }
            .map { value ->
                val bytes = ByteArray(4) { index ->
                    (value shr (24 - index * 8)).toByte()
                }
                InetAddress.getByAddress(bytes) as Inet4Address
            }
    }
}

class NetworkDiscoveryScanner {
    suspend fun scan(
        localCidr: String,
        timeoutMs: Int = 300,
        onProgress: suspend (completed: Int, total: Int) -> Unit = { _, _ -> }
    ): List<DiscoveredHost> {
        require(timeoutMs in 100..2000) { "Timeout must be between 100 and 2000 ms." }
        val targets = Ipv4Subnet.hostAddresses(localCidr)
        val semaphore = Semaphore(MAX_CONCURRENT_HOSTS)
        var completed = 0

        return coroutineScope {
            targets.map { target ->
                async(Dispatchers.IO) {
                    semaphore.withPermit {
                        val host = probe(target, timeoutMs)
                        val done = synchronized(this@coroutineScope) {
                            completed += 1
                            completed
                        }
                        withContext(Dispatchers.Main.immediate) {
                            onProgress(done, targets.size)
                        }
                        host
                    }
                }
            }.awaitAll()
                .filterNotNull()
                .sortedBy { addressToLong(it.address) }
        }
    }

    private fun probe(address: Inet4Address, timeoutMs: Int): DiscoveredHost? {
        val openPorts = mutableListOf<Int>()
        var fastestLatency = Long.MAX_VALUE

        for (port in COMMON_TCP_PORTS) {
            val started = System.nanoTime()
            try {
                Socket().use { socket ->
                    socket.tcpNoDelay = true
                    socket.connect(InetSocketAddress(address, port), timeoutMs)
                }
                val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
                fastestLatency = minOf(fastestLatency, elapsed)
                openPorts += port
            } catch (_: Exception) {
                // A closed or filtered port is not a responsive-host finding.
            }
        }

        if (openPorts.isEmpty()) return null
        return DiscoveredHost(
            address = address.hostAddress ?: address.toString(),
            openPorts = openPorts,
            latencyMs = if (fastestLatency == Long.MAX_VALUE) 0L else fastestLatency
        )
    }

    private fun addressToLong(address: String): Long {
        val bytes = (InetAddress.getByName(address) as Inet4Address).address
        return bytes.fold(0L) { acc, byte -> (acc shl 8) or (byte.toLong() and 0xffL) }
    }

    companion object {
        const val MAX_CONCURRENT_HOSTS = 64
        val COMMON_TCP_PORTS = listOf(22, 80, 443, 445, 8080, 3389)
    }
}
