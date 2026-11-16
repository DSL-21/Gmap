package com.dsl.gmap.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.net.ConnectException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit

data class DiscoveredHost(
    val address: String,
    val openPorts: List<Int>,
    val latencyMs: Long,
    val likelyRole: String = "Unknown device"
)

object Ipv4Subnet {
    fun hostAddresses(cidr: String): List<Inet4Address> {
        val parts = cidr.trim().split("/")
        require(parts.size == 2) { "Enter an IPv4 CIDR such as 192.168.1.10/24." }
        require(IPV4_PATTERN.matches(parts[0])) { "Enter a numeric IPv4 address." }

        val octets = parts[0].split(".").map { it.toIntOrNull() ?: -1 }
        require(octets.size == 4 && octets.all { it in 0..255 }) { "Invalid IPv4 address." }
        val localAddress = InetAddress.getByAddress(octets.map { it.toByte() }.toByteArray()) as Inet4Address
        val prefix = parts[1].toIntOrNull() ?: throw IllegalArgumentException("Invalid subnet prefix.")

        require(prefix in MIN_PREFIX..MAX_PREFIX) {
            "Subnet /$prefix is outside the supported discovery range (/$MIN_PREFIX to /$MAX_PREFIX)."
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

    private val IPV4_PATTERN = Regex("""^\d{1,3}(?:\.\d{1,3}){3}$""")
    const val MIN_PREFIX = 22
    const val MAX_PREFIX = 30
}

object DeviceRoleClassifier {
    fun classify(openPorts: List<Int>): String {
        val ports = openPorts.toSet()
        return when {
            ports.any { it in setOf(631, 9100, 515) } -> "Printer"
            ports.any { it in setOf(554, 8554, 1883) } -> "Camera / IoT"
            ports.any { it in setOf(445, 139, 5000, 5001, 32400) } -> "NAS / File sharing"
            ports.any { it in setOf(3389, 5900) } -> "Remote access"
            ports.any { it in setOf(53, 67, 68) } && ports.any { it in setOf(80, 443) } -> "Network device"
            ports.any { it in setOf(80, 443, 8080, 8443, 8000, 8888) } -> "Web service"
            ports.any { it in setOf(22, 21, 25, 3306, 5432, 6379) } -> "Server"
            else -> "Unknown device"
        }
    }
}

class NetworkDiscoveryScanner {
    suspend fun scan(
        localCidr: String,
        timeoutMs: Int = 350,
        onProgress: suspend (completed: Int, total: Int) -> Unit = { _, _ -> }
    ): List<DiscoveredHost> {
        require(timeoutMs in 100..2000) { "Timeout must be between 100 and 2000 ms." }
        val targets = Ipv4Subnet.hostAddresses(localCidr)
        val semaphore = Semaphore(MAX_CONCURRENT_PROBES)
        val discovered = ArrayList<DiscoveredHost>()
        var completed = 0

        // Work in small batches so both host and per-port coroutine counts stay bounded.
        for (batch in targets.chunked(MAX_CONCURRENT_HOSTS)) {
            val batchResults = coroutineScope {
                batch.map { target ->
                    async {
                        val responsivePorts = coroutineScope {
                            COMMON_TCP_PORTS.map { port ->
                                async(Dispatchers.IO) {
                                    semaphore.withPermit { probePort(target, port, timeoutMs) }
                                }
                            }.awaitAll().filterNotNull()
                        }

                        if (responsivePorts.isEmpty()) null else {
                            val ports = responsivePorts.map { it.first }.sorted()
                            DiscoveredHost(
                                address = target.hostAddress ?: target.toString(),
                                openPorts = ports,
                                latencyMs = responsivePorts.minOf { it.second },
                                likelyRole = DeviceRoleClassifier.classify(ports)
                            )
                        }
                    }
                }.awaitAll()
            }
            discovered += batchResults.filterNotNull()
            completed += batch.size
            onProgress(completed, targets.size)
        }
        return discovered.sortedBy { addressToLong(it.address) }
    }

    private fun probePort(address: Inet4Address, port: Int, timeoutMs: Int): Pair<Int, Long>? {
        val started = System.nanoTime()
        return try {
            Socket().use { socket ->
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(address, port), timeoutMs)
            }
            port to TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
        } catch (_: ConnectException) {
            null
        } catch (_: SocketTimeoutException) {
            null
        } catch (_: SecurityException) {
            null
        } catch (_: Exception) {
            null
        }
    }

    private fun addressToLong(address: String): Long {
        val bytes = (InetAddress.getByName(address) as Inet4Address).address
        return bytes.fold(0L) { acc, byte -> (acc shl 8) or (byte.toLong() and 0xffL) }
    }

    companion object {
        const val MAX_CONCURRENT_HOSTS = 32
        const val MAX_CONCURRENT_PROBES = 128
        val COMMON_TCP_PORTS = listOf(
            21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 554,
            631, 993, 995, 1883, 3306, 3389, 5000, 5432, 5900,
            8000, 8080, 8443, 8888, 9100, 32400
        )
    }
}
