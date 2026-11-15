package com.dsl.gmap.scanner.engine

import com.dsl.gmap.scanner.model.PortScanResult
import com.dsl.gmap.scanner.model.PortState
import com.dsl.gmap.scanner.model.ScanProgress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.BindException
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.SocketAddress
import java.net.SocketTimeoutException
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.PriorityQueue
import java.util.concurrent.TimeUnit

/**
 * High-concurrency rootless TCP Connect scanner.
 *
 * Uses non-blocking SocketChannels multiplexed by a Selector. It does not
 * allocate one thread or coroutine per port. The outstanding-probe window
 * grows as the scan progresses and backs off when the OS reports local
 * socket/file-descriptor exhaustion.
 */
class TcpConnectScanner {

    suspend fun scan(
        address: InetAddress,
        startPort: Int,
        endPort: Int,
        timeoutMs: Int = 1200,
        onProgress: (ScanProgress, PortScanResult) -> Unit = { _, _ -> }
    ): List<PortScanResult> = withContext(Dispatchers.IO) {
        require(startPort in 1..65535) { "Start port must be between 1 and 65535." }
        require(endPort in startPort..65535) { "End port must be between start port and 65535." }
        require(timeoutMs in 100..30000) { "Timeout must be between 100 and 30000 ms." }

        val selector = Selector.open()
        val results = ArrayList<PortScanResult>(endPort - startPort + 1)
        val deadlines = PriorityQueue<PendingProbe>(compareBy { it.deadlineNanos })
        val total = endPort - startPort + 1

        val scanStartedNanos = System.nanoTime()
        var nextPort = startPort
        var inFlight = 0
        var completed = 0
        var openCount = 0
        var closedCount = 0
        var filteredCount = 0
        var errorCount = 0

        // There is no fixed 48/128 worker cap. The window can grow to the
        // requested scan size and backs off only when the OS reports pressure.
        var window = minOf(
            total,
            maxOf(256, Runtime.getRuntime().availableProcessors() * 128)
        )
        var resourceBackoffUntil = 0L
        var completedSinceGrowth = 0
        var resourceCooldown = 0

        fun record(result: PortScanResult) {
            results.add(result)
            completed++

            when (result.state) {
                PortState.OPEN -> openCount++
                PortState.CLOSED -> closedCount++
                PortState.FILTERED -> filteredCount++
                PortState.ERROR -> errorCount++
            }

            if (result.state == PortState.OPEN || completed % 16 == 0 || completed == total) {
                onProgress(
                    ScanProgress(
                        completed = completed,
                        total = total,
                        openCount = openCount,
                        closedCount = closedCount,
                        filteredCount = filteredCount,
                        errorCount = errorCount,
                        elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - scanStartedNanos),
                        probesPerSecond = if (System.nanoTime() > scanStartedNanos) {
                            completed * 1_000_000_000.0 / (System.nanoTime() - scanStartedNanos)
                        } else 0.0
                    ),
                    result
                )
            }

            if (resourceCooldown > 0) resourceCooldown--
            completedSinceGrowth++
            if (completedSinceGrowth >= 128) {
                if (resourceCooldown == 0 && window < total) {
                    val increase = maxOf(64, window / 2)
                    window = minOf(total, window + increase)
                }
                completedSinceGrowth = 0
            }
        }

        fun closePending(probe: PendingProbe) {
            if (probe.completed) return
            probe.completed = true
            try {
                probe.channel.keyFor(selector)?.cancel()
            } catch (_: Exception) {
                // The channel may already have been deregistered.
            }
            try {
                probe.channel.close()
            } catch (_: IOException) {
                // The probe is already finished from the scanner's perspective.
            }
            inFlight = (inFlight - 1).coerceAtLeast(0)
        }

        fun classifyConnectFailure(port: Int, exception: IOException): PortScanResult {
            return when (exception) {
                is ConnectException -> PortScanResult(
                    port = port,
                    state = PortState.CLOSED,
                    detail = "Connection refused."
                )
                is SocketTimeoutException -> PortScanResult(
                    port = port,
                    state = PortState.FILTERED,
                    detail = "Connection timed out; the port may be filtered or the host may not respond."
                )
                is NoRouteToHostException -> PortScanResult(
                    port = port,
                    state = PortState.ERROR,
                    detail = "No route to host."
                )
                else -> PortScanResult(
                    port = port,
                    state = PortState.ERROR,
                    detail = exception.message ?: "Network connection error."
                )
            }
        }

        try {
            while (nextPort <= endPort || inFlight > 0) {
                currentCoroutineContext().ensureActive()

                // Refill the outstanding-probe window.
                while (
                    nextPort <= endPort &&
                    inFlight < window &&
                    System.nanoTime() >= resourceBackoffUntil
                ) {
                    currentCoroutineContext().ensureActive()
                    val port = nextPort
                    var channel: SocketChannel? = null

                    try {
                        channel = SocketChannel.open()
                        channel.configureBlocking(false)

                        val startedAt = System.nanoTime()
                        val remote: SocketAddress = InetSocketAddress(address, port)
                        val connectedImmediately = channel.connect(remote)

                        if (connectedImmediately) {
                            channel.close()
                            nextPort++
                            record(
                                PortScanResult(
                                    port = port,
                                    state = PortState.OPEN,
                                    latencyMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt),
                                    serviceHint = commonServiceHint(port)
                                )
                            )
                        } else {
                            val probe = PendingProbe(
                                port = port,
                                channel = channel,
                                startedAtNanos = startedAt,
                                deadlineNanos = startedAt + TimeUnit.MILLISECONDS.toNanos(timeoutMs.toLong())
                            )
                            // Advance only after registration succeeds. If registration
                            // hits local descriptor pressure, retry this same port.
                            channel.register(selector, SelectionKey.OP_CONNECT, probe)
                            deadlines.add(probe)
                            inFlight++
                            nextPort++
                        }
                    } catch (exception: IOException) {
                        try {
                            channel?.close()
                        } catch (_: IOException) {
                            // Ignore cleanup errors while classifying the original failure.
                        }

                        if (isLocalResourceExhaustion(exception)) {
                            // Do not advance nextPort: retry the same port after backing off.
                            window = maxOf(8, window / 2)
                            resourceCooldown = maxOf(resourceCooldown, window)
                            resourceBackoffUntil = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(250)
                            break
                        }

                        nextPort++
                        record(classifyConnectFailure(port, exception))
                    } catch (exception: SecurityException) {
                        try {
                            channel?.close()
                        } catch (_: IOException) {
                            // Ignore cleanup errors.
                        }
                        nextPort++
                        record(
                            PortScanResult(
                                port = port,
                                state = PortState.ERROR,
                                detail = "The operating system denied the network operation."
                            )
                        )
                    }
                }

                // Wait for readiness, but wake regularly for cancellation and deadlines.
                val now = System.nanoTime()
                val nextDeadline = deadlines.peek()?.deadlineNanos
                val untilDeadlineMs = nextDeadline?.let {
                    TimeUnit.NANOSECONDS.toMillis((it - now).coerceAtLeast(0L))
                } ?: 50L
                val waitMs = untilDeadlineMs.coerceIn(1L, 50L)

                if (inFlight > 0) {
                    selector.select(waitMs)

                    val selected = selector.selectedKeys()
                    val iterator = selected.iterator()
                    while (iterator.hasNext()) {
                        val key = iterator.next()
                        iterator.remove()

                        val probe = key.attachment() as? PendingProbe ?: continue
                        if (probe.completed) continue

                        try {
                            if (key.isValid && key.isConnectable && probe.channel.finishConnect()) {
                                closePending(probe)
                                record(
                                    PortScanResult(
                                        port = probe.port,
                                        state = PortState.OPEN,
                                        latencyMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - probe.startedAtNanos),
                                        serviceHint = commonServiceHint(probe.port)
                                    )
                                )
                            }
                        } catch (exception: IOException) {
                            closePending(probe)
                            record(classifyConnectFailure(probe.port, exception))
                        } catch (exception: SecurityException) {
                            closePending(probe)
                            record(
                                PortScanResult(
                                    port = probe.port,
                                    state = PortState.ERROR,
                                    detail = "The operating system denied the network operation."
                                )
                            )
                        }
                    }
                } else if (nextPort <= endPort && System.nanoTime() < resourceBackoffUntil) {
                    val sleepMs = TimeUnit.NANOSECONDS.toMillis(
                        (resourceBackoffUntil - System.nanoTime()).coerceAtLeast(1L)
                    ).coerceIn(1L, 50L)
                    Thread.sleep(sleepMs)
                }

                // Expire silent probes. A timeout is not proof that a port is closed.
                val expiryNow = System.nanoTime()
                while (deadlines.peek()?.deadlineNanos?.let { it <= expiryNow } == true) {
                    val probe = deadlines.poll() ?: break
                    if (!probe.completed) {
                        closePending(probe)
                        record(
                            PortScanResult(
                                port = probe.port,
                                state = PortState.FILTERED,
                                detail = "No TCP response before timeout."
                            )
                        )
                    }
                }
            }

            results.sortedBy { it.port }
        } finally {
            // Closing all pending channels ensures cancellation does not leave sockets behind.
            try {
                selector.keys().toList().forEach { key ->
                    try {
                        key.channel().close()
                    } catch (_: IOException) {
                        // Best-effort cleanup.
                    }
                    key.cancel()
                }
            } finally {
                selector.close()
            }
        }
    }

    private fun isLocalResourceExhaustion(exception: IOException): Boolean {
        // BindException can indicate exhaustion of the ephemeral local port
        // range during a high-concurrency connect scan.
        if (exception is BindException) return true

        val message = exception.message.orEmpty().lowercase()
        return message.contains("too many open files") ||
            message.contains("emfile") ||
            message.contains("enfile") ||
            message.contains("resource temporarily unavailable") ||
            message.contains("no file descriptors available") ||
            message.contains("cannot assign requested address") ||
            message.contains("address not available") ||
            message.contains("eaddrnotavail") ||
            message.contains("no buffer space available")
    }

    private fun commonServiceHint(port: Int): String? = when (port) {
        21 -> "FTP"
        22 -> "SSH"
        23 -> "Telnet"
        25 -> "SMTP"
        53 -> "DNS"
        80 -> "HTTP"
        110 -> "POP3"
        139 -> "NetBIOS"
        143 -> "IMAP"
        443 -> "HTTPS"
        445 -> "SMB"
        993 -> "IMAPS"
        995 -> "POP3S"
        1433 -> "Microsoft SQL Server"
        3306 -> "MySQL"
        3389 -> "RDP"
        5432 -> "PostgreSQL"
        5900 -> "VNC"
        8080 -> "HTTP alternate"
        8443 -> "HTTPS alternate"
        else -> null
    }

    private data class PendingProbe(
        val port: Int,
        val channel: SocketChannel,
        val startedAtNanos: Long,
        val deadlineNanos: Long,
        var completed: Boolean = false
    )
}
