package com.dsl.gmap.scanner.engine

import com.dsl.gmap.scanner.model.PortScanResult
import com.dsl.gmap.scanner.model.PortState
import com.dsl.gmap.scanner.model.ScanProgress
import com.dsl.gmap.scanner.model.TcpScanSettings
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
import java.util.ArrayDeque
import java.util.PriorityQueue
import java.util.concurrent.TimeUnit

/**
 * Rootless TCP Connect scanner with bounded retries and adaptive concurrency.
 *
 * Each requested port receives exactly one final result. Unanswered probes are
 * retried according to the selected Gmap scan profile and only become FILTERED
 * after the retry budget is exhausted. The adaptive controller changes its
 * window from batches of outcomes rather than punishing every single timeout.
 */
class TcpConnectScanner {

    suspend fun scan(
        address: InetAddress,
        startPort: Int,
        endPort: Int,
        settings: TcpScanSettings = TcpScanSettings.preset(com.dsl.gmap.scanner.model.TcpScanMode.BALANCED),
        onProgress: (ScanProgress, PortScanResult) -> Unit = { _, _ -> }
    ): List<PortScanResult> = withContext(Dispatchers.IO) {
        require(startPort in 1..65535) { "Start port must be between 1 and 65535." }
        require(endPort in startPort..65535) { "End port must be between start port and 65535." }
        val config = settings.normalized()
        require(config.timeoutMs in 100..30000) { "Connection timeout is outside the supported range." }

        val selector = Selector.open()
        val total = endPort - startPort + 1
        val results = ArrayList<PortScanResult>(total)
        val deadlines = PriorityQueue<PendingProbe>(compareBy { it.deadlineNanos })
        val retryQueue = ArrayDeque<Int>()
        val attemptsByPort = IntArray(total)

        val scanStartedNanos = System.nanoTime()
        var nextPort = startPort
        var inFlight = 0
        var completed = 0
        var openCount = 0
        var closedCount = 0
        var filteredCount = 0
        var errorCount = 0

        // Begin conservatively, then ramp up when a batch of probes is responsive.
        var window = if (config.adaptiveConcurrency) {
            minOf(total, config.maxConcurrentProbes, INITIAL_CONCURRENT_PROBES)
        } else {
            minOf(total, config.maxConcurrentProbes)
        }
        var resourceBackoffUntil = 0L
        var outcomeSampleCount = 0
        var timeoutSampleCount = 0
        var newPortsSinceRetry = 0

        fun observeProbeOutcome(timedOut: Boolean) {
            if (!config.adaptiveConcurrency) return
            outcomeSampleCount++
            if (timedOut) timeoutSampleCount++

            if (outcomeSampleCount >= ADAPTIVE_SAMPLE_SIZE) {
                val timeoutRatio = timeoutSampleCount.toFloat() / outcomeSampleCount
                when {
                    timeoutRatio >= HIGH_TIMEOUT_RATIO -> {
                        window = maxOf(config.minConcurrentProbes, (window * 3) / 4)
                        resourceBackoffUntil = System.nanoTime() +
                            TimeUnit.MILLISECONDS.toNanos(ADAPTIVE_BACKOFF_MS.toLong())
                    }
                    timeoutRatio <= LOW_TIMEOUT_RATIO -> {
                        window = minOf(
                            total,
                            config.maxConcurrentProbes,
                            window + maxOf(1, window / 4)
                        )
                    }
                }
                outcomeSampleCount = 0
                timeoutSampleCount = 0
            }
        }

        fun recordFinal(result: PortScanResult) {
            results.add(result)
            completed++
            when (result.state) {
                PortState.OPEN -> openCount++
                PortState.CLOSED -> closedCount++
                PortState.FILTERED -> filteredCount++
                PortState.ERROR -> errorCount++
            }

            if (result.state == PortState.OPEN || completed % 16 == 0 || completed == total) {
                val now = System.nanoTime()
                val elapsedNanos = (now - scanStartedNanos).coerceAtLeast(1L)
                onProgress(
                    ScanProgress(
                        completed = completed,
                        total = total,
                        openCount = openCount,
                        closedCount = closedCount,
                        filteredCount = filteredCount,
                        errorCount = errorCount,
                        elapsedMs = TimeUnit.NANOSECONDS.toMillis(elapsedNanos),
                        probesPerSecond = completed * 1_000_000_000.0 / elapsedNanos
                    ),
                    result
                )
            }
        }

        fun recordAttempt(port: Int, result: PortScanResult) {
            val attemptCount = attemptsByPort[port - startPort]
            if (result.state == PortState.FILTERED && attemptCount <= config.maxRetries) {
                // Only unanswered probes are retried. A refusal is a positive
                // network response and must remain CLOSED, not be retried.
                retryQueue.addLast(port)
            } else {
                val detail = if (result.state == PortState.FILTERED && attemptCount > 1) {
                    "${result.detail ?: "No TCP response."} (${attemptCount} attempts)"
                } else {
                    result.detail
                }
                recordFinal(result.copy(detail = detail, attempts = attemptCount))
            }
        }

        fun consumeScheduledPort(port: Int, fromRetryQueue: Boolean) {
            if (fromRetryQueue) {
                // The retry is always taken from the head of the queue.
                if (retryQueue.peekFirst() == port) retryQueue.removeFirst()
                else retryQueue.remove(port)
                newPortsSinceRetry = 0
            } else {
                nextPort++
                newPortsSinceRetry++
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
                // Best-effort cleanup.
            }
            inFlight = (inFlight - 1).coerceAtLeast(0)
        }

        fun classifyConnectFailure(port: Int, exception: IOException): PortScanResult {
            return when (exception) {
                is ConnectException -> {
                    val message = exception.message.orEmpty()
                    val lowerMessage = message.lowercase()
                    when {
                        lowerMessage.contains("timed out") || lowerMessage.contains("timeout") ->
                            PortScanResult(
                                port = port,
                                state = PortState.FILTERED,
                                detail = "Connection timed out; the port may be filtered or the host may not respond."
                            )
                        lowerMessage.contains("refused") ->
                            PortScanResult(
                                port = port,
                                state = PortState.CLOSED,
                                detail = "Connection refused."
                            )
                        else ->
                            PortScanResult(
                                port = port,
                                state = PortState.ERROR,
                                detail = message.ifBlank { "TCP connection failed." }
                            )
                    }
                }
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
            while (nextPort <= endPort || retryQueue.isNotEmpty() || inFlight > 0) {
                currentCoroutineContext().ensureActive()

                while (
                    (retryQueue.isNotEmpty() || nextPort <= endPort) &&
                    inFlight < window &&
                    System.nanoTime() >= resourceBackoffUntil
                ) {
                    currentCoroutineContext().ensureActive()
                    val fromRetryQueue = retryQueue.isNotEmpty() &&
                        (nextPort > endPort || newPortsSinceRetry >= RETRY_FAIRNESS_NEW_PORTS)
                    val port = if (fromRetryQueue) retryQueue.peekFirst() else nextPort
                    var channel: SocketChannel? = null

                    try {
                        channel = SocketChannel.open()
                        channel.configureBlocking(false)

                        val startedAt = System.nanoTime()
                        val remote: SocketAddress = InetSocketAddress(address, port)
                        val connectedImmediately = channel.connect(remote)

                        if (connectedImmediately) {
                            channel.close()
                            consumeScheduledPort(port, fromRetryQueue)
                            attemptsByPort[port - startPort]++
                            observeProbeOutcome(timedOut = false)
                            recordAttempt(
                                port,
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
                                deadlineNanos = startedAt + TimeUnit.MILLISECONDS.toNanos(config.timeoutMs.toLong())
                            )
                            // Advance only after selector registration succeeds. Local
                            // descriptor exhaustion retries the same scheduled port.
                            channel.register(selector, SelectionKey.OP_CONNECT, probe)
                            deadlines.add(probe)
                            inFlight++
                            consumeScheduledPort(port, fromRetryQueue)
                            attemptsByPort[port - startPort]++
                        }
                    } catch (exception: IOException) {
                        try {
                            channel?.close()
                        } catch (_: IOException) {
                            // Ignore cleanup errors while classifying the original failure.
                        }

                        if (isLocalResourceExhaustion(exception)) {
                            window = maxOf(config.minConcurrentProbes, window / 2)
                            resourceBackoffUntil = System.nanoTime() +
                                TimeUnit.MILLISECONDS.toNanos(LOCAL_RESOURCE_BACKOFF_MS.toLong())
                            break
                        }

                        consumeScheduledPort(port, fromRetryQueue)
                        attemptsByPort[port - startPort]++
                        val result = classifyConnectFailure(port, exception)
                        observeProbeOutcome(timedOut = result.state == PortState.FILTERED)
                        recordAttempt(port, result)
                    } catch (exception: SecurityException) {
                        try {
                            channel?.close()
                        } catch (_: IOException) {
                            // Ignore cleanup errors.
                        }
                        consumeScheduledPort(port, fromRetryQueue)
                        attemptsByPort[port - startPort]++
                        recordAttempt(
                            port,
                            PortScanResult(
                                port = port,
                                state = PortState.ERROR,
                                detail = "The operating system denied the network operation."
                            )
                        )
                    }
                }

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
                                observeProbeOutcome(timedOut = false)
                                recordAttempt(
                                    probe.port,
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
                            val result = classifyConnectFailure(probe.port, exception)
                            observeProbeOutcome(timedOut = result.state == PortState.FILTERED)
                            recordAttempt(probe.port, result)
                        } catch (exception: SecurityException) {
                            closePending(probe)
                            recordAttempt(
                                probe.port,
                                PortScanResult(
                                    port = probe.port,
                                    state = PortState.ERROR,
                                    detail = "The operating system denied the network operation."
                                )
                            )
                        }
                    }
                } else if (
                    (retryQueue.isNotEmpty() || nextPort <= endPort) &&
                    System.nanoTime() < resourceBackoffUntil
                ) {
                    val sleepMs = TimeUnit.NANOSECONDS.toMillis(
                        (resourceBackoffUntil - System.nanoTime()).coerceAtLeast(1L)
                    ).coerceIn(1L, 50L)
                    Thread.sleep(sleepMs)
                }

                val expiryNow = System.nanoTime()
                while (deadlines.peek()?.deadlineNanos?.let { it <= expiryNow } == true) {
                    val probe = deadlines.poll() ?: break
                    if (!probe.completed) {
                        closePending(probe)
                        observeProbeOutcome(timedOut = true)
                        recordAttempt(
                            probe.port,
                            PortScanResult(
                                port = probe.port,
                                state = PortState.FILTERED,
                                detail = "No TCP response before timeout; the port may be filtered or rate-limited."
                            )
                        )
                    }
                }
            }

            // One and only one final row per requested port, even when retries occurred.
            check(results.size == total) {
                "Scanner completed with ${results.size} results for $total requested ports."
            }
            results.sortedBy { it.port }
        } finally {
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

    companion object {
        const val INITIAL_CONCURRENT_PROBES = 32
        const val RETRY_FAIRNESS_NEW_PORTS = 16
        const val ADAPTIVE_SAMPLE_SIZE = 32
        const val HIGH_TIMEOUT_RATIO = 0.50f
        const val LOW_TIMEOUT_RATIO = 0.125f
        const val ADAPTIVE_BACKOFF_MS = 100
        const val LOCAL_RESOURCE_BACKOFF_MS = 250
    }
}
