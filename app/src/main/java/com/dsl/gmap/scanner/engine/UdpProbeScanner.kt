package com.dsl.gmap.scanner.engine

import com.dsl.gmap.scanner.model.UdpPortScanResult
import com.dsl.gmap.scanner.model.UdpPortState
import com.dsl.gmap.scanner.model.UdpScanProgress
import com.dsl.gmap.scanner.model.UdpScanSettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.BindException
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.PortUnreachableException
import java.net.SocketException
import java.net.StandardProtocolFamily
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.ArrayDeque
import java.util.PriorityQueue
import java.util.concurrent.TimeUnit

/**
 * Rootless UDP scanner built around non-blocking DatagramChannel + Selector.
 *
 * One selector owns every in-flight probe. It bounds open channels, uses a fair
 * retry queue for silent endpoints, validates supported protocol responses and
 * checks cancellation between selector waits (at most 50 ms). No raw sockets,
 * packet injection, authentication or state-changing requests are used.
 */
class UdpProbeScanner(
    private val probePayloadOverride: ((Int) -> ByteArray)? = null
) {
    suspend fun scan(
        address: InetAddress,
        startPort: Int,
        endPort: Int,
        settings: UdpScanSettings = UdpScanSettings(),
        onProgress: (UdpScanProgress, UdpPortScanResult) -> Unit = { _, _ -> }
    ): List<UdpPortScanResult> = withContext(Dispatchers.IO) {
        require(startPort in 1..65535) { "Start port must be between 1 and 65535." }
        require(endPort in startPort..65535) { "End port must be between start port and 65535." }
        require(endPort - startPort + 1 <= MAX_PORTS_PER_SCAN) {
            "UDP scans are limited to $MAX_PORTS_PER_SCAN ports per target address."
        }

        val config = settings.normalized()
        val selector = Selector.open()
        val total = endPort - startPort + 1
        val results = ArrayList<UdpPortScanResult>(total)
        val deadlines = PriorityQueue<PendingProbe>(compareBy { it.deadlineNanos })
        val retryQueue = ArrayDeque<Int>()
        val attemptsByPort = IntArray(total)
        val startedAt = System.nanoTime()

        var nextPort = startPort
        var inFlight = 0
        var completed = 0
        var openCount = 0
        var closedCount = 0
        var openFilteredCount = 0
        var errorCount = 0
        var notTestedCount = 0
        var attemptsSent = 0
        var newPortsSinceRetry = 0
        var resourceBackoffUntil = 0L
        var resourceFailures = 0

        var window = if (config.adaptiveConcurrency) {
            minOf(total, config.maxConcurrentProbes, INITIAL_CONCURRENT_PROBES)
        } else {
            minOf(total, config.maxConcurrentProbes)
        }
        var sampleCount = 0
        var timeoutCount = 0

        fun observeOutcome(timedOut: Boolean) {
            if (!config.adaptiveConcurrency) return
            sampleCount++
            if (timedOut) timeoutCount++
            if (sampleCount >= ADAPTIVE_SAMPLE_SIZE) {
                val ratio = timeoutCount.toFloat() / sampleCount
                when {
                    ratio >= HIGH_TIMEOUT_RATIO -> {
                        window = maxOf(config.minConcurrency, (window * 3) / 4)
                        resourceBackoffUntil = System.nanoTime() +
                            TimeUnit.MILLISECONDS.toNanos(ADAPTIVE_BACKOFF_MS.toLong())
                    }
                    ratio <= LOW_TIMEOUT_RATIO -> {
                        window = minOf(
                            total,
                            config.maxConcurrentProbes,
                            window + maxOf(1, window / 4)
                        )
                    }
                }
                sampleCount = 0
                timeoutCount = 0
            }
        }

        fun recordFinal(result: UdpPortScanResult) {
            results.add(result)
            completed++
            when (result.state) {
                UdpPortState.OPEN -> openCount++
                UdpPortState.CLOSED -> closedCount++
                UdpPortState.OPEN_FILTERED -> openFilteredCount++
                UdpPortState.ERROR -> errorCount++
                UdpPortState.NOT_TESTED -> notTestedCount++
            }

            if (
                result.state == UdpPortState.OPEN ||
                result.state == UdpPortState.CLOSED ||
                result.state == UdpPortState.NOT_TESTED ||
                completed % PROGRESS_UPDATE_INTERVAL == 0 ||
                completed == total
            ) {
                val elapsedNanos = (System.nanoTime() - startedAt).coerceAtLeast(1L)
                onProgress(
                    UdpScanProgress(
                        completed = completed,
                        total = total,
                        openCount = openCount,
                        closedCount = closedCount,
                        openFilteredCount = openFilteredCount,
                        errorCount = errorCount,
                        notTestedCount = notTestedCount,
                        attemptsSent = attemptsSent,
                        elapsedMs = TimeUnit.NANOSECONDS.toMillis(elapsedNanos),
                        probesPerSecond = attemptsSent * 1_000_000_000.0 / elapsedNanos
                    ),
                    result
                )
            }
        }

        fun recordAttempt(port: Int, result: UdpPortScanResult) {
            val attempts = attemptsByPort[port - startPort]
            if (result.state == UdpPortState.OPEN_FILTERED && attempts <= config.maxRetries) {
                retryQueue.addLast(port)
            } else {
                val detail = if (result.state == UdpPortState.OPEN_FILTERED && attempts > 1) {
                    (result.detail ?: "No UDP response.") + " (" + attempts + " attempts)"
                } else {
                    result.detail
                }
                recordFinal(result.copy(detail = detail, attempts = attempts))
            }
        }

        fun consumeScheduledPort(port: Int, fromRetryQueue: Boolean) {
            if (fromRetryQueue) {
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
                // The channel may already be deregistered.
            }
            try {
                probe.channel.close()
            } catch (_: IOException) {
                // Best-effort cleanup.
            }
            inFlight = (inFlight - 1).coerceAtLeast(0)
        }

        fun classifyFailure(port: Int, definition: UdpProbeDefinition, exception: IOException): UdpPortScanResult {
            val state = when {
                exception is PortUnreachableException -> UdpPortState.CLOSED
                exception is NoRouteToHostException -> UdpPortState.ERROR
                exception is SocketException &&
                    (exception.message.orEmpty().contains("port unreachable", true) ||
                        exception.message.orEmpty().contains("econnrefused", true)) -> UdpPortState.CLOSED
                else -> UdpPortState.ERROR
            }
            val detail = when (state) {
                UdpPortState.CLOSED -> "The network stack reported the UDP destination as unreachable."
                else -> exception.message ?: "UDP network error."
            }
            return UdpPortScanResult(
                port = port,
                state = state,
                latencyMs = null,
                serviceHint = definition.serviceHint,
                detail = detail,
                probeName = definition.name
            )
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
                    val attemptNumber = attemptsByPort[port - startPort] + 1
                    val definition = UdpProbeCatalog.forPort(port, attemptNumber)
                    val payload = probePayloadOverride?.invoke(port) ?: definition.payload

                    if (payload == null) {
                        consumeScheduledPort(port, fromRetryQueue)
                        recordFinal(
                            UdpPortScanResult(
                                port = port,
                                state = UdpPortState.NOT_TESTED,
                                serviceHint = definition.serviceHint,
                                detail = definition.notTestedReason,
                                probeName = definition.name,
                                attempts = 0
                            )
                        )
                        continue
                    }

                    var channel: DatagramChannel? = null
                    try {
                        val family = if (address is Inet6Address) {
                            StandardProtocolFamily.INET6
                        } else {
                            StandardProtocolFamily.INET
                        }
                        channel = DatagramChannel.open(family)
                        channel.configureBlocking(false)
                        channel.connect(InetSocketAddress(address, port))
                        channel.write(ByteBuffer.wrap(payload))

                        val attemptStarted = System.nanoTime()
                        val pending = PendingProbe(
                            port = port,
                            channel = channel,
                            definition = definition,
                            attempt = attemptNumber,
                            startedAtNanos = attemptStarted,
                            deadlineNanos = attemptStarted +
                                TimeUnit.MILLISECONDS.toNanos(config.timeoutMs.toLong())
                        )
                        channel.register(selector, SelectionKey.OP_READ, pending)
                        deadlines.add(pending)
                        inFlight++
                        attemptsByPort[port - startPort] = attemptNumber
                        attemptsSent++
                        resourceFailures = 0
                        consumeScheduledPort(port, fromRetryQueue)
                    } catch (exception: IOException) {
                        try {
                            channel?.close()
                        } catch (_: IOException) {
                            // Preserve the original network error.
                        }

                        if (isLocalResourceExhaustion(exception) && resourceFailures < MAX_RESOURCE_FAILURES) {
                            resourceFailures++
                            window = maxOf(config.minConcurrency, window / 2)
                            resourceBackoffUntil = System.nanoTime() +
                                TimeUnit.MILLISECONDS.toNanos(LOCAL_RESOURCE_BACKOFF_MS.toLong())
                            break
                        }

                        consumeScheduledPort(port, fromRetryQueue)
                        attemptsByPort[port - startPort] = attemptNumber
                        recordAttempt(port, classifyFailure(port, definition, exception))
                    } catch (exception: SecurityException) {
                        try {
                            channel?.close()
                        } catch (_: IOException) {
                            // Best-effort cleanup.
                        }
                        consumeScheduledPort(port, fromRetryQueue)
                        attemptsByPort[port - startPort] = attemptNumber
                        recordAttempt(
                            port,
                            UdpPortScanResult(
                                port = port,
                                state = UdpPortState.ERROR,
                                serviceHint = definition.serviceHint,
                                detail = "The operating system denied the UDP operation.",
                                probeName = definition.name
                            )
                        )
                    }
                    catch (exception: Exception) {
                        try {
                            channel?.close()
                        } catch (_: IOException) {
                            // Preserve the original failure.
                        }
                        consumeScheduledPort(port, fromRetryQueue)
                        attemptsByPort[port - startPort] = attemptNumber
                        recordAttempt(
                            port,
                            UdpPortScanResult(
                                port = port,
                                state = UdpPortState.ERROR,
                                serviceHint = definition.serviceHint,
                                detail = exception.message ?: "Unsupported UDP address family or socket operation.",
                                probeName = definition.name
                            )
                        )
                    }
                }

                val nextDeadline = deadlines.peek()?.deadlineNanos
                val untilDeadlineMs = nextDeadline?.let {
                    TimeUnit.NANOSECONDS.toMillis((it - System.nanoTime()).coerceAtLeast(0L))
                } ?: SELECT_MAX_WAIT_MS.toLong()
                val waitMs = untilDeadlineMs.coerceIn(1L, SELECT_MAX_WAIT_MS.toLong())

                if (inFlight > 0) {
                    selector.select(waitMs)
                    val iterator = selector.selectedKeys().iterator()
                    while (iterator.hasNext()) {
                        val key = iterator.next()
                        iterator.remove()
                        val pending = key.attachment() as? PendingProbe ?: continue
                        if (pending.completed || !key.isValid || !key.isReadable) continue

                        val response = ByteBuffer.allocate(MAX_RESPONSE_BYTES)
                        try {
                            val received = pending.channel.read(response)
                            if (received >= 0) {
                                response.flip()
                                val bytes = ByteArray(response.remaining())
                                response.get(bytes)
                                closePending(pending)
                                observeOutcome(timedOut = false)
                                val assessment = UdpProbeCatalog.assessResponse(pending.definition, bytes)
                                recordAttempt(
                                    pending.port,
                                    UdpPortScanResult(
                                        port = pending.port,
                                        state = UdpPortState.OPEN,
                                        latencyMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - pending.startedAtNanos),
                                        responseBytes = received,
                                        serviceHint = pending.definition.serviceHint,
                                        detail = assessment.detail,
                                        probeName = pending.definition.name,
                                        serviceConfirmed = assessment.serviceConfirmed,
                                        attempts = pending.attempt,
                                        responsePreview = responsePreview(bytes)
                                    )
                                )
                            }
                        } catch (exception: IOException) {
                            closePending(pending)
                            val result = classifyFailure(pending.port, pending.definition, exception)
                                .copy(attempts = pending.attempt)
                            observeOutcome(timedOut = false)
                            recordAttempt(pending.port, result)
                        }
                    }
                } else if (
                    (retryQueue.isNotEmpty() || nextPort <= endPort) &&
                    System.nanoTime() < resourceBackoffUntil
                ) {
                    val sleepMs = TimeUnit.NANOSECONDS.toMillis(
                        (resourceBackoffUntil - System.nanoTime()).coerceAtLeast(1L)
                    ).coerceIn(1L, SELECT_MAX_WAIT_MS.toLong())
                    Thread.sleep(sleepMs)
                }

                val now = System.nanoTime()
                while (deadlines.peek()?.deadlineNanos?.let { it <= now } == true) {
                    val pending = deadlines.poll() ?: break
                    if (!pending.completed) {
                        closePending(pending)
                        observeOutcome(timedOut = true)
                        recordAttempt(
                            pending.port,
                            UdpPortScanResult(
                                port = pending.port,
                                state = UdpPortState.OPEN_FILTERED,
                                latencyMs = config.timeoutMs.toLong(),
                                serviceHint = pending.definition.serviceHint,
                                detail = "No UDP response before timeout; the port may be open or filtered.",
                                probeName = pending.definition.name,
                                attempts = pending.attempt
                            )
                        )
                    }
                }
            }

            check(results.size == total) {
                "UDP scanner completed with " + results.size + " results for " + total + " requested ports."
            }
            check(results.map { it.port }.distinct().size == total) {
                "UDP scanner produced duplicate final results."
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

    private fun responsePreview(bytes: ByteArray): String? {
        if (bytes.isEmpty()) return null
        return bytes.take(RESPONSE_PREVIEW_BYTES)
            .joinToString(" ") { "%02X".format(it.toInt() and 0xff) }
    }

    private data class PendingProbe(
        val port: Int,
        val channel: DatagramChannel,
        val definition: UdpProbeDefinition,
        val attempt: Int,
        val startedAtNanos: Long,
        val deadlineNanos: Long,
        var completed: Boolean = false
    )

    companion object {
        const val MAX_PORTS_PER_SCAN = 4096
        const val MAX_CONCURRENT_PROBES = 64
        const val INITIAL_CONCURRENT_PROBES = 12
        const val RETRY_FAIRNESS_NEW_PORTS = 16
        const val ADAPTIVE_SAMPLE_SIZE = 24
        const val HIGH_TIMEOUT_RATIO = 0.75f
        const val LOW_TIMEOUT_RATIO = 0.20f
        const val ADAPTIVE_BACKOFF_MS = 50
        const val LOCAL_RESOURCE_BACKOFF_MS = 200
        private const val MAX_RESOURCE_FAILURES = 5
        private const val PROGRESS_UPDATE_INTERVAL = 8
        private const val SELECT_MAX_WAIT_MS = 50
        private const val MAX_RESPONSE_BYTES = 2048
        private const val RESPONSE_PREVIEW_BYTES = 16
    }
}
