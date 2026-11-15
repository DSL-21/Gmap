package com.dsl.gmap.scanner.engine

import com.dsl.gmap.scanner.model.PortScanResult
import com.dsl.gmap.scanner.model.PortState
import com.dsl.gmap.scanner.model.ScanProgress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import java.io.IOException
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger

class TcpConnectScanner {

    suspend fun scan(
        address: InetAddress,
        startPort: Int,
        endPort: Int,
        timeoutMs: Int = 1200,
        parallelism: Int = 48,
        onProgress: (ScanProgress, PortScanResult) -> Unit = { _, _ -> }
    ): List<PortScanResult> {
        require(startPort in 1..65535) { "Start port must be between 1 and 65535." }
        require(endPort in startPort..65535) { "End port must be between start port and 65535." }
        require(timeoutMs in 100..15000) { "Timeout must be between 100 and 15000 ms." }
        require(parallelism in 1..128) { "Parallelism must be between 1 and 128 workers." }

        val total = endPort - startPort + 1
        val workerCount = minOf(parallelism, total)
        val nextPort = AtomicInteger(startPort)
        val completed = AtomicInteger(0)
        val open = AtomicInteger(0)
        val closed = AtomicInteger(0)
        val filtered = AtomicInteger(0)
        val errors = AtomicInteger(0)
        val results = ConcurrentLinkedQueue<PortScanResult>()

        coroutineScope {
            val workers = List(workerCount) {
                launch(Dispatchers.IO) {
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val port = nextPort.getAndIncrement()
                        if (port > endPort) break

                        val result = scanPort(address, port, timeoutMs)
                        results.add(result)

                        when (result.state) {
                            PortState.OPEN -> open.incrementAndGet()
                            PortState.CLOSED -> closed.incrementAndGet()
                            PortState.FILTERED -> filtered.incrementAndGet()
                            PortState.ERROR -> errors.incrementAndGet()
                        }

                        val done = completed.incrementAndGet()
                        if (result.state == PortState.OPEN || done % 16 == 0 || done == total) {
                            onProgress(
                                ScanProgress(
                                    completed = done,
                                    total = total,
                                    openCount = open.get(),
                                    closedCount = closed.get(),
                                    filteredCount = filtered.get(),
                                    errorCount = errors.get()
                                ),
                                result
                            )
                        }
                    }
                }
            }
            workers.joinAll()
        }

        return results.toList().sortedBy { it.port }
    }

    private fun scanPort(address: InetAddress, port: Int, timeoutMs: Int): PortScanResult {
        val startedAt = System.nanoTime()
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(address, port), timeoutMs)
            }
            PortScanResult(
                port = port,
                state = PortState.OPEN,
                latencyMs = (System.nanoTime() - startedAt) / 1_000_000,
                serviceHint = commonServiceHint(port)
            )
        } catch (exception: SocketTimeoutException) {
            PortScanResult(
                port, PortState.FILTERED,
                detail = "Connection timed out; the port may be filtered or the host may not respond."
            )
        } catch (exception: ConnectException) {
            PortScanResult(port, PortState.CLOSED, detail = "Connection refused.")
        } catch (exception: NoRouteToHostException) {
            PortScanResult(port, PortState.ERROR, detail = "No route to host.")
        } catch (exception: SecurityException) {
            PortScanResult(port, PortState.ERROR, detail = "The operating system denied the network operation.")
        } catch (exception: IOException) {
            PortScanResult(port, PortState.ERROR, detail = exception.message ?: "Network I/O error.")
        }
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
}
