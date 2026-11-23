package com.dsl.gmap.scanner.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.dsl.gmap.scanner.engine.UdpProbeScanner
import com.dsl.gmap.scanner.model.UdpPortScanResult
import com.dsl.gmap.scanner.model.UdpPortState
import com.dsl.gmap.scanner.model.UdpScanSessionSummary
import com.dsl.gmap.scanner.model.UdpScanSettings
import com.dsl.gmap.scanner.model.UdpScanUiState
import com.dsl.gmap.scanner.validation.PortRangeParser
import com.dsl.gmap.scanner.validation.TargetAddressSelector
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetAddress

class UdpScanViewModel(
    private val scanner: UdpProbeScanner = UdpProbeScanner()
) : ViewModel() {
    private val _uiState = MutableStateFlow(UdpScanUiState())
    val uiState: StateFlow<UdpScanUiState> = _uiState.asStateFlow()

    private val _history = MutableStateFlow<List<UdpScanSessionSummary>>(emptyList())
    val history: StateFlow<List<UdpScanSessionSummary>> = _history.asStateFlow()

    private var scanJob: Job? = null

    fun startScan(
        targetInput: String,
        startPortInput: String,
        endPortInput: String,
        scanAllResolvedAddresses: Boolean = false,
        settings: UdpScanSettings = UdpScanSettings()
    ) {
        if (scanJob?.isActive == true) return

        val target = targetInput.trim()
        if (target.isBlank() || target.contains("/") || target.contains("://") || target.any { it.isWhitespace() }) {
            setError("Enter one hostname or IP address.")
            return
        }

        val range = PortRangeParser.parse(startPortInput, endPortInput)
        if (range == null || range.size > UdpProbeScanner.MAX_PORTS_PER_SCAN) {
            setError("Enter a valid UDP port range. Each target address is limited to " +
                UdpProbeScanner.MAX_PORTS_PER_SCAN + " ports.")
            return
        }

        val scanSettings = settings.normalized()
        scanJob = viewModelScope.launch {
            val startedAt = System.currentTimeMillis()
            _uiState.value = UdpScanUiState(
                isScanning = true,
                target = target,
                statusMessage = "Resolving target..."
            )

            try {
                val resolved = withContext(Dispatchers.IO) {
                    InetAddress.getAllByName(target).distinctBy { it.hostAddress }.toList()
                }
                val addresses = TargetAddressSelector.select(resolved, scanAllResolvedAddresses)
                val totalChecks = range.size * addresses.size
                require(totalChecks <= MAX_TOTAL_SCAN_CHECKS) {
                    "This UDP scan would require " + totalChecks +
                        " host/port checks. Scan fewer DNS addresses or reduce the port range (limit: " +
                        MAX_TOTAL_SCAN_CHECKS + ")."
                }

                val resolvedLabels = addresses.mapNotNull { it.hostAddress }
                val skippedAddresses = resolved.size - addresses.size
                val resolutionSummary = resolvedLabels.joinToString(", ") +
                    if (skippedAddresses > 0) " (" + skippedAddresses + " other DNS address(es) not scanned)" else ""

                val allResults = ArrayList<UdpPortScanResult>(totalChecks)
                _uiState.update {
                    it.copy(
                        resolvedAddress = resolutionSummary,
                        total = totalChecks,
                        statusMessage = "Scanning " + addresses.size + " resolved address(es)"
                    )
                }

                addresses.forEachIndexed { addressIndex, address ->
                    val addressLabel = address.hostAddress ?: address.hostName
                    val completedBefore = allResults.size
                    val priorOpen = allResults.count { it.state == UdpPortState.OPEN }
                    val priorClosed = allResults.count { it.state == UdpPortState.CLOSED }
                    val priorFiltered = allResults.count { it.state == UdpPortState.OPEN_FILTERED }
                    val priorErrors = allResults.count { it.state == UdpPortState.ERROR }
                    val priorNotTested = allResults.count { it.state == UdpPortState.NOT_TESTED }
                    val attemptsBefore = allResults.sumOf { it.attempts }

                    _uiState.update {
                        it.copy(statusMessage = "Scanning " + addressLabel + " (" +
                            (addressIndex + 1) + "/" + addresses.size + ")")
                    }

                    val addressResults = scanner.scan(
                        address = address,
                        startPort = range.start,
                        endPort = range.end,
                        settings = scanSettings
                    ) { progress, latest ->
                        val tagged = latest.copy(targetAddress = addressLabel)
                        _uiState.update { current ->
                            val openRows = if (tagged.state == UdpPortState.OPEN) {
                                (current.results + tagged)
                                    .distinctBy { result -> (result.targetAddress ?: "") + ":" + result.port }
                                    .sortedWith(compareBy({ it.targetAddress }, { it.port }))
                            } else {
                                current.results
                            }
                            current.copy(
                                completed = completedBefore + progress.completed,
                                total = totalChecks,
                                progress = (completedBefore + progress.completed).toFloat() / totalChecks.toFloat(),
                                openCount = priorOpen + progress.openCount,
                                closedCount = priorClosed + progress.closedCount,
                                openFilteredCount = priorFiltered + progress.openFilteredCount,
                                errorCount = priorErrors + progress.errorCount,
                                notTestedCount = priorNotTested + progress.notTestedCount,
                                attemptsSent = attemptsBefore + progress.attemptsSent,
                                results = openRows,
                                elapsedMs = System.currentTimeMillis() - startedAt,
                                statusMessage = "Scanning " + addressLabel + " (" +
                                    (addressIndex + 1) + "/" + addresses.size + ")"
                            )
                        }
                    }

                    allResults.addAll(addressResults.map { it.copy(targetAddress = addressLabel) })
                }

                val ordered = allResults.sortedWith(compareBy({ it.targetAddress }, { it.port }))
                val openCount = ordered.count { it.state == UdpPortState.OPEN }
                val closedCount = ordered.count { it.state == UdpPortState.CLOSED }
                val filteredCount = ordered.count { it.state == UdpPortState.OPEN_FILTERED }
                val errorCount = ordered.count { it.state == UdpPortState.ERROR }
                val notTestedCount = ordered.count { it.state == UdpPortState.NOT_TESTED }
                val attemptsSent = ordered.sumOf { it.attempts }
                val elapsed = System.currentTimeMillis() - startedAt
                val finishedAt = System.currentTimeMillis()

                _uiState.update {
                    it.copy(
                        isScanning = false,
                        completed = ordered.size,
                        total = ordered.size,
                        progress = 1f,
                        openCount = openCount,
                        closedCount = closedCount,
                        openFilteredCount = filteredCount,
                        errorCount = errorCount,
                        notTestedCount = notTestedCount,
                        attemptsSent = attemptsSent,
                        results = ordered,
                        elapsedMs = elapsed,
                        statusMessage = "UDP scan completed"
                    )
                }

                val summary = UdpScanSessionSummary(
                    id = finishedAt,
                    target = target,
                    resolvedAddress = resolvedLabels.joinToString(", "),
                    portRange = range.start.toString() + "-" + range.end,
                    totalPorts = ordered.size,
                    openCount = openCount,
                    closedCount = closedCount,
                    openFilteredCount = filteredCount,
                    errorCount = errorCount,
                    notTestedCount = notTestedCount,
                    attemptsSent = attemptsSent,
                    elapsedMs = elapsed,
                    finishedAtEpochMs = finishedAt,
                    results = ordered
                )
                _history.update { (listOf(summary) + it).take(MAX_HISTORY_ITEMS) }
            } catch (cancelled: CancellationException) {
                _uiState.update { it.copy(isScanning = false, statusMessage = "UDP scan cancelled") }
                throw cancelled
            } catch (exception: Exception) {
                setError("UDP scan failed: " + (exception.message ?: "Unknown error"))
            }
        }
    }

    fun stopScan() {
        scanJob?.cancel()
    }

    fun clearHistory() {
        _history.value = emptyList()
    }

    private fun setError(message: String) {
        _uiState.update {
            it.copy(isScanning = false, statusMessage = message, errorMessage = message)
        }
    }

    companion object {
        const val MAX_TOTAL_SCAN_CHECKS = 16_384
        const val MAX_HISTORY_ITEMS = 10
    }
}
