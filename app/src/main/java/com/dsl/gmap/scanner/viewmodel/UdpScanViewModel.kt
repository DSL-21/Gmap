package com.dsl.gmap.scanner.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.dsl.gmap.scanner.engine.UdpProbeScanner
import com.dsl.gmap.scanner.model.UdpPortState
import com.dsl.gmap.scanner.model.UdpScanSessionSummary
import com.dsl.gmap.scanner.model.UdpScanUiState
import com.dsl.gmap.scanner.validation.PortRangeParser
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

    fun startScan(targetInput: String, startPortInput: String, endPortInput: String) {
        if (scanJob?.isActive == true) return

        val target = targetInput.trim()
        if (target.isBlank() || target.contains("/") || target.contains("://") || target.any { it.isWhitespace() }) {
            setError("Enter one hostname or IP address.")
            return
        }

        val range = PortRangeParser.parse(startPortInput, endPortInput)
        if (range == null) {
            setError("Enter a valid UDP port range between 1 and 65535.")
            return
        }
        if (range.size > UdpProbeScanner.MAX_PORTS_PER_SCAN) {
            setError("UDP scans are limited to ${UdpProbeScanner.MAX_PORTS_PER_SCAN} ports per run.")
            return
        }

        scanJob = viewModelScope.launch {
            val startedAt = System.currentTimeMillis()
            _uiState.value = UdpScanUiState(
                isScanning = true,
                target = target,
                statusMessage = "Resolving target..."
            )
            try {
                val address = withContext(Dispatchers.IO) { InetAddress.getByName(target) }
                _uiState.update {
                    it.copy(
                        resolvedAddress = address.hostAddress,
                        total = range.size,
                        statusMessage = "Probing UDP services on ${address.hostAddress}"
                    )
                }

                val results = scanner.scan(
                    address = address,
                    startPort = range.start,
                    endPort = range.end
                ) { completed, total, latest ->
                    _uiState.update { current ->
                        val stored = if (latest.state == UdpPortState.OPEN) {
                            (current.results.filterNot { it.port == latest.port } + latest).sortedBy { it.port }
                        } else {
                            current.results.filterNot { it.port == latest.port }
                        }
                        current.copy(
                            completed = completed,
                            total = total,
                            progress = completed.toFloat() / total.coerceAtLeast(1),
                            openCount = resultsCountAfter(current, latest, UdpPortState.OPEN),
                            closedCount = resultsCountAfter(current, latest, UdpPortState.CLOSED),
                            openFilteredCount = resultsCountAfter(current, latest, UdpPortState.OPEN_FILTERED),
                            errorCount = resultsCountAfter(current, latest, UdpPortState.ERROR),
                            results = stored
                        )
                    }
                }

                val elapsed = System.currentTimeMillis() - startedAt
                val openCount = results.count { it.state == UdpPortState.OPEN }
                val closedCount = results.count { it.state == UdpPortState.CLOSED }
                val openFilteredCount = results.count { it.state == UdpPortState.OPEN_FILTERED }
                val errorCount = results.count { it.state == UdpPortState.ERROR }
                val visible = results.filter { it.state == UdpPortState.OPEN }

                _uiState.update {
                    it.copy(
                        isScanning = false,
                        completed = results.size,
                        total = results.size,
                        progress = 1f,
                        openCount = openCount,
                        closedCount = closedCount,
                        openFilteredCount = openFilteredCount,
                        errorCount = errorCount,
                        results = visible,
                        elapsedMs = elapsed,
                        statusMessage = "UDP scan completed"
                    )
                }

                val finishedAt = System.currentTimeMillis()
                val summary = UdpScanSessionSummary(
                    id = finishedAt,
                    target = target,
                    resolvedAddress = address.hostAddress ?: target,
                    portRange = "${range.start}-${range.end}",
                    totalPorts = results.size,
                    openCount = openCount,
                    closedCount = closedCount,
                    openFilteredCount = openFilteredCount,
                    errorCount = errorCount,
                    elapsedMs = elapsed,
                    finishedAtEpochMs = finishedAt,
                    results = visible
                )
                _history.update { (listOf(summary) + it).take(MAX_HISTORY_ITEMS) }
            } catch (cancelled: CancellationException) {
                _uiState.update { it.copy(isScanning = false, statusMessage = "UDP scan cancelled") }
                throw cancelled
            } catch (exception: Exception) {
                setError("UDP scan failed: ${exception.message ?: "Unknown error"}")
            }
        }
    }

    fun stopScan() {
        scanJob?.cancel()
    }

    fun clearHistory() {
        _history.value = emptyList()
    }

    private fun resultsCountAfter(
        current: UdpScanUiState,
        latest: com.dsl.gmap.scanner.model.UdpPortScanResult,
        selected: UdpPortState
    ): Int {
        val old = current.results.firstOrNull { it.port == latest.port }?.state
        return current.run {
            val currentCount = when (selected) {
                UdpPortState.OPEN -> openCount
                UdpPortState.CLOSED -> closedCount
                UdpPortState.OPEN_FILTERED -> openFilteredCount
                UdpPortState.ERROR -> errorCount
            }
            currentCount + (if (latest.state == selected) 1 else 0) - (if (old == selected) 1 else 0)
        }
    }

    private fun setError(message: String) {
        _uiState.update { it.copy(isScanning = false, statusMessage = message, errorMessage = message) }
    }

    companion object {
        const val MAX_HISTORY_ITEMS = 20
    }
}
