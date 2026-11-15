package com.dsl.gmap.scanner.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.dsl.gmap.scanner.engine.TcpConnectScanner
import com.dsl.gmap.scanner.model.PortState
import com.dsl.gmap.scanner.model.ScanUiState
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

class ScanViewModel(
    private val scanner: TcpConnectScanner = TcpConnectScanner()
) : ViewModel() {

    private val _uiState = MutableStateFlow(ScanUiState())
    val uiState: StateFlow<ScanUiState> = _uiState.asStateFlow()
    private var scanJob: Job? = null

    fun startScan(
        targetInput: String,
        startPortInput: String,
        endPortInput: String,
        authorizationConfirmed: Boolean
    ) {
        if (scanJob?.isActive == true) return

        val target = targetInput.trim()
        if (target.isBlank() || target.contains("/") || target.contains("://") || target.any { it.isWhitespace() }) {
            setError("Enter one hostname or IP address. CIDR ranges and URLs are not supported in this build.")
            return
        }
        if (!authorizationConfirmed) {
            setError("Confirm that you own this target or have permission to assess it.")
            return
        }

        val portRange = PortRangeParser.parse(startPortInput, endPortInput)
        if (portRange == null) {
            setError("Enter a valid port range between 1 and 65535.")
            return
        }

        scanJob = viewModelScope.launch {
            val startedAt = System.currentTimeMillis()
            _uiState.value = ScanUiState(
                isScanning = true,
                target = target,
                statusMessage = "Resolving target..."
            )

            try {
                val address = withContext(Dispatchers.IO) { InetAddress.getByName(target) }
                _uiState.update {
                    it.copy(
                        resolvedAddress = address.hostAddress,
                        statusMessage = "Scanning ${address.hostAddress}",
                        total = portRange.size
                    )
                }

                val results = scanner.scan(
                    address = address,
                    startPort = portRange.start,
                    endPort = portRange.end,
                    timeoutMs = 1200,
                    parallelism = 48
                ) { progress, latestResult ->
                    _uiState.update { current ->
                        val updatedOpenPorts = if (latestResult.state == PortState.OPEN) {
                            (current.openPorts + latestResult)
                                .distinctBy { result -> result.port }
                                .sortedBy { result -> result.port }
                                .take(100)
                        } else {
                            current.openPorts
                        }

                        current.copy(
                            completed = maxOf(current.completed, progress.completed),
                            total = progress.total,
                            progress = maxOf(current.progress, progress.fraction),
                            openCount = progress.openCount,
                            closedCount = progress.closedCount,
                            filteredCount = progress.filteredCount,
                            errorCount = progress.errorCount,
                            openPorts = updatedOpenPorts,
                            statusMessage = "Scanning ${address.hostAddress}"
                        )
                    }
                }

                val elapsed = System.currentTimeMillis() - startedAt
                _uiState.update { current ->
                    current.copy(
                        isScanning = false,
                        completed = results.size,
                        total = results.size,
                        progress = 1f,
                        openCount = results.count { it.state == PortState.OPEN },
                        closedCount = results.count { it.state == PortState.CLOSED },
                        filteredCount = results.count { it.state == PortState.FILTERED },
                        errorCount = results.count { it.state == PortState.ERROR },
                        openPorts = results.filter { it.state == PortState.OPEN }.take(100),
                        elapsedMs = elapsed,
                        statusMessage = "Scan completed"
                    )
                }
            } catch (cancelled: CancellationException) {
                _uiState.update { it.copy(isScanning = false, statusMessage = "Scan cancelled") }
                throw cancelled
            } catch (exception: Exception) {
                setError("Scan failed: ${exception.message ?: "Unknown error"}")
            }
        }
    }

    fun stopScan() {
        scanJob?.cancel()
    }

    private fun setError(message: String) {
        _uiState.update {
            it.copy(isScanning = false, statusMessage = message, errorMessage = message)
        }
    }
}
