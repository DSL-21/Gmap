package com.dsl.gmap.scanner.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.dsl.gmap.scanner.engine.TcpConnectScanner
import com.dsl.gmap.scanner.engine.ServiceDetector
import com.dsl.gmap.scanner.engine.VulnerabilityIntelligenceEngine
import com.dsl.gmap.scanner.model.PortState
import com.dsl.gmap.scanner.model.ScanSessionSummary
import com.dsl.gmap.scanner.model.ScanUiState
import com.dsl.gmap.scanner.model.VulnerabilityAssessment
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
    private val scanner: TcpConnectScanner = TcpConnectScanner(),
    private val serviceDetector: ServiceDetector = ServiceDetector(),
    private val vulnerabilityEngine: VulnerabilityIntelligenceEngine = VulnerabilityIntelligenceEngine()
) : ViewModel() {

    private val _uiState = MutableStateFlow(ScanUiState())
    val uiState: StateFlow<ScanUiState> = _uiState.asStateFlow()

    private val _history = MutableStateFlow<List<ScanSessionSummary>>(emptyList())
    val history: StateFlow<List<ScanSessionSummary>> = _history.asStateFlow()

    private val _timeoutMs = MutableStateFlow(DEFAULT_TIMEOUT_MS)
    val timeoutMs: StateFlow<Int> = _timeoutMs.asStateFlow()

    private val _onlineIntelligenceEnabled = MutableStateFlow(true)
    val onlineIntelligenceEnabled: StateFlow<Boolean> = _onlineIntelligenceEnabled.asStateFlow()

    private var scanJob: Job? = null

    private val _prefillTarget = MutableStateFlow("")
    val prefillTarget: StateFlow<String> = _prefillTarget.asStateFlow()

    fun setPrefillTarget(value: String) {
        _prefillTarget.value = value
    }

    fun clearPrefillTarget() {
        _prefillTarget.value = ""
    }

    fun setTimeoutMs(value: Int) {
        if (value in ALLOWED_TIMEOUTS_MS) _timeoutMs.value = value
    }

    fun setOnlineIntelligenceEnabled(value: Boolean) {
        _onlineIntelligenceEnabled.value = value
    }

    fun clearHistory() {
        _history.value = emptyList()
    }

    fun startScan(
        targetInput: String,
        startPortInput: String,
        endPortInput: String
    ) {
        if (scanJob?.isActive == true) return

        val target = targetInput.trim()
        if (target.isBlank() || target.contains("/") || target.contains("://") || target.any { it.isWhitespace() }) {
            setError("Enter one hostname or IP address. CIDR ranges and URLs are not supported in this build.")
            return
        }
        val portRange = PortRangeParser.parse(startPortInput, endPortInput)
        if (portRange == null) {
            setError("Enter a valid port range between 1 and 65535.")
            return
        }

        val selectedTimeoutMs = _timeoutMs.value
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
                        statusMessage = "Scanning " + address.hostAddress,
                        total = portRange.size
                    )
                }

                val results = scanner.scan(
                    address = address,
                    startPort = portRange.start,
                    endPort = portRange.end,
                    timeoutMs = selectedTimeoutMs
                ) { progress, latestResult ->
                    _uiState.update { current ->
                        val updatedOpenPorts = if (latestResult.state == PortState.OPEN) {
                            (current.openPorts + latestResult)
                                .distinctBy { result -> result.port }
                                .sortedBy { result -> result.port }
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
                            elapsedMs = progress.elapsedMs,
                            probesPerSecond = progress.probesPerSecond,
                            statusMessage = "Scanning " + address.hostAddress
                        )
                    }
                }

                val tcpOpenPorts = results.filter { it.state == PortState.OPEN }
                _uiState.update {
                    it.copy(statusMessage = "Identifying services on " + tcpOpenPorts.size + " open ports...")
                }
                val openPorts = serviceDetector.identify(
                    address = address,
                    originalTarget = target,
                    openPorts = tcpOpenPorts,
                    timeoutMs = selectedTimeoutMs
                )
                val openCount = openPorts.size
                val closedCount = results.count { it.state == PortState.CLOSED }
                val filteredCount = results.count { it.state == PortState.FILTERED }
                val errorCount = results.count { it.state == PortState.ERROR }
                val softwareIdentities = openPorts.mapNotNull { it.fingerprint?.software }
                    .distinctBy { it.cpeName }

                _uiState.update {
                    it.copy(
                        openPorts = openPorts,
                        softwareIdentities = softwareIdentities,
                        isAssessing = true,
                        statusMessage = if (_onlineIntelligenceEnabled.value) {
                            "Checking public vulnerability intelligence..."
                        } else {
                            "Finalizing scan results..."
                        }
                    )
                }

                val assessment = if (_onlineIntelligenceEnabled.value) {
                    try {
                        vulnerabilityEngine.assess(softwareIdentities)
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (exception: Exception) {
                        VulnerabilityAssessment(
                            products = softwareIdentities,
                            findings = emptyList(),
                            message = "Vulnerability lookup failed.",
                            warnings = listOf(exception.message ?: exception.javaClass.simpleName)
                        )
                    }
                } else {
                    VulnerabilityAssessment(
                        products = softwareIdentities,
                        findings = emptyList(),
                        message = "Online vulnerability lookup is disabled in Settings."
                    )
                }

                val elapsed = System.currentTimeMillis() - startedAt
                _uiState.update {
                    it.copy(
                        isScanning = false,
                        isAssessing = false,
                        completed = results.size,
                        total = results.size,
                        progress = 1f,
                        openCount = openCount,
                        closedCount = closedCount,
                        filteredCount = filteredCount,
                        errorCount = errorCount,
                        openPorts = openPorts,
                        softwareIdentities = assessment.products,
                        vulnerabilityFindings = assessment.findings,
                        intelligenceMessage = assessment.message,
                        intelligenceWarnings = assessment.warnings,
                        elapsedMs = elapsed,
                        probesPerSecond = if (elapsed > 0) results.size * 1000.0 / elapsed else 0.0,
                        statusMessage = "Scan completed"
                    )
                }

                val finishedAt = System.currentTimeMillis()
                val session = ScanSessionSummary(
                    id = finishedAt,
                    target = target,
                    resolvedAddress = address.hostAddress ?: target,
                    portRange = portRange.start.toString() + "-" + portRange.end,
                    totalPorts = results.size,
                    openCount = openCount,
                    closedCount = closedCount,
                    filteredCount = filteredCount,
                    errorCount = errorCount,
                    elapsedMs = elapsed,
                    finishedAtEpochMs = finishedAt,
                    openPorts = openPorts,
                    softwareIdentities = assessment.products,
                    vulnerabilityFindings = assessment.findings,
                    intelligenceMessage = assessment.message,
                    intelligenceWarnings = assessment.warnings
                )
                _history.update { (listOf(session) + it).take(MAX_HISTORY_ITEMS) }
            } catch (cancelled: CancellationException) {
                _uiState.update {
                    it.copy(isScanning = false, isAssessing = false, statusMessage = "Scan cancelled")
                }
                throw cancelled
            } catch (exception: Exception) {
                setError("Scan failed: " + (exception.message ?: "Unknown error"))
            }
        }
    }

    fun stopScan() {
        scanJob?.cancel()
    }

    private fun setError(message: String) {
        _uiState.update {
            it.copy(isScanning = false, isAssessing = false, statusMessage = message, errorMessage = message)
        }
    }

    companion object {
        const val DEFAULT_TIMEOUT_MS = 1200
        const val MAX_HISTORY_ITEMS = 20
        val ALLOWED_TIMEOUTS_MS = setOf(500, 1200, 2000, 3500)
    }
}
