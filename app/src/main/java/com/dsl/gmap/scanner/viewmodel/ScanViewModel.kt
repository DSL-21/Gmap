package com.dsl.gmap.scanner.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.dsl.gmap.scanner.engine.TcpConnectScanner
import com.dsl.gmap.scanner.engine.ServiceDetector
import com.dsl.gmap.scanner.engine.VulnerabilityIntelligenceEngine
import com.dsl.gmap.scanner.model.PortState
import com.dsl.gmap.scanner.model.ScanSessionSummary
import com.dsl.gmap.scanner.model.TcpScanMode
import com.dsl.gmap.scanner.model.TcpScanSettings
import com.dsl.gmap.scanner.model.ScanUiState
import com.dsl.gmap.scanner.model.VulnerabilityAssessment
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
import java.util.concurrent.TimeUnit

class ScanViewModel @JvmOverloads constructor(
    application: Application,
    private val scanner: TcpConnectScanner = TcpConnectScanner(),
    private val serviceDetector: ServiceDetector = ServiceDetector(),
    private val vulnerabilityEngine: VulnerabilityIntelligenceEngine = VulnerabilityIntelligenceEngine()
) : AndroidViewModel(application) {

    init {
        // Remove legacy persisted scan settings from versions <= 2.8.0.
        application.deleteSharedPreferences(SCAN_SETTINGS_PREFS)
    }

    private val _uiState = MutableStateFlow(ScanUiState())
    val uiState: StateFlow<ScanUiState> = _uiState.asStateFlow()

    private val _history = MutableStateFlow<List<ScanSessionSummary>>(emptyList())
    val history: StateFlow<List<ScanSessionSummary>> = _history.asStateFlow()

    private val _scanSettings = MutableStateFlow(TcpScanSettings.preset(TcpScanMode.BALANCED))
    val scanSettings: StateFlow<TcpScanSettings> = _scanSettings.asStateFlow()

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

    fun setScanMode(mode: TcpScanMode) {
        val current = _scanSettings.value
        val next = if (mode == TcpScanMode.CUSTOM) {
            current.copy(mode = TcpScanMode.CUSTOM)
        } else {
            TcpScanSettings.preset(mode)
        }
        updateScanSettings(next)
    }

    fun updateCustomConcurrency(value: Int) {
        updateScanSettings(_scanSettings.value.copy(mode = TcpScanMode.CUSTOM, maxConcurrentProbes = value))
    }

    fun updateCustomTimeout(value: Int) {
        updateScanSettings(_scanSettings.value.copy(mode = TcpScanMode.CUSTOM, timeoutMs = value))
    }

    fun updateCustomRetries(value: Int) {
        updateScanSettings(_scanSettings.value.copy(mode = TcpScanMode.CUSTOM, maxRetries = value))
    }

    fun setAdaptiveConcurrencyEnabled(value: Boolean) {
        updateScanSettings(_scanSettings.value.copy(mode = TcpScanMode.CUSTOM, adaptiveConcurrency = value))
    }

    private fun updateScanSettings(settings: TcpScanSettings) {
        val normalized = settings.normalized()
        _scanSettings.value = normalized

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
        endPortInput: String,
        scanAllResolvedAddresses: Boolean = false
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

        val selectedScanSettings = _scanSettings.value
        val selectedTimeoutMs = selectedScanSettings.timeoutMs
        scanJob = viewModelScope.launch {
            val startedAt = System.currentTimeMillis()
            _uiState.value = ScanUiState(
                isScanning = true,
                target = target,
                statusMessage = "Resolving target..."
            )

            try {
                // Resolve all DNS answers once, then scan one deterministic address
                // by default. Scanning every answer is an explicit user choice.
                val addresses = withContext(Dispatchers.IO) {
                    InetAddress.getAllByName(target).distinctBy { it.hostAddress }.toList()
                }
                require(addresses.isNotEmpty()) { "The target did not resolve to an IP address." }

                val addressesToScan = TargetAddressSelector.select(addresses, scanAllResolvedAddresses)
                val skippedAddressCount = addresses.size - addressesToScan.size
                val resolvedAddresses = addressesToScan.mapNotNull { it.hostAddress }
                val totalChecks = portRange.size * addressesToScan.size
                require(totalChecks <= MAX_TOTAL_SCAN_CHECKS) {
                    "This scan would require " + totalChecks + " host/port checks. Reduce the port range or scan fewer DNS addresses (limit: " + MAX_TOTAL_SCAN_CHECKS + ")."
                }
                val allResults = ArrayList<com.dsl.gmap.scanner.model.PortScanResult>(totalChecks)
                val identifiedPorts = ArrayList<com.dsl.gmap.scanner.model.PortScanResult>()
                val scanStartedNanos = System.nanoTime()
                val resolutionSummary = resolvedAddresses.joinToString(", ") +
                    if (skippedAddressCount > 0) " (" + skippedAddressCount + " other DNS address(es) not scanned)" else ""

                _uiState.update {
                    it.copy(
                        resolvedAddress = resolutionSummary,
                        statusMessage = "Scanning " + addressesToScan.size + " of " + addresses.size + " resolved address(es)",
                        total = totalChecks
                    )
                }

                addressesToScan.forEachIndexed { addressIndex, address ->
                    val addressLabel = address.hostAddress ?: address.hostName
                    val completedBefore = allResults.size
                    val previousOpen = allResults.count { it.state == PortState.OPEN }
                    val previousClosed = allResults.count { it.state == PortState.CLOSED }
                    val previousFiltered = allResults.count { it.state == PortState.FILTERED }
                    val previousErrors = allResults.count { it.state == PortState.ERROR }

                    _uiState.update {
                        it.copy(statusMessage = "Scanning $addressLabel (${addressIndex + 1}/${addresses.size})")
                    }

                    val addressResults = scanner.scan(
                        address = address,
                        startPort = portRange.start,
                        endPort = portRange.end,
                        settings = selectedScanSettings
                    ) { progress, latestResult ->
                        val taggedResult = latestResult.copy(targetAddress = addressLabel)
                        _uiState.update { current ->
                            val updatedOpenPorts = if (taggedResult.state == PortState.OPEN) {
                                (current.openPorts + taggedResult)
                                    .distinctBy { result -> "${result.targetAddress}:${result.port}" }
                                    .sortedWith(compareBy({ it.targetAddress }, { it.port }))
                            } else {
                                current.openPorts
                            }

                            val completed = completedBefore + progress.completed
                            val elapsedNanos = (System.nanoTime() - scanStartedNanos).coerceAtLeast(1L)
                            current.copy(
                                completed = completed,
                                total = totalChecks,
                                progress = completed.toFloat() / totalChecks.toFloat(),
                                openCount = previousOpen + progress.openCount,
                                closedCount = previousClosed + progress.closedCount,
                                filteredCount = previousFiltered + progress.filteredCount,
                                errorCount = previousErrors + progress.errorCount,
                                openPorts = updatedOpenPorts,
                                elapsedMs = TimeUnit.NANOSECONDS.toMillis(elapsedNanos),
                                probesPerSecond = completed * 1_000_000_000.0 / elapsedNanos,
                                statusMessage = "Scanning $addressLabel (${addressIndex + 1}/${addresses.size})"
                            )
                        }
                    }

                    val taggedResults = addressResults.map { it.copy(targetAddress = addressLabel) }
                    allResults.addAll(taggedResults)
                    val tcpOpenPorts = taggedResults.filter { it.state == PortState.OPEN }
                    _uiState.update {
                        it.copy(statusMessage = "Identifying services on $addressLabel (${tcpOpenPorts.size} open ports)...")
                    }
                    identifiedPorts.addAll(
                        serviceDetector.identify(
                            address = address,
                            originalTarget = target,
                            openPorts = tcpOpenPorts,
                            timeoutMs = selectedTimeoutMs
                        )
                    )
                }

                val results = allResults
                val openPorts = identifiedPorts
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
                    resolvedAddress = resolvedAddresses.joinToString(", "),
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
        private const val SCAN_SETTINGS_PREFS = "gmap_tcp_scan_settings"
        const val MAX_TOTAL_SCAN_CHECKS = 262_144
        const val MAX_HISTORY_ITEMS = 20
    }
}
