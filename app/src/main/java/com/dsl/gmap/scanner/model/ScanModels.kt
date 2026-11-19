package com.dsl.gmap.scanner.model

enum class PortState { OPEN, CLOSED, FILTERED, ERROR }

/**
 * User-facing TCP scan behavior. Profiles are Gmap-native presets, not Nmap timing templates.
 */
enum class TcpScanMode(
    val title: String,
    val description: String
) {
    RELIABLE("Reliable", "More time and retries for slower or filtered networks."),
    BALANCED("Balanced", "A practical balance of speed and result confidence."),
    PERFORMANCE("Performance", "Higher concurrency for responsive networks."),
    MAXIMUM("Maximum", "Highest allowed throughput with bounded retries and adaptive protection."),
    CUSTOM("Custom", "Tune concurrency, timeout, retries and adaptive control yourself.")
}

/**
 * TCP scanner tuning captured at scan start; changing Settings never mutates a running scan.
 */
data class TcpScanSettings(
    val mode: TcpScanMode = TcpScanMode.BALANCED,
    val maxConcurrentProbes: Int = 48,
    val timeoutMs: Int = 1200,
    val maxRetries: Int = 2,
    val adaptiveConcurrency: Boolean = true
) {
    val minConcurrentProbes: Int
        get() = minOf(maxConcurrentProbes, maxOf(4, maxConcurrentProbes / 4))

    fun normalized(): TcpScanSettings = copy(
        maxConcurrentProbes = maxConcurrentProbes.coerceIn(MIN_CONCURRENCY, MAX_CONCURRENCY),
        timeoutMs = timeoutMs.coerceIn(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS),
        maxRetries = maxRetries.coerceIn(0, MAX_RETRIES)
    )

    companion object {
        const val MIN_CONCURRENCY = 4
        const val MAX_CONCURRENCY = 128
        const val MIN_TIMEOUT_MS = 300
        const val MAX_TIMEOUT_MS = 8000
        const val MAX_RETRIES = 5
        const val DEFAULT_TIMEOUT_MS = 1200

        fun preset(mode: TcpScanMode): TcpScanSettings = when (mode) {
            TcpScanMode.RELIABLE -> TcpScanSettings(
                mode = mode,
                maxConcurrentProbes = 24,
                timeoutMs = 2500,
                maxRetries = 3,
                adaptiveConcurrency = true
            )
            TcpScanMode.BALANCED -> TcpScanSettings(
                mode = mode,
                maxConcurrentProbes = 48,
                timeoutMs = 1200,
                maxRetries = 2,
                adaptiveConcurrency = true
            )
            TcpScanMode.PERFORMANCE -> TcpScanSettings(
                mode = mode,
                maxConcurrentProbes = 80,
                timeoutMs = 900,
                maxRetries = 1,
                adaptiveConcurrency = true
            )
            TcpScanMode.MAXIMUM -> TcpScanSettings(
                mode = mode,
                maxConcurrentProbes = 128,
                timeoutMs = 750,
                maxRetries = 1,
                adaptiveConcurrency = true
            )
            TcpScanMode.CUSTOM -> TcpScanSettings(
                mode = mode,
                maxConcurrentProbes = 64,
                timeoutMs = DEFAULT_TIMEOUT_MS,
                maxRetries = 2,
                adaptiveConcurrency = true
            )
        }
    }
}

data class PortScanResult(
    val port: Int,
    val state: PortState,
    val latencyMs: Long? = null,
    val serviceHint: String? = null,
    val detail: String? = null,
    val fingerprint: ServiceFingerprint? = null,
    val targetAddress: String? = null,
    val attempts: Int = 1
)

data class ServiceFingerprint(
    val service: String,
    val banner: String? = null,
    val serverHeader: String? = null,
    val additionalInfo: String? = null,
    val tlsVersion: String? = null,
    val cipherSuite: String? = null,
    val certificateSubject: String? = null,
    val certificateIssuer: String? = null,
    val certificateExpiresAtEpochMs: Long? = null,
    val software: SoftwareIdentity? = null
)

data class ScanProgress(
    val completed: Int,
    val total: Int,
    val openCount: Int,
    val closedCount: Int,
    val filteredCount: Int,
    val errorCount: Int,
    val elapsedMs: Long = 0,
    val probesPerSecond: Double = 0.0
) {
    val fraction: Float
        get() = if (total <= 0) 0f else completed.toFloat() / total.toFloat()
}

data class ScanUiState(
    val isScanning: Boolean = false,
    val isAssessing: Boolean = false,
    val target: String = "",
    val resolvedAddress: String? = null,
    val statusMessage: String = "Ready",
    val errorMessage: String? = null,
    val completed: Int = 0,
    val total: Int = 0,
    val progress: Float = 0f,
    val openCount: Int = 0,
    val closedCount: Int = 0,
    val filteredCount: Int = 0,
    val errorCount: Int = 0,
    val openPorts: List<PortScanResult> = emptyList(),
    val softwareIdentities: List<SoftwareIdentity> = emptyList(),
    val vulnerabilityFindings: List<VulnerabilityFinding> = emptyList(),
    val intelligenceMessage: String? = null,
    val intelligenceWarnings: List<String> = emptyList(),
    val elapsedMs: Long? = null,
    val probesPerSecond: Double = 0.0
)

data class ScanSessionSummary(
    val id: Long,
    val target: String,
    val resolvedAddress: String,
    val portRange: String,
    val totalPorts: Int,
    val openCount: Int,
    val closedCount: Int,
    val filteredCount: Int,
    val errorCount: Int,
    val elapsedMs: Long,
    val finishedAtEpochMs: Long,
    val openPorts: List<PortScanResult>,
    val softwareIdentities: List<SoftwareIdentity> = emptyList(),
    val vulnerabilityFindings: List<VulnerabilityFinding> = emptyList(),
    val intelligenceMessage: String? = null,
    val intelligenceWarnings: List<String> = emptyList()
)
