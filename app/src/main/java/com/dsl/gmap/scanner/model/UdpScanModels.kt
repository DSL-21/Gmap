package com.dsl.gmap.scanner.model

enum class UdpPortState {
    OPEN,
    CLOSED,
    OPEN_FILTERED,
    ERROR,
    NOT_TESTED
}

data class UdpScanSettings(
    val timeoutMs: Int = 1000,
    val maxRetries: Int = 1,
    val maxConcurrentProbes: Int = 24,
    val adaptiveConcurrency: Boolean = true
) {
    val minConcurrency: Int
        get() = minOf(maxConcurrentProbes, maxOf(MIN_CONCURRENCY, maxConcurrentProbes / 4))

    fun normalized(): UdpScanSettings = copy(
        timeoutMs = timeoutMs.coerceIn(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS),
        maxRetries = maxRetries.coerceIn(MIN_RETRIES, MAX_RETRIES),
        maxConcurrentProbes = maxConcurrentProbes.coerceIn(MIN_CONCURRENCY, MAX_CONCURRENCY)
    )

    companion object {
        const val MIN_TIMEOUT_MS = 100
        const val MAX_TIMEOUT_MS = 5000
        const val MIN_RETRIES = 0
        const val MAX_RETRIES = 3
        const val MIN_CONCURRENCY = 4
        const val MAX_CONCURRENCY = 64
    }
}

data class UdpPortScanResult(
    val port: Int,
    val state: UdpPortState,
    val latencyMs: Long? = null,
    val responseBytes: Int = 0,
    val serviceHint: String? = null,
    val detail: String? = null,
    val targetAddress: String? = null,
    val probeName: String? = null,
    val serviceConfirmed: Boolean = false,
    val attempts: Int = 0,
    val responsePreview: String? = null
)

data class UdpScanProgress(
    val completed: Int,
    val total: Int,
    val openCount: Int,
    val closedCount: Int,
    val openFilteredCount: Int,
    val errorCount: Int,
    val notTestedCount: Int,
    val attemptsSent: Int,
    val elapsedMs: Long,
    val probesPerSecond: Double
)

data class UdpScanUiState(
    val isScanning: Boolean = false,
    val target: String = "",
    val resolvedAddress: String? = null,
    val statusMessage: String = "Ready",
    val errorMessage: String? = null,
    val completed: Int = 0,
    val total: Int = 0,
    val progress: Float = 0f,
    val openCount: Int = 0,
    val closedCount: Int = 0,
    val openFilteredCount: Int = 0,
    val errorCount: Int = 0,
    val notTestedCount: Int = 0,
    val attemptsSent: Int = 0,
    val results: List<UdpPortScanResult> = emptyList(),
    val elapsedMs: Long? = null
)

data class UdpScanSessionSummary(
    val id: Long,
    val target: String,
    val resolvedAddress: String,
    val portRange: String,
    val totalPorts: Int,
    val openCount: Int,
    val closedCount: Int,
    val openFilteredCount: Int,
    val errorCount: Int,
    val notTestedCount: Int,
    val attemptsSent: Int,
    val elapsedMs: Long,
    val finishedAtEpochMs: Long,
    val results: List<UdpPortScanResult>
)
