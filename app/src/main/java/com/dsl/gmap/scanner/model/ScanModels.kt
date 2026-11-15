package com.dsl.gmap.scanner.model

enum class PortState { OPEN, CLOSED, FILTERED, ERROR }

data class PortScanResult(
    val port: Int,
    val state: PortState,
    val latencyMs: Long? = null,
    val serviceHint: String? = null,
    val detail: String? = null,
    val fingerprint: ServiceFingerprint? = null
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
    val certificateExpiresAtEpochMs: Long? = null
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
    val elapsedMs: Long? = null,
    val probesPerSecond: Double = 0.0
)

/**
 * A compact in-memory record. We retain open findings and scan statistics,
 * rather than every negative probe, to keep session history lightweight.
 */
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
    val openPorts: List<PortScanResult>
)
