package com.dsl.gmap.scanner.model

enum class UdpPortState {
    OPEN,
    CLOSED,
    OPEN_FILTERED,
    ERROR
}

data class UdpPortScanResult(
    val port: Int,
    val state: UdpPortState,
    val latencyMs: Long? = null,
    val responseBytes: Int = 0,
    val serviceHint: String? = null,
    val detail: String? = null
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
    val elapsedMs: Long,
    val finishedAtEpochMs: Long,
    val results: List<UdpPortScanResult>
)
