package com.dsl.gmap.scanner.model

enum class PortState { OPEN, CLOSED, FILTERED, ERROR }

data class PortScanResult(
    val port: Int,
    val state: PortState,
    val latencyMs: Long? = null,
    val serviceHint: String? = null,
    val detail: String? = null
)

data class ScanProgress(
    val completed: Int,
    val total: Int,
    val openCount: Int,
    val closedCount: Int,
    val filteredCount: Int,
    val errorCount: Int
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
    val elapsedMs: Long? = null
)
