package com.dsl.gmap.web

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.dsl.gmap.scanner.engine.SoftwareFingerprintParser
import com.dsl.gmap.scanner.engine.VulnerabilityIntelligenceEngine
import com.dsl.gmap.scanner.model.ServiceFingerprint
import com.dsl.gmap.scanner.model.VulnerabilityAssessment
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class WebAuditUiState(
    val target: String = "",
    val isScanning: Boolean = false,
    val isAssessing: Boolean = false,
    val statusMessage: String = "Ready",
    val errorMessage: String? = null,
    val result: WebAuditResult? = null
)

class WebAuditViewModel(
    private val engine: WebAuditEngine = WebAuditEngine(),
    private val vulnerabilityEngine: VulnerabilityIntelligenceEngine = VulnerabilityIntelligenceEngine()
) : ViewModel() {
    private val _uiState = MutableStateFlow(WebAuditUiState())
    val uiState: StateFlow<WebAuditUiState> = _uiState.asStateFlow()

    private val _history = MutableStateFlow<List<WebAuditResult>>(emptyList())
    val history: StateFlow<List<WebAuditResult>> = _history.asStateFlow()

    private val _onlineIntelligenceEnabled = MutableStateFlow(true)
    val onlineIntelligenceEnabled: StateFlow<Boolean> = _onlineIntelligenceEnabled.asStateFlow()

    private var scanJob: Job? = null

    fun setTarget(value: String) {
        _uiState.update { it.copy(target = value) }
    }

    fun setOnlineIntelligenceEnabled(value: Boolean) {
        _onlineIntelligenceEnabled.value = value
    }

    fun startAudit() {
        if (scanJob?.isActive == true) return
        val target = _uiState.value.target
        if (target.isBlank()) {
            _uiState.update { it.copy(errorMessage = "Enter a hostname or URL.") }
            return
        }

        scanJob = viewModelScope.launch {
            _uiState.update {
                it.copy(
                    isScanning = true,
                    isAssessing = false,
                    statusMessage = "Auditing web configuration...",
                    errorMessage = null,
                    result = null
                )
            }

            try {
                val baseResult = engine.scan(target)
                val headers = baseResult.responseHeaders
                val identity = SoftwareFingerprintParser.identify(
                    ServiceFingerprint(
                        service = "HTTP",
                        banner = headers.headerValue("X-AspNet-Version"),
                        serverHeader = headers.headerValue("Server"),
                        additionalInfo = headers.headerValue("X-Powered-By")?.let { "X-Powered-By: " + it }
                    )
                )
                val products = listOfNotNull(identity).distinctBy { it.cpeName }

                _uiState.update {
                    it.copy(
                        isAssessing = true,
                        statusMessage = if (_onlineIntelligenceEnabled.value) {
                            "Checking public vulnerability intelligence..."
                        } else {
                            "Finalizing web audit..."
                        },
                        result = baseResult.copy(softwareIdentities = products)
                    )
                }

                val assessment = if (_onlineIntelligenceEnabled.value) {
                    try {
                        vulnerabilityEngine.assess(products)
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (exception: Exception) {
                        VulnerabilityAssessment(
                            products = products,
                            findings = emptyList(),
                            message = "Web software vulnerability lookup failed.",
                            warnings = listOf(exception.message ?: exception.javaClass.simpleName)
                        )
                    }
                } else {
                    VulnerabilityAssessment(
                        products = products,
                        findings = emptyList(),
                        message = "Online vulnerability lookup is disabled in Settings."
                    )
                }

                val message = if (products.isEmpty() && _onlineIntelligenceEnabled.value) {
                    "No versioned web server software was exposed in the response headers. CVE matching was not possible."
                } else {
                    assessment.message
                }
                val result = baseResult.copy(
                    softwareIdentities = assessment.products,
                    vulnerabilityFindings = assessment.findings,
                    intelligenceMessage = message,
                    intelligenceWarnings = assessment.warnings
                )

                _uiState.update {
                    it.copy(
                        isScanning = false,
                        isAssessing = false,
                        statusMessage = "Web audit completed",
                        result = result
                    )
                }
                _history.update { (listOf(result) + it).take(MAX_HISTORY_ITEMS) }
            } catch (cancelled: CancellationException) {
                _uiState.update {
                    it.copy(isScanning = false, isAssessing = false, statusMessage = "Web audit cancelled")
                }
                throw cancelled
            } catch (exception: Exception) {
                _uiState.update {
                    it.copy(
                        isScanning = false,
                        isAssessing = false,
                        statusMessage = "Web audit failed",
                        errorMessage = exception.message ?: "Web audit failed."
                    )
                }
            }
        }
    }

    fun clearHistory() {
        _history.value = emptyList()
    }

    private fun Map<String, List<String>>.headerValue(name: String): String? =
        entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value?.firstOrNull()

    companion object {
        const val MAX_HISTORY_ITEMS = 15
    }
}
