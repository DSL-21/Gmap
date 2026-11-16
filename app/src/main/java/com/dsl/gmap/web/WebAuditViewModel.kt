package com.dsl.gmap.web

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
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
    val errorMessage: String? = null,
    val result: WebAuditResult? = null
)

class WebAuditViewModel(
    private val engine: WebAuditEngine = WebAuditEngine()
) : ViewModel() {
    private val _uiState = MutableStateFlow(WebAuditUiState())
    val uiState: StateFlow<WebAuditUiState> = _uiState.asStateFlow()

    private val _history = MutableStateFlow<List<WebAuditResult>>(emptyList())
    val history: StateFlow<List<WebAuditResult>> = _history.asStateFlow()

    private var scanJob: Job? = null

    fun setTarget(value: String) {
        _uiState.update { it.copy(target = value) }
    }

    fun startAudit() {
        if (scanJob?.isActive == true) return
        val target = _uiState.value.target
        if (target.isBlank()) {
            _uiState.update { it.copy(errorMessage = "Enter a hostname or URL.") }
            return
        }

        scanJob = viewModelScope.launch {
            _uiState.update { it.copy(isScanning = true, errorMessage = null, result = null) }
            try {
                val result = engine.scan(target)
                _uiState.update { it.copy(isScanning = false, result = result) }
                _history.update { (listOf(result) + it).take(MAX_HISTORY_ITEMS) }
            } catch (cancelled: CancellationException) {
                _uiState.update { it.copy(isScanning = false) }
                throw cancelled
            } catch (exception: Exception) {
                _uiState.update {
                    it.copy(isScanning = false, errorMessage = exception.message ?: "Web audit failed.")
                }
            }
        }
    }

    fun clearHistory() {
        _history.value = emptyList()
    }

    companion object {
        const val MAX_HISTORY_ITEMS = 15
    }
}
