package com.dsl.gmap.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dsl.gmap.scanner.model.UdpPortState
import com.dsl.gmap.scanner.viewmodel.UdpScanViewModel

@Composable
fun UdpScanScreen(viewModel: UdpScanViewModel) {
    val state by viewModel.uiState.collectAsState()
    var target by remember { mutableStateOf("") }
    var startPort by remember { mutableStateOf("1") }
    var endPort by remember { mutableStateOf("256") }
    var permissionError by remember { mutableStateOf<String?>(null) }
    val requestLocalNetworkPermission = rememberLocalNetworkPermissionGate()

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text("UDP PROBE SCAN", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold, letterSpacing = 1.5.sp)
        OutlinedTextField(
            value = target,
            onValueChange = { target = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Target hostname or IP address") },
            placeholder = { Text("192.168.1.1 or example.com") },
            singleLine = true,
            enabled = !state.isScanning
        )

        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            OutlinedTextField(
                value = startPort,
                onValueChange = { startPort = it.filter(Char::isDigit).take(5) },
                modifier = Modifier.weight(1f),
                label = { Text("Start port") },
                enabled = !state.isScanning,
                singleLine = true
            )
            OutlinedTextField(
                value = endPort,
                onValueChange = { endPort = it.filter(Char::isDigit).take(5) },
                modifier = Modifier.weight(1f),
                label = { Text("End port") },
                enabled = !state.isScanning,
                singleLine = true
            )
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = { startPort = "53"; endPort = "53" },
                modifier = Modifier.weight(1f),
                enabled = !state.isScanning
            ) { Text("DNS") }
            OutlinedButton(
                onClick = { startPort = "123"; endPort = "123" },
                modifier = Modifier.weight(1f),
                enabled = !state.isScanning
            ) { Text("NTP") }
            OutlinedButton(
                onClick = { startPort = "1"; endPort = "256" },
                modifier = Modifier.weight(1f),
                enabled = !state.isScanning
            ) { Text("Quick") }
        }
        OutlinedButton(
            onClick = { startPort = "1"; endPort = "512" },
            modifier = Modifier.fillMaxWidth(),
            enabled = !state.isScanning
        ) { Text("Extended · 512 ports") }

        Text(
            "No UDP response is inconclusive. Gmap reports silent ports as OPEN|FILTERED, not CLOSED.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodySmall
        )

        if (state.isScanning) {
            OutlinedButton(
                onClick = viewModel::stopScan,
                modifier = Modifier.fillMaxWidth().height(52.dp)
            ) {
                Icon(Icons.Default.Stop, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Stop UDP scan")
            }
        } else {
            Button(
                onClick = {
                    val start = { viewModel.startScan(target, startPort, endPort) }
                    if (LocalNetworkAccess.targetRequiresPermission(target)) {
                        requestLocalNetworkPermission(
                            { permissionError = null; start() },
                            { permissionError = "Local network access is required for this target. Enable it in Android app permissions." }
                        )
                    } else {
                        permissionError = null
                        start()
                    }
                },
                modifier = Modifier.fillMaxWidth().height(52.dp),
                enabled = target.isNotBlank(),
                shape = RoundedCornerShape(14.dp)
            ) {
                Icon(Icons.Default.PlayArrow, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Start UDP scan", fontWeight = FontWeight.Bold)
            }
        }

        state.errorMessage?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        permissionError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }

        if (state.isScanning || state.total > 0) {
            Text(state.statusMessage, fontWeight = FontWeight.SemiBold)
            LinearProgressIndicator(
                progress = { state.progress },
                modifier = Modifier.fillMaxWidth()
            )
            Text("${state.completed} / ${state.total} ports checked", color = MaterialTheme.colorScheme.onSurfaceVariant)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                UdpMetric(Modifier.weight(1f), state.openCount.toString(), "OPEN")
                UdpMetric(Modifier.weight(1f), state.openFilteredCount.toString(), "OPEN|FILTERED")
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                UdpMetric(Modifier.weight(1f), state.closedCount.toString(), "CLOSED")
                UdpMetric(Modifier.weight(1f), state.errorCount.toString(), "ERROR")
            }
        }

        if (state.total > 0 && state.results.isEmpty() && !state.isScanning) {
            Text(
                "No UDP service returned a response. ${state.openFilteredCount} ports did not reply.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall
            )
        }

        state.results.forEach { result ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("${result.port}/UDP", modifier = Modifier.weight(1f), fontWeight = FontWeight.Bold)
                        Text(
                            result.state.name.replace('_', '|'),
                            color = when (result.state) {
                                UdpPortState.OPEN -> MaterialTheme.colorScheme.primary
                                UdpPortState.OPEN_FILTERED -> MaterialTheme.colorScheme.tertiary
                                else -> MaterialTheme.colorScheme.onSurfaceVariant
                            },
                            fontWeight = FontWeight.Bold,
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                    result.serviceHint?.let { Text(it, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall) }
                    Text(result.detail.orEmpty(), color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
                    if (result.responseBytes > 0) Text("Response: ${result.responseBytes} bytes", style = MaterialTheme.typography.labelSmall)
                }
            }
        }
    }
}

@Composable
private fun UdpMetric(modifier: Modifier, value: String, label: String) {
    Card(modifier = modifier, colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(vertical = 10.dp, horizontal = 4.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text(value, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(label, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
        }
    }
}
