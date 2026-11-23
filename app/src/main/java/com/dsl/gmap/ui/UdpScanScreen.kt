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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dsl.gmap.network.ActiveNetworkInspector
import com.dsl.gmap.scanner.engine.UdpDiscoveryResult
import com.dsl.gmap.scanner.engine.UdpMulticastDiscovery
import com.dsl.gmap.scanner.model.UdpPortState
import com.dsl.gmap.scanner.model.UdpScanSettings
import com.dsl.gmap.scanner.viewmodel.UdpScanViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

@Composable
fun UdpScanScreen(viewModel: UdpScanViewModel) {
    val state by viewModel.uiState.collectAsState()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val localNetwork = remember(context) { ActiveNetworkInspector.inspect(context) }
    var target by remember { mutableStateOf("") }
    var startPort by remember { mutableStateOf("1") }
    var endPort by remember { mutableStateOf("256") }
    var timeoutMs by remember { mutableIntStateOf(1000) }
    var retries by remember { mutableIntStateOf(1) }
    var concurrency by remember { mutableIntStateOf(24) }
    var adaptiveConcurrency by remember { mutableStateOf(true) }
    var scanAllResolvedAddresses by remember { mutableStateOf(false) }
    var permissionError by remember { mutableStateOf<String?>(null) }
    var isDiscovering by remember { mutableStateOf(false) }
    var discoveryJob by remember { mutableStateOf<Job?>(null) }
    var discoveryResults by remember { mutableStateOf<List<UdpDiscoveryResult>>(emptyList()) }
    var discoveryWarnings by remember { mutableStateOf<List<String>>(emptyList()) }
    val requestLocalNetworkPermission = rememberLocalNetworkPermissionGate()

    val scanSettings = UdpScanSettings(
        timeoutMs = timeoutMs,
        maxRetries = retries,
        maxConcurrentProbes = concurrency,
        adaptiveConcurrency = adaptiveConcurrency
    )

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(
            "UDP PROBE SCAN",
            color = MaterialTheme.colorScheme.primary,
            style = MaterialTheme.typography.labelLarge,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.5.sp
        )
        Text(
            "Rootless UDP scanner",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )

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
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = { startPort = "1"; endPort = "512" },
                modifier = Modifier.weight(1f),
                enabled = !state.isScanning
            ) { Text("512 ports") }
            OutlinedButton(
                onClick = { startPort = "1"; endPort = UdpProbeLimit.MAX_PORTS.toString() },
                modifier = Modifier.weight(1f),
                enabled = !state.isScanning
            ) { Text("Max · 4096") }
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text("Scan all resolved DNS addresses", fontWeight = FontWeight.SemiBold)
                Text(
                    "Off by default. Turn on to probe every returned IP address.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall
                )
            }
            Switch(
                checked = scanAllResolvedAddresses,
                onCheckedChange = { scanAllResolvedAddresses = it },
                enabled = !state.isScanning
            )
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            shape = RoundedCornerShape(14.dp)
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text("UDP ENGINE SETTINGS", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelLarge)
                Text("Timeout: " + timeoutMs + " ms", style = MaterialTheme.typography.bodySmall)
                Slider(
                    value = timeoutMs.toFloat(),
                    onValueChange = { timeoutMs = it.toInt() },
                    valueRange = 300f..3000f,
                    steps = 26,
                    enabled = !state.isScanning
                )
                Text("Retries for silent ports: " + retries, style = MaterialTheme.typography.bodySmall)
                Slider(
                    value = retries.toFloat(),
                    onValueChange = { retries = it.toInt() },
                    valueRange = 0f..3f,
                    steps = 2,
                    enabled = !state.isScanning
                )
                Text("Maximum concurrent probes: " + concurrency, style = MaterialTheme.typography.bodySmall)
                Slider(
                    value = concurrency.toFloat(),
                    onValueChange = { concurrency = it.toInt() },
                    valueRange = 4f..64f,
                    steps = 14,
                    enabled = !state.isScanning
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Adaptive rate control", modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                    Switch(
                        checked = adaptiveConcurrency,
                        onCheckedChange = { adaptiveConcurrency = it },
                        enabled = !state.isScanning
                    )
                }
            }
        }

        Text(
            "UDP silence is inconclusive. Only a response can confirm an open endpoint; ICMP unreachable may identify a closed port.",
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
                    val start = {
                        viewModel.startScan(
                            target,
                            startPort,
                            endPort,
                            scanAllResolvedAddresses,
                            scanSettings
                        )
                    }
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
            state.resolvedAddress?.let {
                Text("Target IP address(es): " + it, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
            }
            LinearProgressIndicator(
                progress = { state.progress },
                modifier = Modifier.fillMaxWidth()
            )
            Text(
                state.completed.toString() + " / " + state.total + " host/port checks completed",
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                UdpMetric(Modifier.weight(1f), state.openCount.toString(), "OPEN")
                UdpMetric(Modifier.weight(1f), state.closedCount.toString(), "CLOSED")
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                UdpMetric(Modifier.weight(1f), state.openFilteredCount.toString(), "OPEN|FILTERED")
                UdpMetric(Modifier.weight(1f), state.errorCount.toString(), "ERROR")
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                UdpMetric(Modifier.weight(1f), state.notTestedCount.toString(), "NOT TESTED")
                UdpMetric(Modifier.weight(1f), state.attemptsSent.toString(), "PROBE ATTEMPTS")
            }
            state.elapsedMs?.let {
                Text(
                    "Elapsed: " + (it / 1000.0) + " s",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        if (state.results.isNotEmpty()) {
            Text(
                "ALL UDP RESULTS · " + state.results.size,
                color = MaterialTheme.colorScheme.primary,
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.2.sp
            )
            LazyColumn(
                modifier = Modifier.fillMaxWidth().height(420.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(state.results, key = { (it.targetAddress ?: "") + ":" + it.port }) { result ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Column(
                            modifier = Modifier.fillMaxWidth().padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    result.port.toString() + "/UDP",
                                    modifier = Modifier.weight(1f),
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    result.state.name.replace('_', '|'),
                                    color = when (result.state) {
                                        UdpPortState.OPEN -> MaterialTheme.colorScheme.primary
                                        UdpPortState.OPEN_FILTERED -> MaterialTheme.colorScheme.tertiary
                                        UdpPortState.CLOSED -> MaterialTheme.colorScheme.error
                                        UdpPortState.ERROR -> MaterialTheme.colorScheme.error
                                        UdpPortState.NOT_TESTED -> MaterialTheme.colorScheme.onSurfaceVariant
                                    },
                                    fontWeight = FontWeight.Bold,
                                    style = MaterialTheme.typography.labelSmall
                                )
                            }
                            result.targetAddress?.let {
                                Text(it, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            result.serviceHint?.let {
                                Text(
                                    if (result.serviceConfirmed) it + " · verified" else it + " · port hint only",
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                            result.probeName?.let {
                                Text(it, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            Text(result.detail.orEmpty(), style = MaterialTheme.typography.bodySmall)
                            if (result.responseBytes > 0) {
                                Text("Response: " + result.responseBytes + " bytes", style = MaterialTheme.typography.labelSmall)
                            }
                            result.responsePreview?.let {
                                Text("Payload preview: " + it, style = MaterialTheme.typography.labelSmall)
                            }
                            Text("Attempts: " + result.attempts, style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            shape = RoundedCornerShape(14.dp)
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text("LOCAL MULTICAST DISCOVERY", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelLarge)
                Text(
                    "Discover UPnP/SSDP and DNS-SD/mDNS responders on the active local network. This is a separate multicast operation, not a unicast port scan.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall
                )
                Button(
                    onClick = {
                        if (isDiscovering) {
                            discoveryJob?.cancel()
                        } else {
                            val interfaceName = localNetwork.interfaceName
                            if (interfaceName.isNullOrBlank()) {
                                discoveryWarnings = listOf("No active network interface is available.")
                            } else {
                                requestLocalNetworkPermission(
                                    {
                                        discoveryJob = scope.launch {
                                            isDiscovering = true
                                            discoveryWarnings = emptyList()
                                            discoveryResults = emptyList()
                                            try {
                                                val report = UdpMulticastDiscovery().discover(
                                                    context.applicationContext,
                                                    interfaceName
                                                )
                                                discoveryResults = report.responders
                                                discoveryWarnings = report.warnings
                                            } catch (cancelled: CancellationException) {
                                                throw cancelled
                                            } catch (exception: Exception) {
                                                discoveryWarnings = listOf(exception.message ?: "Local discovery failed.")
                                            } finally {
                                                isDiscovering = false
                                                discoveryJob = null
                                            }
                                        }
                                    },
                                    { discoveryWarnings = listOf("Local network access is required for multicast discovery.") }
                                )
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(if (isDiscovering) "Stop local discovery" else "Discover local UDP services")
                }
                if (isDiscovering) {
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                }
                discoveryWarnings.forEach {
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
                discoveryResults.forEach {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(it.protocol + " · " + it.address + ":" + it.port, fontWeight = FontWeight.SemiBold)
                        Text(it.detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                if (!isDiscovering && discoveryResults.isNotEmpty()) {
                    Text(
                        discoveryResults.size.toString() + " multicast responder(s) found.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            }
        }
    }
}

@Composable
private fun UdpMetric(modifier: Modifier, value: String, label: String) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
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

private object UdpProbeLimit {
    const val MAX_PORTS = 4096
}
