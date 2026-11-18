package com.dsl.gmap.ui

import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.launch
import androidx.compose.material.icons.filled.Search

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dsl.gmap.scanner.model.PortScanResult
import com.dsl.gmap.scanner.model.ScanSessionSummary
import com.dsl.gmap.scanner.model.VulnerabilityFinding
import com.dsl.gmap.scanner.viewmodel.ScanViewModel
import com.dsl.gmap.web.WebAuditViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ScannerHubScreen(
    tcpViewModel: ScanViewModel,
    udpViewModel: com.dsl.gmap.scanner.viewmodel.UdpScanViewModel
) {
    var udpMode by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            if (udpMode) {
                OutlinedButton(onClick = { udpMode = false }, modifier = Modifier.weight(1f)) { Text("TCP") }
                Button(onClick = { udpMode = true }, modifier = Modifier.weight(1f)) { Text("UDP") }
            } else {
                Button(onClick = { udpMode = false }, modifier = Modifier.weight(1f)) { Text("TCP") }
                OutlinedButton(onClick = { udpMode = true }, modifier = Modifier.weight(1f)) { Text("UDP") }
            }
        }
        Box(modifier = Modifier.weight(1f)) {
            if (udpMode) UdpScanScreen(udpViewModel) else ScanScreen(tcpViewModel)
        }
    }
}

@Composable
fun DashboardScreen(
    onStartScan: (String) -> Unit
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    val requestLocalNetworkPermission = rememberLocalNetworkPermissionGate()
    var network by remember { mutableStateOf(com.dsl.gmap.network.ActiveNetworkInspector.inspect(context)) }
    var discoveryJob by remember { mutableStateOf<kotlinx.coroutines.Job?>(null) }
    var discoveredHosts by remember { mutableStateOf<List<com.dsl.gmap.network.DiscoveredHost>>(emptyList()) }
    var discoveryProgress by remember { mutableStateOf<Pair<Int, Int>?>(null) }
    var discoveryError by remember { mutableStateOf<String?>(null) }
    val localIpv4 = network.addresses.firstOrNull { it.contains('.') && it.contains('/') }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(
                    "NETWORK",
                    color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.2.sp
                )
                Text(
                    network.connectionType,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
            }
            OutlinedButton(
                onClick = {
                    network = com.dsl.gmap.network.ActiveNetworkInspector.inspect(context)
                    discoveredHosts = emptyList()
                    discoveryProgress = null
                    discoveryError = null
                }
            ) {
                Text("Refresh")
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            shape = RoundedCornerShape(18.dp)
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    "LOCAL IP",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    localIpv4?.substringBefore('/') ?: "Not connected",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
                Row(horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                    Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text("GATEWAY", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.labelSmall)
                        Text(network.gateway ?: "—", style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text("INTERFACE", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.labelSmall)
                        Text(network.interfaceName ?: "—", style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                }
                Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text("DNS", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.labelSmall)
                    Text(
                        network.dnsServers.ifEmpty { listOf("—") }.joinToString(" · "),
                        style = MaterialTheme.typography.bodyMedium,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "DEVICES",
                modifier = Modifier.weight(1f),
                color = MaterialTheme.colorScheme.primary,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp
            )
            Text(discoveredHosts.size.toString(), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        }

        Button(
            onClick = {
                if (discoveryJob != null) {
                    discoveryJob?.cancel()
                } else {
                    val cidr = localIpv4
                    if (cidr == null) {
                        discoveryError = "No active IPv4 network."
                    } else {
                        requestLocalNetworkPermission(
                            {
                                discoveredHosts = emptyList()
                                discoveryProgress = 0 to 0
                                discoveryError = null
                                discoveryJob = scope.launch {
                                    try {
                                        discoveredHosts = com.dsl.gmap.network.NetworkDiscoveryScanner().scan(cidr) { done, total ->
                                            discoveryProgress = done to total
                                        }
                                    } catch (cancelled: kotlinx.coroutines.CancellationException) {
                                        throw cancelled
                                    } catch (exception: Exception) {
                                        discoveryError = exception.message ?: "Discovery failed."
                                    } finally {
                                        discoveryJob = null
                                    }
                                }
                            },
                            {
                                discoveryError = "Local network access is required to discover devices. Enable it in Android app permissions."
                            }
                        )
                    }
                }
            },
            modifier = Modifier.fillMaxWidth().height(52.dp),
            shape = RoundedCornerShape(14.dp)
        ) {
            Icon(
                if (discoveryJob != null) Icons.Default.Stop else Icons.Default.Radar,
                contentDescription = null
            )
            Spacer(Modifier.width(8.dp))
            Text(if (discoveryJob != null) "Stop discovery" else "Scan local network")
        }

        discoveryProgress?.let { (done, total) ->
            if (discoveryJob != null) {
                Text(
                    "Scanning ${done} / ${total}",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall
                )
                LinearProgressIndicator(
                    progress = { if (total > 0) done.toFloat() / total else 0f },
                    modifier = Modifier.fillMaxWidth()
                )
            } else if (discoveryError == null && discoveredHosts.isEmpty()) {
                Text("No responding hosts found.", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
            } else if (discoveryError == null) {
                Text("${done} / ${total} addresses checked", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
            }
        }

        discoveryError?.let {
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }

        discoveredHosts.forEach { host ->
            Card(
                modifier = Modifier.fillMaxWidth().clickable { onStartScan(host.address) },
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                shape = RoundedCornerShape(14.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(host.address, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                        Text(host.likelyRole, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.SemiBold)
                        Text(host.openPorts.joinToString(" · ") { "${it}/tcp" }.ifBlank { "No detected open ports" }, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
                    }
                    Text(
                        "${host.latencyMs} ms",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.labelSmall
                    )
                }
            }
        }

        OutlinedButton(
            onClick = { onStartScan("") },
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Default.Search, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("Scan a host")
        }
    }
}

@Composable
private fun NetworkInfoRow(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            label.uppercase(Locale.ENGLISH),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Bold,
            letterSpacing = 0.8.sp
        )
        Text(
            value,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}

@Composable
fun ScanScreen(viewModel: ScanViewModel) {
    val state by viewModel.uiState.collectAsState()
    val timeoutMs by viewModel.timeoutMs.collectAsState()
    val prefillTarget by viewModel.prefillTarget.collectAsState()
    // Scan inputs are ephemeral and are not persisted.
    var target by remember { mutableStateOf("") }
    var startPort by remember { mutableStateOf("1") }
    var endPort by remember { mutableStateOf("1024") }
    var permissionError by remember { mutableStateOf<String?>(null) }
    val requestLocalNetworkPermission = rememberLocalNetworkPermissionGate()

    LaunchedEffect(prefillTarget) {
        if (prefillTarget.isNotBlank()) {
            target = prefillTarget
            viewModel.clearPrefillTarget()
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(
            "NEW SCAN",
            color = MaterialTheme.colorScheme.primary,
            style = MaterialTheme.typography.labelLarge,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.5.sp
        )
        Text("TCP Connect scan", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)

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
                singleLine = true,
                enabled = !state.isScanning
            )
            OutlinedTextField(
                value = endPort,
                onValueChange = { endPort = it.filter(Char::isDigit).take(5) },
                modifier = Modifier.weight(1f),
                label = { Text("End port") },
                singleLine = true,
                enabled = !state.isScanning
            )
        }

        Text("QUICK PORT PROFILES", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold, letterSpacing = 1.2.sp)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { startPort = "1"; endPort = "256" }, modifier = Modifier.weight(1f), enabled = !state.isScanning) {
                Text("Quick", maxLines = 1)
            }
            OutlinedButton(onClick = { startPort = "1"; endPort = "1024" }, modifier = Modifier.weight(1f), enabled = !state.isScanning) {
                Text("Well-known", maxLines = 1)
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { startPort = "1"; endPort = "10000" }, modifier = Modifier.weight(1f), enabled = !state.isScanning) {
                Text("Extended", maxLines = 1)
            }
            OutlinedButton(onClick = { startPort = "1"; endPort = "65535" }, modifier = Modifier.weight(1f), enabled = !state.isScanning) {
                Text("Full TCP", maxLines = 1)
            }
        }

        Text(
            "Connection timeout: ${timeoutMs} ms (change in Settings)",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        if (state.isScanning) {
            OutlinedButton(
                onClick = viewModel::stopScan,
                modifier = Modifier.fillMaxWidth().height(52.dp),
                shape = RoundedCornerShape(14.dp)
            ) {
                Icon(Icons.Default.Stop, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text(if (state.isAssessing) "Cancel assessment" else "Stop scan")
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
                shape = RoundedCornerShape(14.dp)
            ) {
                Icon(Icons.Default.PlayArrow, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Start TCP scan", fontWeight = FontWeight.Bold)
            }
        }

        if (state.isScanning || state.total > 0) {
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text(state.statusMessage, fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    state.resolvedAddress?.let {
                        Text(
                            "Resolved address: $it",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                    if (state.isScanning) {
                        LinearProgressIndicator(progress = { state.progress }, modifier = Modifier.fillMaxWidth())
                    }
                    Text(
                        "${state.completed} / ${state.total} ports checked",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodySmall
                    )
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            MetricCard(Modifier.weight(1f), state.openCount.toString(), "OPEN")
                            MetricCard(Modifier.weight(1f), state.closedCount.toString(), "CLOSED")
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            MetricCard(Modifier.weight(1f), state.filteredCount.toString(), "NO RESPONSE")
                            MetricCard(Modifier.weight(1f), state.errorCount.toString(), "ERROR")
                        }
                    }
                    state.elapsedMs?.let {
                        Text(
                            "Elapsed: ${it / 1000.0}s  •  Rate: ${state.probesPerSecond.toLong()} probes/s",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
        }

        state.errorMessage?.let {
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }
        permissionError?.let {
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }

        if (state.total > 0) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
            Text(
                "OPEN PORTS",
                color = MaterialTheme.colorScheme.primary,
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.5.sp
            )
            if (state.openPorts.isEmpty()) {
                Text(
                    if (state.isScanning) "No open ports found yet." else "No open ports detected.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodyMedium
                )
            } else {
                state.openPorts.forEach { PortResultRow(it) }
            }
        }

        if (state.total > 0 && (!state.isScanning || state.isAssessing || state.softwareIdentities.isNotEmpty())) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
            Text(
                "SECURITY INTELLIGENCE",
                color = MaterialTheme.colorScheme.primary,
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.2.sp
            )
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    if (state.softwareIdentities.isNotEmpty()) {
                        Text("IDENTIFIED SOFTWARE", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                        state.softwareIdentities.forEach { identity ->
                            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(identity.displayName + " " + identity.version, fontWeight = FontWeight.SemiBold)
                                Text(identity.cpeName, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.labelSmall)
                            }
                        }
                    }
                    if (state.isAssessing) {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                        Text("Querying NVD, CISA KEV and FIRST EPSS...", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
                    }
                    state.intelligenceMessage?.let {
                        Text(it, style = MaterialTheme.typography.bodySmall)
                    }
                    state.intelligenceWarnings.forEach {
                        Text(it, color = MaterialTheme.colorScheme.tertiary, style = MaterialTheme.typography.bodySmall)
                    }
                    if (!state.isAssessing && state.vulnerabilityFindings.isEmpty() && state.softwareIdentities.isNotEmpty()) {
                        Text(
                            "No matching CVE records were returned. This is not proof that the host is free of vulnerabilities.",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
            state.vulnerabilityFindings.take(25).forEach { VulnerabilityResultCard(it) }
            if (state.vulnerabilityFindings.size > 25) {
                Text("Showing 25 of " + state.vulnerabilityFindings.size + " findings.", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
fun HistoryScreen(
    viewModel: ScanViewModel,
    webAuditViewModel: com.dsl.gmap.web.WebAuditViewModel,
    udpScanViewModel: com.dsl.gmap.scanner.viewmodel.UdpScanViewModel
) {
    val sessions by viewModel.history.collectAsState()
    val webAudits by webAuditViewModel.history.collectAsState()
    val udpSessions by udpScanViewModel.history.collectAsState()

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("RESULTS", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold, letterSpacing = 1.5.sp)
                Text("Recent results", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            }
            if (sessions.isNotEmpty() || webAudits.isNotEmpty() || udpSessions.isNotEmpty()) {
                OutlinedButton(onClick = {
                    viewModel.clearHistory()
                    webAuditViewModel.clearHistory()
                    udpScanViewModel.clearHistory()
                }) {
                    Icon(Icons.Default.DeleteSweep, contentDescription = null)
                    Spacer(Modifier.width(6.dp))
                    Text("Clear")
                }
            }
        }

        if (sessions.isEmpty() && webAudits.isEmpty() && udpSessions.isEmpty()) {
            EmptyFeatureCard(
                heading = "No results yet",
                description = "Your scan results will appear here."
            )
        }

        if (sessions.isNotEmpty()) {
            Text("HOST SCANS", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold)
            sessions.forEach { session -> HistorySessionCard(session) }
        }


        if (udpSessions.isNotEmpty()) {
            Text("UDP SCANS", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold)
            udpSessions.forEach { session ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Column(
                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(session.target, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                        Text(session.resolvedAddress, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
                        Text("UDP ports ${session.portRange} · ${session.totalPorts} checked", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text("${session.openCount} open")
                            Text("${session.openFilteredCount} open|filtered", color = MaterialTheme.colorScheme.tertiary)
                            Text("${session.closedCount} closed")
                        }
                        session.results.forEach { result ->
                            Text(
                                "${result.port}/UDP · ${result.state.name.replace('_', '|')}${result.serviceHint?.let { " · $it" } ?: ""}",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                }
            }
        }

        if (webAudits.isNotEmpty()) {
            Text("WEB AUDITS", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold)
            webAudits.forEach { audit ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Column(
                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(audit.host, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                        Text(audit.url, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text("HTTP ${audit.httpStatus}")
                            Text("${audit.findings.size} findings", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                        }
                        audit.findings.take(4).forEach { finding ->
                            Text(
                                "${finding.severity.name} · ${finding.title}",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun HistorySessionCard(session: ScanSessionSummary) {
    val dateText = SimpleDateFormat("MMM d, HH:mm", Locale.ENGLISH).format(Date(session.finishedAtEpochMs))
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        shape = RoundedCornerShape(18.dp)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(session.target, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(session.resolvedAddress, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
            Text("$dateText  •  TCP ports ${session.portRange}", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                MetricCard(Modifier.weight(1f), session.openCount.toString(), "OPEN")
                MetricCard(Modifier.weight(1f), session.totalPorts.toString(), "CHECKED")
                MetricCard(Modifier.weight(1f), "${session.elapsedMs / 1000.0}s", "DURATION")
            }
            if (session.openPorts.isNotEmpty()) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
                Text("OPEN PORTS", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                session.openPorts.forEach { PortResultRow(it) }
            } else {
                Text("No open TCP ports detected.", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
            }
            if (session.softwareIdentities.isNotEmpty()) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
                Text("IDENTIFIED SOFTWARE", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                session.softwareIdentities.forEach { identity ->
                    Text(identity.displayName + " " + identity.version, style = MaterialTheme.typography.bodySmall)
                }
            }
            if (session.vulnerabilityFindings.isNotEmpty()) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
                Text("VULNERABILITIES · " + session.vulnerabilityFindings.size, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                session.vulnerabilityFindings.take(5).forEach { VulnerabilityResultCard(it) }
            }
            session.intelligenceMessage?.let {
                Text(it, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
fun SettingsScreen(viewModel: ScanViewModel, webAuditViewModel: WebAuditViewModel) {
    val timeoutMs by viewModel.timeoutMs.collectAsState()
    val onlineIntelligenceEnabled by viewModel.onlineIntelligenceEnabled.collectAsState()
    val webOnlineIntelligenceEnabled by webAuditViewModel.onlineIntelligenceEnabled.collectAsState()
    val options = listOf(500, 1200, 2000, 3500)

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text("SCAN TIMEOUT", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold, letterSpacing = 1.2.sp)
        Text("TCP connection wait", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(
            "Choose how long each connection attempt may wait.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodyMedium
        )

        options.chunked(2).forEach { rowOptions ->
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                rowOptions.forEach { option ->
                    val label = if (option < 1000) "${option} ms" else "${option / 1000.0}s"
                    if (timeoutMs == option) {
                        Button(onClick = { viewModel.setTimeoutMs(option) }, modifier = Modifier.weight(1f)) {
                            Text(label)
                        }
                    } else {
                        OutlinedButton(onClick = { viewModel.setTimeoutMs(option) }, modifier = Modifier.weight(1f)) {
                            Text(label)
                        }
                    }
                }
                if (rowOptions.size == 1) Spacer(Modifier.weight(1f))
            }
        }

        HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text("ONLINE CVE INTELLIGENCE", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                Text("Check identified product versions against NVD, CISA KEV and FIRST EPSS after a scan.", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
            }
            Switch(
                checked = onlineIntelligenceEnabled,
                onCheckedChange = viewModel::setOnlineIntelligenceEnabled
            )
        }
        HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text("WEB CVE INTELLIGENCE", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                Text("Correlate exposed web server versions with NVD, CISA KEV and FIRST EPSS.", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
            }
            Switch(
                checked = webOnlineIntelligenceEnabled,
                onCheckedChange = webAuditViewModel::setOnlineIntelligenceEnabled
            )
        }
        HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
        Text("PRIVACY", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        Text(
            "Scan history and findings stay in RAM only. Online lookups send product CPEs and CVE IDs to public providers, never target IP addresses or hostnames. No scan database, report files, analytics or cloud sync are used.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodyMedium
        )
    }
}

@Composable
private fun EmptyFeatureCard(heading: String, description: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        shape = RoundedCornerShape(18.dp)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Icon(Icons.Default.Info, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(38.dp))
            Text(heading, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(description, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun MetricCard(
    modifier: Modifier = Modifier,
    value: String,
    label: String
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        shape = RoundedCornerShape(14.dp)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp, horizontal = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text(value, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(
                label,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                maxLines = 1
            )
        }
    }
}

@Composable
private fun FeatureRow(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    description: String
) {
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Surface(color = MaterialTheme.colorScheme.surfaceVariant, shape = RoundedCornerShape(12.dp)) {
            Box(modifier = Modifier.size(44.dp), contentAlignment = Alignment.Center) {
                Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            }
        }
        Spacer(Modifier.width(12.dp))
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, fontWeight = FontWeight.SemiBold)
            Text(description, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun PortResultRow(result: PortScanResult) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f), RoundedCornerShape(12.dp))
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text("${result.port} / TCP", fontWeight = FontWeight.Bold)
            result.targetAddress?.let { address ->
                Text(address, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.labelSmall)
            }
            Text(
                result.fingerprint?.service ?: result.serviceHint ?: "Unknown service",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall
            )
            result.fingerprint?.let { fingerprint ->
                val detailLines = listOfNotNull(
                    fingerprint.banner?.let { "Banner: $it" },
                    fingerprint.serverHeader?.let { "Server: $it" },
                    fingerprint.additionalInfo,
                    fingerprint.software?.let { "Product: " + it.displayName + " " + it.version },
                    fingerprint.software?.let { "CPE: " + it.cpeName },
                    fingerprint.tlsVersion?.let { "TLS: $it" },
                    fingerprint.cipherSuite?.let { "Cipher: $it" },
                    fingerprint.certificateSubject?.let { "Certificate subject: $it" },
                    fingerprint.certificateIssuer?.let { "Certificate issuer: $it" },
                    fingerprint.certificateExpiresAtEpochMs?.let {
                        "Certificate expires: ${SimpleDateFormat("yyyy-MM-dd", Locale.ENGLISH).format(Date(it))}"
                    }
                )
                detailLines.forEach { line ->
                    Text(
                        line,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.labelSmall,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
        Surface(color = MaterialTheme.colorScheme.primary.copy(alpha = 0.14f), shape = RoundedCornerShape(100.dp)) {
            Text(
                result.state.name,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold
            )
        }
        result.latencyMs?.let {
            Spacer(Modifier.width(10.dp))
            Text(
                "${it} ms",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.labelSmall
            )
        }
    }
}


@Composable
private fun VulnerabilityResultCard(finding: VulnerabilityFinding) {
    val uriHandler = LocalUriHandler.current
    val severityColor = when (finding.cvssSeverity?.uppercase()) {
        "CRITICAL", "HIGH" -> MaterialTheme.colorScheme.error
        "MEDIUM" -> MaterialTheme.colorScheme.tertiary
        else -> MaterialTheme.colorScheme.primary
    }

    Card(
        modifier = Modifier.fillMaxWidth().clickable { runCatching { uriHandler.openUri(finding.nvdUrl) } },
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        shape = RoundedCornerShape(14.dp)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(7.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(finding.cveId, modifier = Modifier.weight(1f), fontWeight = FontWeight.Bold)
                Text(
                    finding.cvssSeverity ?: "UNRATED",
                    color = severityColor,
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold
                )
            }
            Text(
                finding.productName + " " + finding.version,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall
            )
            Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                Text(
                    finding.cvssScore?.let { "CVSS " + String.format(Locale.ENGLISH, "%.1f", it) } ?: "CVSS N/A",
                    color = severityColor,
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    finding.epssScore?.let { "EPSS " + String.format(Locale.ENGLISH, "%.2f%%", it * 100.0) } ?: "EPSS N/A",
                    style = MaterialTheme.typography.labelMedium
                )
                if (finding.isKnownExploited) {
                    Text("CISA KEV", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                }
            }
            Text(
                finding.description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 4,
                overflow = TextOverflow.Ellipsis
            )
            finding.weakness?.let {
                Text(it, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.labelSmall)
            }
            if (finding.isKnownExploited) {
                Text(
                    "Known exploited · Added " + (finding.kevDateAdded ?: "date unavailable"),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold
                )
                finding.kevRequiredAction?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
            Text(
                "CPE match from a service banner · verify vendor patch/backport status · tap for NVD",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.labelSmall
            )
        }
    }
}
