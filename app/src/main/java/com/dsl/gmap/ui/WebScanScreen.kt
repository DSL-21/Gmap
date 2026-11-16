package com.dsl.gmap.ui

import androidx.compose.foundation.clickable
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
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun WebScanScreen(viewModel: com.dsl.gmap.web.WebAuditViewModel) {
    val state by viewModel.uiState.collectAsState()
    val target = state.target
    val isScanning = state.isScanning || state.isAssessing
    val result = state.result
    val uriHandler = LocalUriHandler.current
    var permissionError by remember { mutableStateOf<String?>(null) }
    val requestLocalNetworkPermission = rememberLocalNetworkPermissionGate()

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(
            "WEB AUDIT",
            color = MaterialTheme.colorScheme.primary,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.5.sp
        )
        OutlinedTextField(
            value = target,
            onValueChange = viewModel::setTarget,
            modifier = Modifier.fillMaxWidth(),
            enabled = !isScanning,
            label = { Text("Hostname or URL") },
            placeholder = { Text("example.com") },
            singleLine = true
        )
        Button(
            onClick = {
                val start = { viewModel.startAudit() }
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
            enabled = target.isNotBlank() && !isScanning,
            modifier = Modifier.fillMaxWidth().height(52.dp),
            shape = RoundedCornerShape(14.dp)
        ) {
            androidx.compose.material3.Icon(Icons.Default.PlayArrow, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text(if (isScanning) "Scanning..." else "Run web audit")
        }

        if (isScanning) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            Text(state.statusMessage, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
        }
        state.errorMessage?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        permissionError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }

        result?.let { audit ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(audit.host, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                    Text(audit.url, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text("HTTP ${audit.httpStatus}", fontWeight = FontWeight.Bold)
                    Text("DNS: ${audit.resolvedAddresses.joinToString(", ")}")
                    audit.tlsCipherSuite?.let { Text("TLS cipher: $it") }
                    audit.certificateSubject?.let { Text("Certificate: $it") }
                    audit.certificateIssuer?.let { Text("Issuer: $it") }
                    if (audit.certificateSans.isNotEmpty()) {
                        Text("SANs: ${audit.certificateSans.joinToString(", ")}", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
                    }
                    audit.redirectChain.drop(1).forEach { Text("Redirect → ${it}", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall) }
                    audit.certificateExpiryEpochMs?.let {
                        Text("Expires: ${SimpleDateFormat("yyyy-MM-dd", Locale.ENGLISH).format(Date(it))}")
                    }
                    audit.redirectLocation?.let { Text("Redirect: $it") }
                }
            }

            if (audit.resources.isNotEmpty()) {
                Text("PUBLIC ENDPOINTS", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                audit.resources.forEach { resource ->
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(resource.path, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                        Text(
                            if (resource.sensitiveExposure) "EXPOSED" else if (resource.statusCode == 0) "NO RESPONSE" else resource.statusCode.toString(),
                            color = if (resource.sensitiveExposure) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }

            if (audit.softwareIdentities.isNotEmpty()) {
                Text("IDENTIFIED SOFTWARE", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                audit.softwareIdentities.forEach { identity ->
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(identity.displayName + " " + identity.version, fontWeight = FontWeight.SemiBold)
                        Text(identity.cpeName, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
            audit.intelligenceMessage?.let {
                Text(it, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
            }
            audit.intelligenceWarnings.forEach {
                Text(it, color = MaterialTheme.colorScheme.tertiary, style = MaterialTheme.typography.bodySmall)
            }
            audit.vulnerabilityFindings.take(20).forEach { finding ->
                Card(
                    modifier = Modifier.fillMaxWidth().clickable { runCatching { uriHandler.openUri(finding.nvdUrl) } },
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                    shape = RoundedCornerShape(14.dp)
                ) {
                    Column(modifier = Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                        Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                            Text(finding.cveId, modifier = Modifier.weight(1f), fontWeight = FontWeight.Bold)
                            Text(finding.cvssSeverity ?: "UNRATED", color = if (finding.isKnownExploited) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                        }
                        Text(finding.productName + " " + finding.version, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
                        Text(
                            (finding.cvssScore?.let { "CVSS " + String.format(Locale.ENGLISH, "%.1f", it) } ?: "CVSS N/A") +
                                " · " + (finding.epssScore?.let { "EPSS " + String.format(Locale.ENGLISH, "%.2f%%", it * 100.0) } ?: "EPSS N/A") +
                                if (finding.isKnownExploited) " · CISA KEV" else "",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(finding.description, maxLines = 4, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodySmall)
                        if (finding.isKnownExploited) {
                            Text("Known exploited · " + (finding.kevDateAdded ?: "date unavailable"), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
                            finding.kevRequiredAction?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                        }
                    }
                }
            }

            Text(
                "FINDINGS · ${audit.findings.size}",
                color = MaterialTheme.colorScheme.primary,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold
            )
            audit.findings.forEach { finding ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                    shape = RoundedCornerShape(14.dp)
                ) {
                    Column(
                        modifier = Modifier.fillMaxWidth().padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Row {
                            Text(
                                finding.severity.name,
                                modifier = Modifier.weight(1f),
                                color = MaterialTheme.colorScheme.primary,
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold
                            )
                        }
                        Text(finding.title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                        Text(finding.evidence, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text(finding.recommendation, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}
