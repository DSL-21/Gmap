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
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import com.dsl.gmap.web.WebAuditEngine
import com.dsl.gmap.web.WebAuditResult
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun WebScanScreen() {
    var target by remember { mutableStateOf("") }
    var isScanning by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var result by remember { mutableStateOf<WebAuditResult?>(null) }
    val scope = rememberCoroutineScope()

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(
            "WEB AUDIT",
            color = MaterialTheme.colorScheme.primary,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.5f
        )
        OutlinedTextField(
            value = target,
            onValueChange = { target = it },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isScanning,
            label = { Text("Hostname or URL") },
            placeholder = { Text("example.com") },
            singleLine = true
        )
        Button(
            onClick = {
                isScanning = true
                error = null
                result = null
                scope.launch {
                    try {
                        result = WebAuditEngine().scan(target)
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (exception: Exception) {
                        error = exception.message ?: "Web audit failed."
                    } finally {
                        isScanning = false
                    }
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

        if (isScanning) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }

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
                    audit.certificateExpiryEpochMs?.let {
                        Text("Expires: ${SimpleDateFormat("yyyy-MM-dd", Locale.ENGLISH).format(Date(it))}")
                    }
                    audit.redirectLocation?.let { Text("Redirect: $it") }
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
