package com.dsl.gmap.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.lifecycle.viewmodel.compose.viewModel
import com.dsl.gmap.scanner.viewmodel.ScanViewModel
import com.dsl.gmap.web.WebAuditViewModel
import com.dsl.gmap.scanner.viewmodel.UdpScanViewModel

private enum class AppTab(val label: String, val icon: ImageVector) {
    DASHBOARD("Network", Icons.Default.Dashboard),
    SCAN("Scan", Icons.Default.Search),
    WEB("Web", Icons.Default.Info),
    HISTORY("Results", Icons.Default.History)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GmapApp() {
    var selectedTab by rememberSaveable { mutableStateOf(AppTab.DASHBOARD) }
    var showSettings by rememberSaveable { mutableStateOf(false) }
    val scanViewModel: ScanViewModel = viewModel()
    val webAuditViewModel: WebAuditViewModel = viewModel()
    val udpScanViewModel: UdpScanViewModel = viewModel()

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                navigationIcon = {
                    if (showSettings) {
                        IconButton(onClick = { showSettings = false }) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                        }
                    }
                },
                title = {
                    Text(
                        if (showSettings) "Settings" else "GMAP",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Black
                    )
                },
                actions = {
                    if (!showSettings) {
                        IconButton(onClick = { showSettings = true }) {
                            Icon(Icons.Default.Settings, contentDescription = "Settings")
                        }
                    }
                }
            )
        },
        bottomBar = {
            if (!showSettings) {
                NavigationBar {
                    AppTab.values().forEach { tab ->
                        NavigationBarItem(
                            selected = selectedTab == tab,
                            onClick = { selectedTab = tab },
                            icon = { Icon(tab.icon, contentDescription = tab.label) },
                            label = { Text(tab.label) }
                        )
                    }
                }
            }
        },
        containerColor = MaterialTheme.colorScheme.background
    ) { innerPadding ->
        Box(modifier = Modifier.padding(innerPadding)) {
            if (showSettings) {
                SettingsScreen(viewModel = scanViewModel)
            } else {
                when (selectedTab) {
                    AppTab.DASHBOARD -> DashboardScreen(onStartScan = { target ->
                        if (target.isNotBlank()) scanViewModel.setPrefillTarget(target)
                        selectedTab = AppTab.SCAN
                    })
                    AppTab.SCAN -> ScannerHubScreen(tcpViewModel = scanViewModel, udpViewModel = udpScanViewModel)
                    AppTab.WEB -> WebScanScreen(viewModel = webAuditViewModel)
                    AppTab.HISTORY -> HistoryScreen(viewModel = scanViewModel, webAuditViewModel = webAuditViewModel, udpScanViewModel = udpScanViewModel)
                }
            }
        }
    }
}
