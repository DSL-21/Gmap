package com.dsl.gmap.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

data class ActiveNetworkSnapshot(
    val connectionType: String,
    val interfaceName: String?,
    val addresses: List<String>,
    val gateway: String?,
    val dnsServers: List<String>
)

object ActiveNetworkInspector {
    fun inspect(context: Context): ActiveNetworkSnapshot {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = manager.activeNetwork
            ?: return ActiveNetworkSnapshot("Disconnected", null, emptyList(), null, emptyList())

        val capabilities = manager.getNetworkCapabilities(network)
        val properties = manager.getLinkProperties(network)

        val connectionType = when {
            capabilities == null -> "Unknown"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Mobile"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) -> "Bluetooth"
            else -> "Other"
        }

        val addresses = properties?.linkAddresses
            ?.filterNot { it.address.isLoopbackAddress || it.address.isAnyLocalAddress }
            ?.map { "${it.address.hostAddress}/${it.prefixLength}" }
            .orEmpty()

        val gateway = properties?.routes
            ?.firstOrNull { it.isDefaultRoute }
            ?.gateway
            ?.hostAddress

        val dnsServers = properties?.dnsServers
            ?.mapNotNull { it.hostAddress }
            .orEmpty()

        return ActiveNetworkSnapshot(
            connectionType = connectionType,
            interfaceName = properties?.interfaceName,
            addresses = addresses,
            gateway = gateway,
            dnsServers = dnsServers
        )
    }
}
