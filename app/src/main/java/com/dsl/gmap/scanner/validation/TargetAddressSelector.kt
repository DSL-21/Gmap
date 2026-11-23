package com.dsl.gmap.scanner.validation

import java.net.Inet4Address
import java.net.InetAddress

/**
 * Chooses target IPs for a hostname scan.
 *
 * One address is selected by default so a requested port range applies to one
 * endpoint. IPv4 is preferred, then addresses are sorted to keep the selection
 * stable when DNS returns the same set in a different order.
 */
object TargetAddressSelector {
    const val MAX_SCAN_ADDRESSES = 32

    fun select(
        resolvedAddresses: List<InetAddress>,
        scanAllResolvedAddresses: Boolean
    ): List<InetAddress> {
        val uniqueSorted = resolvedAddresses
            .distinctBy { it.hostAddress }
            .sortedWith(
                compareBy<InetAddress>({ if (it is Inet4Address) 0 else 1 }, { it.hostAddress.orEmpty() })
            )

        require(uniqueSorted.isNotEmpty()) { "The target did not resolve to an IP address." }
        if (scanAllResolvedAddresses) {
            require(uniqueSorted.size <= MAX_SCAN_ADDRESSES) {
                "The target resolved to too many addresses. Select one address or reduce the DNS answer set."
            }
            return uniqueSorted
        }
        return uniqueSorted.take(1)
    }
}