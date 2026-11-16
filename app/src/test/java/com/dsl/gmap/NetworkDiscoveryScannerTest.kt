package com.dsl.gmap

import com.dsl.gmap.network.Ipv4Subnet
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkDiscoveryScannerTest {
    @Test
    fun expandsSlash24AndExcludesLocalAddress() {
        val hosts = Ipv4Subnet.hostAddresses("192.168.1.10/24")
        assertEquals(253, hosts.size)
        assertFalse(hosts.any { it.hostAddress == "192.168.1.10" })
        assertTrue(hosts.any { it.hostAddress == "192.168.1.1" })
        assertTrue(hosts.any { it.hostAddress == "192.168.1.254" })
    }

    @Test
    fun expandsSlash23() {
        val hosts = Ipv4Subnet.hostAddresses("192.168.2.10/23")
        assertEquals(509, hosts.size)
        assertTrue(hosts.any { it.hostAddress == "192.168.3.254" })
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsLargeSubnetInsteadOfScanningAnUnboundedRange() {
        Ipv4Subnet.hostAddresses("10.0.0.10/16")
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsMalformedCidr() {
        Ipv4Subnet.hostAddresses("192.168.1.1")
    }
}
