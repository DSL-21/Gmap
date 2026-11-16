package com.dsl.gmap

import com.dsl.gmap.network.DeviceRoleClassifier
import com.dsl.gmap.network.Ipv4Subnet
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkDiscoveryScannerTest {
    @Test
    fun calculatesUsableHostsFor24Subnet() {
        val hosts = Ipv4Subnet.hostAddresses("192.168.1.10/24")
        assertEquals(253, hosts.size)
        assertEquals("192.168.1.1", hosts.first().hostAddress)
        assertEquals("192.168.1.254", hosts.last().hostAddress)
        assertTrue(hosts.none { it.hostAddress == "192.168.1.10" })
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsSubnetsLargerThanMobileDiscoveryLimit() {
        Ipv4Subnet.hostAddresses("192.168.0.10/21")
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsHostnamesInCidrInput() {
        Ipv4Subnet.hostAddresses("router.local/24")
    }

    @Test
    fun classifiesCommonDeviceRolesFromOpenPorts() {
        assertEquals("Printer", DeviceRoleClassifier.classify(listOf(631, 9100)))
        assertEquals("NAS / File sharing", DeviceRoleClassifier.classify(listOf(445, 5000)))
        assertEquals("Camera / IoT", DeviceRoleClassifier.classify(listOf(554, 1883)))
        assertEquals("Remote access", DeviceRoleClassifier.classify(listOf(3389)))
        assertEquals("Web service", DeviceRoleClassifier.classify(listOf(80, 443)))
    }
}
