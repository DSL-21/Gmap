package com.dsl.gmap

import com.dsl.gmap.scanner.validation.TargetAddressSelector
import org.junit.Assert.assertEquals
import org.junit.Test
import java.net.InetAddress

class TargetAddressSelectorTest {
    @Test
    fun defaultSelectsOneDeterministicIpv4Address() {
        val addresses = listOf(
            InetAddress.getByName("2001:db8::1"),
            InetAddress.getByName("192.0.2.20"),
            InetAddress.getByName("192.0.2.10")
        )

        val selected = TargetAddressSelector.select(addresses, scanAllResolvedAddresses = false)

        assertEquals(1, selected.size)
        assertEquals("192.0.2.10", selected.single().hostAddress)
    }

    @Test
    fun allAddressModeReturnsEveryUniqueAddressInStableOrder() {
        val first = InetAddress.getByName("192.0.2.10")
        val second = InetAddress.getByName("2001:db8::1")
        val selected = TargetAddressSelector.select(
            listOf(second, first, first),
            scanAllResolvedAddresses = true
        )

        assertEquals(listOf("192.0.2.10", "2001:db8:0:0:0:0:0:1"), selected.map { it.hostAddress })
    }
}