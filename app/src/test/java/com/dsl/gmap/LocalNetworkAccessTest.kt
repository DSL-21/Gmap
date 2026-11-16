package com.dsl.gmap

import com.dsl.gmap.ui.LocalNetworkAccess
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalNetworkAccessTest {
    @Test
    fun detectsPrivateIpv4Targets() {
        assertTrue(LocalNetworkAccess.targetRequiresPermission("192.168.1.1"))
        assertTrue(LocalNetworkAccess.targetRequiresPermission("10.0.0.12"))
        assertTrue(LocalNetworkAccess.targetRequiresPermission("172.16.2.10"))
    }

    @Test
    fun detectsLocalNamesAndIpv6LocalAddresses() {
        assertTrue(LocalNetworkAccess.targetRequiresPermission("printer.local"))
        assertTrue(LocalNetworkAccess.targetRequiresPermission("router"))
        assertTrue(LocalNetworkAccess.targetRequiresPermission("nas.lan"))
        assertTrue(LocalNetworkAccess.targetRequiresPermission("localhost"))
        assertTrue(LocalNetworkAccess.targetRequiresPermission("fe80::1"))
        assertTrue(LocalNetworkAccess.targetRequiresPermission("fc00::1"))
    }

    @Test
    fun detectsLocalHostsWhenProvidedAsFullUrls() {
        assertTrue(LocalNetworkAccess.targetRequiresPermission("http://192.168.1.1/"))
        assertTrue(LocalNetworkAccess.targetRequiresPermission("https://printer.local/status"))
        assertTrue(LocalNetworkAccess.targetRequiresPermission("http://router:8080/"))
        assertTrue(LocalNetworkAccess.targetRequiresPermission("http://[fe80::1]/"))
    }

    @Test
    fun doesNotRequestLanPermissionForPublicTargets() {
        assertFalse(LocalNetworkAccess.targetRequiresPermission("8.8.8.8"))
        assertFalse(LocalNetworkAccess.targetRequiresPermission("example.com"))
    }
}
