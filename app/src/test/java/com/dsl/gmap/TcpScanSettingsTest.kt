package com.dsl.gmap

import com.dsl.gmap.scanner.model.TcpScanMode
import com.dsl.gmap.scanner.model.TcpScanSettings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TcpScanSettingsTest {

    @Test
    fun presetsUseIncreasingConcurrencyAndBoundedRetries() {
        val reliable = TcpScanSettings.preset(TcpScanMode.RELIABLE)
        val balanced = TcpScanSettings.preset(TcpScanMode.BALANCED)
        val performance = TcpScanSettings.preset(TcpScanMode.PERFORMANCE)
        val maximum = TcpScanSettings.preset(TcpScanMode.MAXIMUM)

        assertTrue(reliable.maxConcurrentProbes < balanced.maxConcurrentProbes)
        assertTrue(balanced.maxConcurrentProbes < performance.maxConcurrentProbes)
        assertTrue(performance.maxConcurrentProbes < maximum.maxConcurrentProbes)
        assertEquals(128, maximum.maxConcurrentProbes)
        listOf(reliable, balanced, performance, maximum).forEach {
            assertTrue(it.maxRetries in 0..TcpScanSettings.MAX_RETRIES)
            assertTrue(it.timeoutMs in TcpScanSettings.MIN_TIMEOUT_MS..TcpScanSettings.MAX_TIMEOUT_MS)
            assertTrue(it.adaptiveConcurrency)
        }
    }

    @Test
    fun customSettingsAreClampedToSafeSupportedBounds() {
        val settings = TcpScanSettings(
            mode = TcpScanMode.CUSTOM,
            maxConcurrentProbes = 999,
            timeoutMs = 50,
            maxRetries = 20,
            adaptiveConcurrency = false
        ).normalized()

        assertEquals(TcpScanSettings.MAX_CONCURRENCY, settings.maxConcurrentProbes)
        assertEquals(TcpScanSettings.MIN_TIMEOUT_MS, settings.timeoutMs)
        assertEquals(TcpScanSettings.MAX_RETRIES, settings.maxRetries)
        assertTrue(!settings.adaptiveConcurrency)
    }

    @Test
    fun customMinimumConcurrencyNeverExceedsMaximum() {
        val settings = TcpScanSettings(
            mode = TcpScanMode.CUSTOM,
            maxConcurrentProbes = 4
        )
        assertTrue(settings.minConcurrentProbes <= settings.maxConcurrentProbes)
        assertTrue(settings.minConcurrentProbes >= TcpScanSettings.MIN_CONCURRENCY)
    }
}
