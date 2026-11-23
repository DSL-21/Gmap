package com.dsl.gmap

import com.dsl.gmap.scanner.engine.UdpProbeCatalog
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UdpProbeCatalogTest {
    @Test
    fun dnsProbeUsesUniqueTransactionAndValidatesMatchingResponse() {
        val definition = UdpProbeCatalog.forPort(53, 1)
        val id = definition.transactionId!!
        val response = ByteArray(12)
        response[0] = (id ushr 8).toByte()
        response[1] = id.toByte()
        response[2] = 0x81.toByte()
        response[3] = 0x80.toByte()
        response[5] = 1
        response[7] = 1

        val assessment = UdpProbeCatalog.assessResponse(definition, response)

        assertTrue(assessment.serviceConfirmed)
        assertTrue(assessment.detail.contains("DNS response"))
    }

    @Test
    fun dnsProbeRejectsMismatchedTransactionId() {
        val definition = UdpProbeCatalog.forPort(53, 2)
        val response = ByteArray(12)
        response[0] = 0x12
        response[1] = 0x34
        response[2] = 0x81.toByte()

        val assessment = UdpProbeCatalog.assessResponse(definition, response)

        assertFalse(assessment.serviceConfirmed)
    }

    @Test
    fun ntpProbeRequiresAValidServerModeResponse() {
        val definition = UdpProbeCatalog.forPort(123, 1)
        val response = ByteArray(48)
        response[0] = ((4 shl 3) or 4).toByte()

        assertTrue(UdpProbeCatalog.assessResponse(definition, response).serviceConfirmed)
        assertFalse(UdpProbeCatalog.assessResponse(definition, ByteArray(20)).serviceConfirmed)
    }

    @Test
    fun genericProbeIsAnExplicitSingleZeroByteDatagram() {
        val definition = UdpProbeCatalog.forPort(9999, 1)
        assertEquals(1, definition.payload?.size)
        assertEquals(0, definition.payload?.single()?.toInt())
    }

    @Test
    fun credentialledFileAndMulticastProtocolsAreNotFalselyUnicastProbed() {
        listOf(67, 68, 69, 161, 162, 500, 4500, 1900, 5353).forEach { port ->
            val definition = UdpProbeCatalog.forPort(port, 1)
            assertEquals("Port " + port, null, definition.payload)
            assertTrue("Port " + port, definition.notTestedReason?.isNotBlank() == true)
        }
    }

    @Test
    fun udpSettingsAreBounded() {
        val settings = com.dsl.gmap.scanner.model.UdpScanSettings(
            timeoutMs = 10_000,
            maxRetries = 10,
            maxConcurrentProbes = 200
        ).normalized()

        assertEquals(5000, settings.timeoutMs)
        assertEquals(3, settings.maxRetries)
        assertEquals(64, settings.maxConcurrentProbes)
        assertEquals(16, settings.minConcurrency)
    }

    @Test
    fun mdnsQueryUsesOnePtrQuestion() {
        val query = UdpProbeCatalog.buildMdnsServiceDiscoveryQuery()
        assertTrue(query.size > 30)
        assertEquals(1, query[5].toInt() and 0xff)
        assertEquals(12, query[query.size - 3].toInt() and 0xff)
        assertEquals(1, query[query.size - 1].toInt() and 0xff)
    }
}
