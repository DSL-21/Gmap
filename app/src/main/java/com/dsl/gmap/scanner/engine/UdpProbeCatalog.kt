package com.dsl.gmap.scanner.engine

import java.nio.charset.StandardCharsets

enum class UdpResponseKind {
    DNS,
    NTP,
    GENERIC
}

data class UdpProbeDefinition(
    val name: String,
    val serviceHint: String?,
    val payload: ByteArray?,
    val responseKind: UdpResponseKind,
    val notTestedReason: String? = null,
    val transactionId: Int? = null
)

data class UdpResponseAssessment(
    val serviceConfirmed: Boolean,
    val detail: String
)

/**
 * Safe, unauthenticated UDP probes. Protocols which require credentials, a file
 * operation, or multicast discovery are deliberately not sent by a unicast sweep.
 */
object UdpProbeCatalog {
    fun forPort(port: Int, attempt: Int): UdpProbeDefinition = when (port) {
        53 -> {
            val id = dnsTransactionId(port, attempt)
            UdpProbeDefinition(
                name = "DNS A query for example.com",
                serviceHint = "DNS",
                payload = dnsAQuery(id),
                responseKind = UdpResponseKind.DNS,
                transactionId = id
            )
        }
        123 -> UdpProbeDefinition(
            name = "NTP client time request",
            serviceHint = "NTP",
            payload = ntpClientRequest(),
            responseKind = UdpResponseKind.NTP
        )
        67, 68 -> notTested(
            "DHCP",
            "DHCP is a broadcast client/server exchange and is not meaningfully tested with a unicast host probe."
        )
        69 -> notTested(
            "TFTP",
            "TFTP requires a read/write filename request. Gmap does not guess filenames or initiate file transfers."
        )
        161, 162 -> notTested(
            "SNMP",
            "SNMP requires an explicitly configured SNMP version and security credentials/community. No default community is sent."
        )
        500, 4500 -> notTested(
            "IPsec / IKE",
            "IKE requires a protocol-specific negotiation. A generic datagram cannot verify this service."
        )
        1900 -> notTested(
            "SSDP",
            "SSDP discovery uses multicast M-SEARCH. Use the separate local multicast discovery action."
        )
        5353 -> notTested(
            "mDNS",
            "mDNS uses link-local multicast. Use the separate local multicast discovery action."
        )
        else -> UdpProbeDefinition(
            name = "Generic one-byte UDP probe (0x00)",
            serviceHint = serviceHint(port),
            payload = byteArrayOf(0x00),
            responseKind = UdpResponseKind.GENERIC
        )
    }

    fun assessResponse(
        definition: UdpProbeDefinition,
        response: ByteArray
    ): UdpResponseAssessment = when (definition.responseKind) {
        UdpResponseKind.DNS -> {
            val valid = response.size >= 12 &&
                definition.transactionId != null &&
                readUnsignedShort(response, 0) == definition.transactionId &&
                (response[2].toInt() and 0x80) != 0 &&
                readUnsignedShort(response, 4) == 1
            if (valid) {
                UdpResponseAssessment(true, "A matching DNS response was received.")
            } else {
                UdpResponseAssessment(
                    false,
                    "A UDP datagram was received, but it did not match the DNS query. The port is responsive; DNS service is unconfirmed."
                )
            }
        }
        UdpResponseKind.NTP -> {
            val first = response.firstOrNull()?.toInt()?.and(0xff) ?: 0
            val version = (first ushr 3) and 0x07
            val mode = first and 0x07
            val valid = response.size >= 48 && version in 3..4 && mode == 4
            if (valid) {
                UdpResponseAssessment(true, "A valid NTP server response was received.")
            } else {
                UdpResponseAssessment(
                    false,
                    "A UDP datagram was received, but it did not match the expected NTP server response."
                )
            }
        }
        UdpResponseKind.GENERIC -> UdpResponseAssessment(
            false,
            "A UDP datagram was received. The endpoint is responsive, but the application protocol was not identified."
        )
    }

    fun buildMdnsServiceDiscoveryQuery(): ByteArray {
        val name = "_services._dns-sd._udp.local"
        val encodedName = name.split('.').flatMap { label ->
            listOf(label.length.toByte()) + label.toByteArray(StandardCharsets.US_ASCII).toList()
        }.toByteArray() + byteArrayOf(0)
        return byteArrayOf(
            0, 0,             // Transaction ID
            0, 0,             // Standard query
            0, 1,             // One question
            0, 0, 0, 0, 0, 0 // No answer/authority/additional records
        ) + encodedName + byteArrayOf(
            0, 12,            // PTR
            0, 1              // IN
        )
    }

    private fun notTested(service: String, reason: String) = UdpProbeDefinition(
        name = "$service probe not sent",
        serviceHint = service,
        payload = null,
        responseKind = UdpResponseKind.GENERIC,
        notTestedReason = reason
    )

    private fun dnsTransactionId(port: Int, attempt: Int): Int =
        (0x474d xor (port shl 1) xor (attempt * 37)) and 0xffff

    private fun dnsAQuery(transactionId: Int): ByteArray {
        val qname = byteArrayOf(
            7, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(),
            'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            3, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0
        )
        return byteArrayOf(
            (transactionId ushr 8).toByte(), transactionId.toByte(),
            0x01, 0x00, // RD
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ) + qname + byteArrayOf(0x00, 0x01, 0x00, 0x01)
    }

    private fun ntpClientRequest(): ByteArray =
        ByteArray(48).also { it[0] = 0x23 } // NTPv4 client mode

    private fun readUnsignedShort(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun serviceHint(port: Int): String? = when (port) {
        7 -> "Echo"
        9 -> "Discard"
        37 -> "Time"
        49 -> "TACACS"
        53 -> "DNS"
        67, 68 -> "DHCP"
        69 -> "TFTP"
        111 -> "RPCbind"
        123 -> "NTP"
        137 -> "NetBIOS Name Service"
        161, 162 -> "SNMP"
        500, 4500 -> "IPsec / IKE"
        514 -> "Syslog"
        1900 -> "SSDP"
        5353 -> "mDNS"
        5355 -> "LLMNR"
        else -> null
    }
}
