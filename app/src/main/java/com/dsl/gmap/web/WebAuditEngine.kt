package com.dsl.gmap.web

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URI
import java.security.cert.X509Certificate
import java.util.Locale
import javax.net.ssl.HttpsURLConnection

enum class FindingSeverity { INFO, LOW, MEDIUM, HIGH }

data class WebFinding(
    val severity: FindingSeverity,
    val title: String,
    val evidence: String,
    val recommendation: String
)

data class WebAuditResult(
    val url: String,
    val host: String,
    val resolvedAddresses: List<String>,
    val httpStatus: Int,
    val responseHeaders: Map<String, List<String>>,
    val tlsCipherSuite: String?,
    val certificateSubject: String?,
    val certificateIssuer: String?,
    val certificateExpiryEpochMs: Long?,
    val redirectLocation: String?,
    val findings: List<WebFinding>
)

class WebAuditEngine {
    suspend fun scan(input: String): WebAuditResult = withContext(Dispatchers.IO) {
        val uri = normalize(input)
        val host = requireNotNull(uri.host)
        val addresses = InetAddress.getAllByName(host).mapNotNull { it.hostAddress }.distinct()

        val connection = (uri.toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = "HEAD"
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            instanceFollowRedirects = false
            useCaches = false
            setRequestProperty("User-Agent", "Gmap/2.1")
            setRequestProperty("Accept", "*/*")
            setRequestProperty("Connection", "close")
        }

        try {
            val status = connection.responseCode
            val headers = connection.headerFields
                .filterKeys { it != null }
                .mapKeys { requireNotNull(it.key) }
                .mapValues { (_, values) -> values.filterNotNull() }

            val tls = (connection as? HttpsURLConnection)?.let { https ->
                val certificate = runCatching {
                    https.serverCertificates.filterIsInstance<X509Certificate>().firstOrNull()
                }.getOrNull()
                TlsDetails(
                    cipherSuite = runCatching { https.cipherSuite }.getOrNull(),
                    subject = certificate?.subjectX500Principal?.name,
                    issuer = certificate?.issuerX500Principal?.name,
                    expiry = certificate?.notAfter?.time
                )
            }

            val redirect = headers.header("Location")
            val findings = buildFindings(uri, status, headers, tls)

            WebAuditResult(
                url = uri.toString(),
                host = host,
                resolvedAddresses = addresses,
                httpStatus = status,
                responseHeaders = headers,
                tlsCipherSuite = tls?.cipherSuite,
                certificateSubject = tls?.subject,
                certificateIssuer = tls?.issuer,
                certificateExpiryEpochMs = tls?.expiry,
                redirectLocation = redirect,
                findings = findings
            )
        } finally {
            connection.disconnect()
        }
    }

    private fun normalize(input: String): URI {
        val raw = input.trim()
        require(raw.isNotEmpty()) { "Enter a hostname or URL." }
        val candidate = if (raw.contains("://")) raw else "https://$raw"
        val uri = runCatching { URI(candidate) }
            .getOrElse { throw IllegalArgumentException("Enter a valid hostname or URL.") }

        val scheme = uri.scheme?.lowercase(Locale.ROOT)
        require(scheme == "http" || scheme == "https") {
            "Only HTTP and HTTPS URLs are supported."
        }
        require(!uri.host.isNullOrBlank() && uri.userInfo == null) {
            "The URL must contain a hostname and must not contain embedded credentials."
        }
        require(uri.port == -1 || uri.port in 1..65535) { "Invalid TCP port in URL." }
        require(uri.rawFragment == null) { "URL fragments are not sent to the web server." }

        return URI(
            scheme,
            null,
            uri.host,
            uri.port,
            uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/",
            uri.rawQuery,
            null
        )
    }

    private fun buildFindings(
        uri: URI,
        status: Int,
        headers: Map<String, List<String>>,
        tls: TlsDetails?
    ): List<WebFinding> {
        val findings = mutableListOf<WebFinding>()
        val https = uri.scheme.equals("https", ignoreCase = true)

        val redirectsToHttps = status in 300..399 &&
            headers.header("Location")?.startsWith("https://", ignoreCase = true) == true

        if (!https && !redirectsToHttps) {
            findings += WebFinding(
                FindingSeverity.MEDIUM,
                "HTTP without TLS",
                "The target responded over plain HTTP without an HTTPS redirect.",
                "Serve the site over HTTPS and redirect HTTP requests to the HTTPS endpoint."
            )
        } else if (https && headers.header("Strict-Transport-Security").isNullOrBlank()) {
            findings += WebFinding(
                FindingSeverity.LOW,
                "HSTS header missing",
                "Strict-Transport-Security was not present in the response.",
                "Consider enabling HSTS after confirming that all required site paths support HTTPS."
            )
        }

        if (headers.header("Content-Security-Policy").isNullOrBlank()) {
            findings += WebFinding(
                FindingSeverity.LOW,
                "Content Security Policy missing",
                "No Content-Security-Policy response header was found.",
                "Define a policy appropriate to the site, starting in report-only mode if necessary."
            )
        }

        if (headers.header("X-Content-Type-Options").isNullOrBlank()) {
            findings += WebFinding(
                FindingSeverity.LOW,
                "MIME-sniffing protection missing",
                "X-Content-Type-Options was not present.",
                "Set X-Content-Type-Options: nosniff where compatible with the application."
            )
        }

        val csp = headers.header("Content-Security-Policy").orEmpty()
        if (headers.header("X-Frame-Options").isNullOrBlank() &&
            !csp.contains("frame-ancestors", ignoreCase = true)
        ) {
            findings += WebFinding(
                FindingSeverity.LOW,
                "Clickjacking protection not detected",
                "Neither X-Frame-Options nor a CSP frame-ancestors directive was found.",
                "Set an appropriate frame-ancestors CSP directive or X-Frame-Options."
            )
        }

        if (headers.header("Referrer-Policy").isNullOrBlank()) {
            findings += WebFinding(
                FindingSeverity.INFO,
                "Referrer Policy not set",
                "No Referrer-Policy response header was found.",
                "Set a Referrer-Policy that matches the site's privacy requirements."
            )
        }

        headers.header("Server")?.takeIf { it.isNotBlank() }?.let { server ->
            findings += WebFinding(
                FindingSeverity.INFO,
                "Server header disclosed",
                server,
                "Review whether the server banner needs to expose implementation or version details."
            )
        }

        headers.headerValues("Set-Cookie").forEach { cookie ->
            val attributes = cookie.split(';').drop(1).map { it.trim().lowercase(Locale.ROOT) }
            val lower = cookie.lowercase(Locale.ROOT)
            val cookieName = cookie.substringBefore(';').take(100)

            if (https && "secure" !in attributes) {
                findings += WebFinding(
                    FindingSeverity.LOW,
                    "Cookie without Secure attribute",
                    cookie.take(180),
                    "Add the Secure attribute to cookies that should only travel over HTTPS."
                )
            }
            if ("httponly" !in attributes) {
                findings += WebFinding(
                    FindingSeverity.INFO,
                    "Cookie without HttpOnly attribute",
                    cookieName,
                    "Use HttpOnly for cookies that do not need to be read by client-side scripts."
                )
            }
            if (attributes.none { it.startsWith("samesite=") }) {
                findings += WebFinding(
                    FindingSeverity.LOW,
                    "Cookie without SameSite attribute",
                    cookieName,
                    "Set an appropriate SameSite value for session and authentication cookies."
                )
            }
        }

        if (status in 300..399) {
            findings += WebFinding(
                FindingSeverity.INFO,
                "Redirect returned",
                headers.header("Location") ?: "HTTP $status without a Location header.",
                "Review the redirect destination and repeat the audit against the final canonical URL."
            )
        } else if (status >= 500) {
            findings += WebFinding(
                FindingSeverity.INFO,
                "Server error response",
                "The server returned HTTP $status to a HEAD request.",
                "Review the endpoint logs and confirm that HEAD is supported; this result alone does not prove a vulnerability."
            )
        }

        if (tls?.expiry != null && tls.expiry < System.currentTimeMillis() + THIRTY_DAYS_MS) {
            findings += WebFinding(
                FindingSeverity.MEDIUM,
                "TLS certificate expires soon",
                "The peer certificate expires at epoch milliseconds ${tls.expiry}.",
                "Renew the certificate before its expiry date."
            )
        }

        return findings.distinctBy { it.title to it.evidence }
    }

    private fun Map<String, List<String>>.headerValues(name: String): List<String> =
        entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value.orEmpty()

    private fun Map<String, List<String>>.header(name: String): String? =
        headerValues(name).takeIf { it.isNotEmpty() }?.joinToString(", ")

    private data class TlsDetails(
        val cipherSuite: String?,
        val subject: String?,
        val issuer: String?,
        val expiry: Long?
    )

    companion object {
        private const val CONNECT_TIMEOUT_MS = 5000
        private const val READ_TIMEOUT_MS = 5000
        private const val THIRTY_DAYS_MS = 30L * 24 * 60 * 60 * 1000
    }
}
