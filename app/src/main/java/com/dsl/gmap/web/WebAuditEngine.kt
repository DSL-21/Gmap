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

data class WebResourceCheck(
    val path: String,
    val statusCode: Int,
    val contentType: String?,
    val sensitiveExposure: Boolean = false
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
    val findings: List<WebFinding>,
    val finalUrl: String = url,
    val redirectChain: List<String> = emptyList(),
    val certificateSans: List<String> = emptyList(),
    val usedGetFallback: Boolean = false,
    val resources: List<WebResourceCheck> = emptyList()
)

class WebAuditEngine {
    suspend fun scan(input: String): WebAuditResult = withContext(Dispatchers.IO) {
        val initialUri = normalize(input)
        val originalHost = requireNotNull(initialUri.host)
        val addresses = InetAddress.getAllByName(originalHost)
            .mapNotNull { it.hostAddress }
            .distinct()

        var currentUri = initialUri
        var response = request(currentUri, "HEAD", includeOrigin = true)
        var usedGetFallback = response.usedGetFallback
        val redirectChain = mutableListOf(initialUri.toString())
        var redirects = 0

        while (response.status in REDIRECT_CODES && redirects < MAX_REDIRECTS) {
            val location = response.headers.header("Location") ?: break
            val next = runCatching { currentUri.resolve(location).normalize() }.getOrNull() ?: break
            if (next.scheme?.lowercase(Locale.ROOT) !in setOf("http", "https") ||
                !next.host.equals(originalHost, ignoreCase = true) ||
                next.userInfo != null
            ) break

            currentUri = next
            redirectChain += currentUri.toString()
            response = request(currentUri, "HEAD", includeOrigin = true)
            usedGetFallback = usedGetFallback || response.usedGetFallback
            redirects++
        }

        val resources = probePublicResources(currentUri)
        val findings = buildFindings(
            uri = currentUri,
            status = response.status,
            headers = response.headers,
            tls = response.tls,
            resources = resources
        )

        WebAuditResult(
            url = initialUri.toString(),
            host = originalHost,
            resolvedAddresses = addresses,
            httpStatus = response.status,
            responseHeaders = response.headers,
            tlsCipherSuite = response.tls?.cipherSuite,
            certificateSubject = response.tls?.subject,
            certificateIssuer = response.tls?.issuer,
            certificateExpiryEpochMs = response.tls?.expiry,
            redirectLocation = response.headers.header("Location"),
            findings = findings,
            finalUrl = currentUri.toString(),
            redirectChain = redirectChain,
            certificateSans = response.tls?.sans.orEmpty(),
            usedGetFallback = usedGetFallback,
            resources = resources
        )
    }

    private fun request(uri: URI, method: String, includeOrigin: Boolean): HttpResponse {
        val response = perform(uri, method, includeOrigin)
        if (method == "HEAD" && response.status in setOf(405, 501)) {
            return perform(uri, "GET", includeOrigin, usedGetFallback = true)
        }
        return response
    }

    private fun perform(
        uri: URI,
        method: String,
        includeOrigin: Boolean,
        usedGetFallback: Boolean = false
    ): HttpResponse {
        val connection = (uri.toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            instanceFollowRedirects = false
            useCaches = false
            setRequestProperty("User-Agent", USER_AGENT)
            setRequestProperty("Accept", "*/*")
            setRequestProperty("Connection", "close")
            if (method == "GET") setRequestProperty("Range", "bytes=0-$MAX_BODY_SAMPLE_BYTES")
            if (includeOrigin) setRequestProperty("Origin", TEST_ORIGIN)
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
                    expiry = certificate?.notAfter?.time,
                    sans = runCatching {
                        certificate?.subjectAlternativeNames.orEmpty()
                            .mapNotNull { it.getOrNull(1)?.toString() }
                            .distinct()
                            .take(MAX_CERTIFICATE_SANS)
                    }.getOrDefault(emptyList())
                )
            }

            val bodySample = if (method == "GET") readBodySample(connection) else ""
            return HttpResponse(status, headers, tls, bodySample, usedGetFallback)
        } finally {
            connection.disconnect()
        }
    }

    private fun probePublicResources(uri: URI): List<WebResourceCheck> =
        RESOURCE_PATHS.map { path ->
            runCatching {
                val resourceUri = uri.resolve(path)
                val head = perform(resourceUri, "HEAD", includeOrigin = false)
                val gitHead = path == "/.git/HEAD"
                val response = if (gitHead && head.status in 200..299) {
                    perform(resourceUri, "GET", includeOrigin = false)
                } else {
                    head
                }
                val exposesGitReference = gitHead &&
                    response.status in 200..299 &&
                    response.bodySample.trimStart().startsWith("ref:")

                WebResourceCheck(
                    path = path,
                    statusCode = response.status,
                    contentType = response.headers.header("Content-Type"),
                    sensitiveExposure = exposesGitReference
                )
            }.getOrElse {
                WebResourceCheck(path = path, statusCode = 0, contentType = null)
            }
        }

    private fun readBodySample(connection: HttpURLConnection): String {
        val stream = runCatching { connection.inputStream }
            .getOrElse { connection.errorStream } ?: return ""
        return stream.use { input ->
            val bytes = ByteArray(MAX_BODY_SAMPLE_BYTES)
            val count = runCatching { input.read(bytes) }.getOrDefault(-1)
            if (count <= 0) "" else String(bytes, 0, count, Charsets.UTF_8)
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
        tls: TlsDetails?,
        resources: List<WebResourceCheck>
    ): List<WebFinding> {
        val findings = mutableListOf<WebFinding>()
        val https = uri.scheme.equals("https", ignoreCase = true)
        val hsts = headers.header("Strict-Transport-Security")
        val redirectsToHttps = status in REDIRECT_CODES &&
            headers.header("Location")?.startsWith("https://", ignoreCase = true) == true

        if (!https && !redirectsToHttps) {
            findings += WebFinding(
                FindingSeverity.MEDIUM,
                "HTTP without TLS",
                "The target responded over plain HTTP without an HTTPS redirect.",
                "Serve the site over HTTPS and redirect HTTP requests to the HTTPS endpoint."
            )
        } else if (https && hsts.isNullOrBlank()) {
            findings += WebFinding(
                FindingSeverity.LOW,
                "HSTS header missing",
                "Strict-Transport-Security was not present in the HTTPS response.",
                "Enable HSTS after confirming that all required site paths support HTTPS."
            )
        } else if (https && hsts != null) {
            val maxAge = Regex("""max-age=($d+)""", RegexOption.IGNORE_CASE)
                .find(hsts)?.groupValues?.getOrNull(1)?.toLongOrNull()
            if (maxAge != null && maxAge < ONE_YEAR_SECONDS) {
                findings += WebFinding(
                    FindingSeverity.LOW,
                    "HSTS max-age is shorter than one year",
                    hsts,
                    "Consider max-age of at least 31536000 seconds after validating deployment readiness."
                )
            }
        }

        val csp = headers.header("Content-Security-Policy").orEmpty()
        if (csp.isBlank()) {
            findings += WebFinding(
                FindingSeverity.LOW,
                "Content Security Policy missing",
                "No Content-Security-Policy response header was found.",
                "Define a policy appropriate to the site, starting in report-only mode if necessary."
            )
        } else {
            if (csp.contains("'unsafe-eval'", ignoreCase = true)) {
                findings += WebFinding(
                    FindingSeverity.MEDIUM,
                    "CSP allows unsafe-eval",
                    "Content-Security-Policy contains unsafe-eval.",
                    "Remove unsafe-eval where possible and use nonces or hashes for required scripts."
                )
            }
            if (csp.contains("'unsafe-inline'", ignoreCase = true)) {
                findings += WebFinding(
                    FindingSeverity.LOW,
                    "CSP allows unsafe-inline",
                    "Content-Security-Policy contains unsafe-inline.",
                    "Prefer nonces or hashes instead of allowing all inline scripts or styles."
                )
            }
        }

        if (headers.header("X-Content-Type-Options").isNullOrBlank()) {
            findings += WebFinding(
                FindingSeverity.LOW,
                "MIME-sniffing protection missing",
                "X-Content-Type-Options was not present.",
                "Set X-Content-Type-Options: nosniff where compatible with the application."
            )
        }

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

        if (headers.header("Permissions-Policy").isNullOrBlank()) {
            findings += WebFinding(
                FindingSeverity.INFO,
                "Permissions Policy not set",
                "No Permissions-Policy response header was found.",
                "Restrict browser features such as camera, microphone and geolocation where they are not needed."
            )
        }

        if (headers.header("Cross-Origin-Opener-Policy").isNullOrBlank()) {
            findings += WebFinding(
                FindingSeverity.INFO,
                "Cross-Origin-Opener-Policy not set",
                "No Cross-Origin-Opener-Policy response header was found.",
                "Consider an appropriate COOP policy for pages that handle sensitive browsing contexts."
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

        headers.header("X-Powered-By")?.takeIf { it.isNotBlank() }?.let { poweredBy ->
            findings += WebFinding(
                FindingSeverity.INFO,
                "Technology header disclosed",
                "X-Powered-By: $poweredBy",
                "Remove unnecessary framework or runtime disclosure headers."
            )
        }

        headers.headerValues("Set-Cookie").forEach { cookie ->
            val attributes = cookie.split(';').drop(1).map { it.trim().lowercase(Locale.ROOT) }
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

        val allowOrigin = headers.header("Access-Control-Allow-Origin")
        val allowCredentials = headers.header("Access-Control-Allow-Credentials")
        if (allowOrigin == TEST_ORIGIN && allowCredentials.equals("true", ignoreCase = true)) {
            findings += WebFinding(
                FindingSeverity.HIGH,
                "Credentialed CORS origin reflection",
                "The response reflected an untrusted Origin and allowed credentials.",
                "Use an explicit allowlist of trusted origins and validate every Origin before returning credentialed CORS headers."
            )
        } else if (allowOrigin == "*") {
            findings += WebFinding(
                FindingSeverity.INFO,
                "Wildcard CORS policy",
                "Access-Control-Allow-Origin: * was returned to the audit origin.",
                "Confirm that the resource is intentionally public and contains no user-specific data."
            )
        }

        if (status in REDIRECT_CODES) {
            findings += WebFinding(
                FindingSeverity.INFO,
                "Redirect returned",
                headers.header("Location") ?: "HTTP $status without a Location header.",
                "Review the redirect destination and confirm the final canonical URL."
            )
        } else if (status >= 500) {
            findings += WebFinding(
                FindingSeverity.INFO,
                "Server error response",
                "The server returned HTTP $status to the audit request.",
                "Review the endpoint logs and confirm that the requested method is supported; this result alone does not prove a vulnerability."
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

        resources.firstOrNull { it.path == "/.git/HEAD" && it.sensitiveExposure }?.let {
            findings += WebFinding(
                FindingSeverity.HIGH,
                "Git repository metadata exposed",
                "A public request to /.git/HEAD returned a Git reference.",
                "Block public access to the .git directory and verify that repository metadata is not deployed with the website."
            )
        }

        resources.firstOrNull {
            it.path in setOf("/openapi.json", "/swagger-ui/index.html") && it.statusCode in 200..299
        }?.let {
            findings += WebFinding(
                FindingSeverity.INFO,
                "Public API documentation detected",
                "${it.path} returned HTTP ${it.statusCode}.",
                "Confirm that the API schema and interactive documentation are intended to be public."
            )
        }

        return findings.distinctBy { it.title to it.evidence }
    }

    private fun readBodySample(connection: HttpURLConnection): String {
        val stream = runCatching { connection.inputStream }
            .getOrElse { connection.errorStream } ?: return ""
        return stream.use { input ->
            val bytes = ByteArray(MAX_BODY_SAMPLE_BYTES)
            val count = runCatching { input.read(bytes) }.getOrDefault(-1)
            if (count <= 0) "" else String(bytes, 0, count, Charsets.UTF_8)
        }
    }

    private fun Map<String, List<String>>.headerValues(name: String): List<String> =
        entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value.orEmpty()

    private fun Map<String, List<String>>.header(name: String): String? =
        headerValues(name).takeIf { it.isNotEmpty() }?.joinToString(", ")

    private data class HttpResponse(
        val status: Int,
        val headers: Map<String, List<String>>,
        val tls: TlsDetails?,
        val bodySample: String,
        val usedGetFallback: Boolean
    )

    private data class TlsDetails(
        val cipherSuite: String?,
        val subject: String?,
        val issuer: String?,
        val expiry: Long?,
        val sans: List<String>
    )

    companion object {
        const val TEST_ORIGIN = "https://gmap.invalid"
        private const val USER_AGENT = "Gmap-Android/2.4"
        private const val CONNECT_TIMEOUT_MS = 4000
        private const val READ_TIMEOUT_MS = 4000
        private const val THIRTY_DAYS_MS = 30L * 24 * 60 * 60 * 1000
        private const val ONE_YEAR_SECONDS = 31_536_000L
        private const val MAX_BODY_SAMPLE_BYTES = 256
        private const val MAX_CERTIFICATE_SANS = 12
        private const val MAX_REDIRECTS = 4
        private val REDIRECT_CODES = setOf(301, 302, 303, 307, 308)
        private val RESOURCE_PATHS = listOf(
            "/.well-known/security.txt",
            "/robots.txt",
            "/openapi.json",
            "/.git/HEAD"
        )
    }
}
