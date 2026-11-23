package com.dsl.gmap.web

import com.dsl.gmap.scanner.model.SoftwareIdentity
import com.dsl.gmap.scanner.model.VulnerabilityFinding
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import okhttp3.Call
import okhttp3.Callback
import okhttp3.CookieJar
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.IOException
import java.net.InetAddress
import java.net.Proxy
import java.net.URI
import java.net.UnknownHostException
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.concurrent.TimeUnit

enum class FindingSeverity { INFO, LOW, MEDIUM, HIGH }
enum class FindingConfidence { LOW, MEDIUM, HIGH }
enum class FindingCategory {
    TRANSPORT_SECURITY, HTTP_HEADERS, COOKIES, CORS,
    PUBLIC_EXPOSURE, INFORMATION_DISCLOSURE, AVAILABILITY
}

data class WebFinding(
    val severity: FindingSeverity,
    val title: String,
    val evidence: String,
    val recommendation: String,
    val id: String = stableFindingId(title),
    val category: FindingCategory = FindingCategory.HTTP_HEADERS,
    val confidence: FindingConfidence = FindingConfidence.MEDIUM,
    val endpoint: String? = null,
    val method: String = "HEAD",
    val references: List<String> = emptyList()
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
    val resources: List<WebResourceCheck> = emptyList(),
    val softwareIdentities: List<SoftwareIdentity> = emptyList(),
    val vulnerabilityFindings: List<VulnerabilityFinding> = emptyList(),
    val intelligenceMessage: String? = null,
    val intelligenceWarnings: List<String> = emptyList(),
    val tlsVersion: String? = null,
    val requestCount: Int = 0
)

fun interface WebHostResolver {
    fun lookup(host: String): List<InetAddress>
}

class WebAuditEngine(
    private val hostResolver: WebHostResolver = WebHostResolver { Dns.SYSTEM.lookup(it) }
) {
    suspend fun scan(input: String): WebAuditResult = withContext(Dispatchers.IO) {
        withTimeout(MAX_SCAN_DURATION_MS) {
            val initialUri = normalize(input)
            val originalHost = requireNotNull(initialUri.host)
            val addresses = try {
                hostResolver.lookup(originalHost).distinctBy { it.hostAddress }
            } catch (exception: Exception) {
                throw IllegalArgumentException(
                    "DNS resolution failed for " + originalHost + ": " +
                        (exception.message ?: exception.javaClass.simpleName),
                    exception
                )
            }
            require(addresses.isNotEmpty()) { "DNS returned no usable addresses for $originalHost." }

            // Pin one DNS answer set to every connection in this audit. OkHttp still uses the
            // original hostname for Host, TLS SNI and normal certificate hostname verification.
            val client = createPinnedClient(originalHost, addresses)
            val budget = RequestBudget(MAX_REQUESTS_PER_AUDIT)
            try {
                var currentUri = initialUri
                var response = request(client, budget, currentUri, "HEAD", includeOrigin = true)
                var usedGetFallback = response.usedGetFallback
                val redirectChain = mutableListOf(initialUri.toString())
                var redirects = 0

                while (response.status in REDIRECT_CODES && redirects < MAX_REDIRECTS) {
                    val location = response.headers.header("Location") ?: break
                    val next = runCatching {
                        currentUri.resolve(location).normalize().withoutQueryAndFragment()
                    }.getOrNull() ?: break

                    val currentScheme = currentUri.scheme.lowercase(Locale.ROOT)
                    val nextScheme = next.scheme?.lowercase(Locale.ROOT)
                    val sameHost = next.host.equals(originalHost, ignoreCase = true)
                    val currentPort = effectivePort(currentUri)
                    val nextPort = effectivePort(next)
                    val safeHttpsUpgrade =
                        currentScheme == "http" && nextScheme == "https" && nextPort == 443

                    if (nextScheme !in setOf("http", "https") ||
                        !sameHost ||
                        next.rawUserInfo != null ||
                        (currentScheme == "https" && nextScheme != "https") ||
                        (!safeHttpsUpgrade && currentPort != nextPort)
                    ) break

                    currentUri = next
                    redirectChain += currentUri.toString()
                    response = request(client, budget, currentUri, "HEAD", includeOrigin = true)
                    usedGetFallback = usedGetFallback || response.usedGetFallback
                    redirects++
                }

                val resources = probePublicResources(client, budget, currentUri)
                val findings = buildFindings(
                    uri = currentUri,
                    status = response.status,
                    headers = response.headers,
                    tls = response.tls,
                    resources = resources
                ).map { finding ->
                    finding.copy(
                        category = categoryFor(finding.title),
                        confidence = confidenceFor(finding.title),
                        endpoint = displayUri(currentUri)
                    )
                }

                WebAuditResult(
                    url = displayUri(initialUri),
                    host = originalHost,
                    resolvedAddresses = addresses.mapNotNull { it.hostAddress }.distinct(),
                    httpStatus = response.status,
                    responseHeaders = response.headers,
                    tlsCipherSuite = response.tls?.cipherSuite,
                    certificateSubject = response.tls?.subject,
                    certificateIssuer = response.tls?.issuer,
                    certificateExpiryEpochMs = response.tls?.expiry,
                    redirectLocation = response.headers.header("Location"),
                    findings = findings,
                    finalUrl = displayUri(currentUri),
                    redirectChain = redirectChain.map { displayUri(URI(it)) },
                    certificateSans = response.tls?.sans.orEmpty(),
                    usedGetFallback = usedGetFallback,
                    resources = resources,
                    tlsVersion = response.tls?.version,
                    requestCount = budget.count
                )
            } finally {
                client.connectionPool.evictAll()
                client.dispatcher.executorService.shutdown()
            }
        }
    }

    private fun createPinnedClient(host: String, addresses: List<InetAddress>): OkHttpClient =
        OkHttpClient.Builder()
            .dns(Dns { requestedHost ->
                if (!requestedHost.equals(host, ignoreCase = true)) {
                    throw UnknownHostException("The audit attempted to resolve an unapproved redirect host.")
                }
                addresses
            })
            // Proxies perform their own DNS lookup and would bypass the pinned answer.
            .proxy(Proxy.NO_PROXY)
            .cookieJar(CookieJar.NO_COOKIES)
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .connectTimeout(CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .readTimeout(READ_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .writeTimeout(WRITE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .callTimeout(CALL_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .build()

    private suspend fun request(
        client: OkHttpClient,
        budget: RequestBudget,
        uri: URI,
        method: String,
        includeOrigin: Boolean
    ): HttpResponse {
        val response = perform(client, budget, uri, method, includeOrigin)
        if (method == "HEAD" && response.status in setOf(405, 501)) {
            return perform(client, budget, uri, "GET", includeOrigin, usedGetFallback = true)
        }
        return response
    }

    private suspend fun perform(
        client: OkHttpClient,
        budget: RequestBudget,
        uri: URI,
        method: String,
        includeOrigin: Boolean,
        usedGetFallback: Boolean = false
    ): HttpResponse {
        budget.consume()
        val builder = Request.Builder()
            .url(uri.toASCIIString())
            .header("User-Agent", USER_AGENT)
            .header("Accept", "*/*")
            .header("Connection", "close")

        if (method == "GET") {
            builder.header("Range", "bytes=0-${MAX_BODY_SAMPLE_BYTES - 1}").get()
        } else {
            builder.head()
        }
        if (includeOrigin) builder.header("Origin", TEST_ORIGIN)

        val response = awaitResponse(client.newCall(builder.build()))
        response.use { received ->
            val headers = sanitizeHeaders(received.headers.toMultimap())
            val tls = received.handshake?.let { handshake ->
                val certificate = runCatching {
                    handshake.peerCertificates.filterIsInstance<X509Certificate>().firstOrNull()
                }.getOrNull()
                TlsDetails(
                    version = handshake.tlsVersion.javaName,
                    cipherSuite = handshake.cipherSuite.javaName,
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
            val bodySample = if (method == "GET") readBodySample(received) else ""
            return HttpResponse(received.code, headers, tls, bodySample, usedGetFallback)
        }
    }

    private suspend fun awaitResponse(call: Call): Response =
        suspendCancellableCoroutine { continuation ->
            continuation.invokeOnCancellation { call.cancel() }
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, exception: IOException) {
                    continuation.resumeWith(Result.failure(exception))
                }

                override fun onResponse(call: Call, response: Response) {
                    if (!continuation.isActive) {
                        response.close()
                        return
                    }
                    try {
                        continuation.resume(response) { _, undelivered, _ -> undelivered.close() }
                    } catch (_: IllegalStateException) {
                        response.close()
                    }
                }
            })
        }

    private suspend fun probePublicResources(
        client: OkHttpClient,
        budget: RequestBudget,
        uri: URI
    ): List<WebResourceCheck> {
        val results = ArrayList<WebResourceCheck>(RESOURCE_PATHS.size)
        for (path in RESOURCE_PATHS) {
            try {
                val resourceUri = uri.resolve(path).withoutQueryAndFragment()
                val head = perform(client, budget, resourceUri, "HEAD", includeOrigin = false)
                val gitHead = path == "/.git/HEAD"
                val response = if (gitHead && head.status in 200..299) {
                    perform(client, budget, resourceUri, "GET", includeOrigin = false)
                } else {
                    head
                }
                val exposesGitReference = gitHead &&
                    response.status in 200..299 &&
                    response.bodySample.trimStart().startsWith("ref:")

                results += WebResourceCheck(
                    path = path,
                    statusCode = response.status,
                    contentType = response.headers.header("Content-Type"),
                    sensitiveExposure = exposesGitReference
                )
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                results += WebResourceCheck(path = path, statusCode = 0, contentType = null)
            }
        }
        return results
    }

    /** Reads no more than 256 bytes even if a server ignores the Range request. */
    private fun readBodySample(response: Response): String {
        val input = response.body?.byteStream() ?: return ""
        val bytes = ByteArray(MAX_BODY_SAMPLE_BYTES)
        var total = 0
        while (total < bytes.size) {
            val count = try {
                input.read(bytes, total, bytes.size - total)
            } catch (_: IOException) {
                -1
            }
            if (count <= 0) break
            total += count
        }
        return if (total == 0) "" else String(bytes, 0, total, Charsets.UTF_8)
    }

    private fun normalize(input: String): URI {
        val raw = input.trim()
        require(raw.isNotEmpty()) { "Enter a hostname or URL." }
        require(raw.length <= MAX_URL_LENGTH) {
            "The URL is too long (maximum " + MAX_URL_LENGTH + " characters)."
        }
        val candidate = if (raw.contains("://")) raw else "https://$raw"
        val parsed = runCatching { URI(candidate) }
            .getOrElse { throw IllegalArgumentException("Enter a valid hostname or URL.") }

        val scheme = parsed.scheme?.lowercase(Locale.ROOT)
        require(scheme == "http" || scheme == "https") {
            "Only HTTP and HTTPS URLs are supported."
        }
        require(!parsed.host.isNullOrBlank() && parsed.rawUserInfo == null) {
            "The URL must contain a hostname and must not contain embedded credentials."
        }
        require(parsed.port == -1 || parsed.port in 1..65535) {
            "Invalid TCP port in URL."
        }

        // Preserve raw path escapes such as %2F and %20; Java's decoded-path constructor
        // would encode the percent sign again and silently change the requested endpoint.
        val authority = requireNotNull(parsed.rawAuthority)
        val rawPath = parsed.rawPath?.takeIf { it.isNotEmpty() } ?: "/"
        return runCatching { URI.create("$scheme://$authority$rawPath").normalize() }
            .getOrElse { throw IllegalArgumentException("Enter a valid hostname or URL path.") }
    }

    private fun URI.withoutQueryAndFragment(): URI {
        require(scheme.equals("http", true) || scheme.equals("https", true))
        require(!host.isNullOrBlank() && rawUserInfo == null)
        val authority = requireNotNull(rawAuthority)
        val path = rawPath?.takeIf { it.isNotEmpty() } ?: "/"
        return URI.create("${scheme.lowercase(Locale.ROOT)}://$authority$path").normalize()
    }

    private fun effectivePort(uri: URI): Int =
        if (uri.port != -1) uri.port else if (uri.scheme.equals("https", true)) 443 else 80

    private fun displayUri(uri: URI): String =
        uri.toASCIIString().substringBefore('?').substringBefore('#')

    /** Retain bounded, sanitized response metadata from an untrusted server. */
    private fun sanitizeHeaders(input: Map<String, List<String>>): Map<String, List<String>> {
        val safe = LinkedHashMap<String, List<String>>()
        input.entries.take(MAX_RESPONSE_HEADERS).forEach { (name, values) ->
            val safeName = name.take(MAX_HEADER_NAME_CHARS)
            val safeValues = values.take(MAX_VALUES_PER_HEADER).mapNotNull { rawValue ->
                when {
                    name.equals("Set-Cookie", ignoreCase = true) -> redactSetCookie(rawValue)
                    name.equals("Location", ignoreCase = true) -> sanitizeLocation(rawValue)
                    else -> rawValue.take(MAX_HEADER_VALUE_CHARS)
                }
            }
            if (safeValues.isNotEmpty()) safe[safeName] = safeValues
        }
        return safe
    }

    private fun redactSetCookie(value: String): String {
        val pair = value.substringBefore(';')
        val name = pair.substringBefore('=', "").trim().take(128)
        val attributes = value.substringAfter(';', "")
            .split(';')
            .map { it.trim().take(128) }
            .filter { it.isNotEmpty() }
        val redactedPair = if (name.isNotBlank()) "$name=<redacted>" else "<redacted>"
        return (listOf(redactedPair) + attributes).joinToString("; ").take(MAX_HEADER_VALUE_CHARS)
    }

    private fun sanitizeLocation(value: String): String? {
        val parsed = runCatching { URI(value) }.getOrNull() ?: return null
        if (parsed.rawUserInfo != null) return null
        return value.substringBefore('#').substringBefore('?')
            .take(MAX_HEADER_VALUE_CHARS)
            .takeIf { it.isNotBlank() }
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
            val maxAge = Regex("""max-age=(\d+)""", RegexOption.IGNORE_CASE)
                .find(hsts)?.groupValues?.getOrNull(1)?.toLongOrNull()
            if (maxAge == null || maxAge == 0L) {
                findings += WebFinding(
                    FindingSeverity.LOW,
                    "HSTS max-age missing or disabled",
                    "The Strict-Transport-Security header does not contain a positive max-age.",
                    "Set a positive max-age and only enable includeSubDomains after validating every affected subdomain."
                )
            } else if (maxAge < ONE_YEAR_SECONDS) {
                findings += WebFinding(
                    FindingSeverity.LOW,
                    "HSTS max-age is shorter than one year",
                    hsts,
                    "Consider max-age of at least 31536000 seconds after validating deployment readiness."
                )
            }
        }

        val contentType = headers.header("Content-Type").orEmpty().lowercase(Locale.ROOT)
        val isHtml = contentType.contains("text/html") || contentType.contains("application/xhtml+xml")
        val csp = headers.header("Content-Security-Policy").orEmpty()
        val cspDirectives = parseCsp(csp)
        if (isHtml && csp.isBlank()) {
            findings += WebFinding(
                FindingSeverity.LOW,
                "Content Security Policy missing",
                "No Content-Security-Policy response header was found.",
                "Define a policy appropriate to the site, starting in report-only mode if necessary."
            )
        } else if (isHtml) {
            val effectiveScript = cspDirectives["script-src"] ?: cspDirectives["default-src"].orEmpty()
            val effectiveScriptElement = cspDirectives["script-src-elem"] ?: effectiveScript
            if ("'unsafe-eval'" in effectiveScript) {
                findings += WebFinding(
                    FindingSeverity.MEDIUM,
                    "CSP allows unsafe-eval",
                    "Content-Security-Policy contains unsafe-eval.",
                    "Remove unsafe-eval where possible and use nonces or hashes for required scripts."
                )
            }
            if ("'unsafe-inline'" in effectiveScriptElement) {
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

        if (isHtml && headers.header("X-Frame-Options").isNullOrBlank() &&
            !cspDirectives.containsKey("frame-ancestors")
        ) {
            findings += WebFinding(
                FindingSeverity.LOW,
                "Clickjacking protection not detected",
                "Neither X-Frame-Options nor a CSP frame-ancestors directive was found.",
                "Set an appropriate frame-ancestors CSP directive or X-Frame-Options."
            )
        }

        if (isHtml && headers.header("Referrer-Policy").isNullOrBlank()) {
            findings += WebFinding(
                FindingSeverity.INFO,
                "Referrer Policy not set",
                "No Referrer-Policy response header was found.",
                "Set a Referrer-Policy that matches the site's privacy requirements."
            )
        }

        if (isHtml && headers.header("Permissions-Policy").isNullOrBlank()) {
            findings += WebFinding(
                FindingSeverity.INFO,
                "Permissions Policy not set",
                "No Permissions-Policy response header was found.",
                "Restrict browser features such as camera, microphone and geolocation where they are not needed."
            )
        }

        if (isHtml && headers.header("Cross-Origin-Opener-Policy").isNullOrBlank()) {
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
                FindingSeverity.MEDIUM,
                "Credentialed CORS origin reflection",
                "The unauthenticated synthetic-origin probe was reflected and Access-Control-Allow-Credentials was true. This does not by itself prove that sensitive data is exposed.",
                "Use an explicit allowlist of trusted origins and verify that credentialed responses expose no data to untrusted origins."
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

    private fun parseCsp(policy: String): Map<String, Set<String>> =
        policy.split(';').mapNotNull { directive ->
            val tokens = directive.trim().split(Regex("\\s+")).filter { it.isNotBlank() }
            val name = tokens.firstOrNull()?.lowercase(Locale.ROOT) ?: return@mapNotNull null
            name to tokens.drop(1).map { it.lowercase(Locale.ROOT) }.toSet()
        }.toMap()

    private fun categoryFor(title: String): FindingCategory = when {
        title.contains("cookie", true) -> FindingCategory.COOKIES
        title.contains("CORS", true) -> FindingCategory.CORS
        title.contains("TLS", true) || title.contains("HTTP without TLS", true) ||
            title.contains("HSTS", true) -> FindingCategory.TRANSPORT_SECURITY
        title.contains("Git repository", true) ||
            title.contains("API documentation", true) -> FindingCategory.PUBLIC_EXPOSURE
        title.contains("Server header", true) ||
            title.contains("Technology header", true) -> FindingCategory.INFORMATION_DISCLOSURE
        title.contains("Redirect", true) ||
            title.contains("Server error", true) -> FindingCategory.AVAILABILITY
        else -> FindingCategory.HTTP_HEADERS
    }

    private fun confidenceFor(title: String): FindingConfidence = when {
        title.contains("Git repository metadata exposed", true) ||
            title.contains("TLS certificate expires soon", true) -> FindingConfidence.HIGH
        title.contains("missing", true) ||
            title.contains("not set", true) ||
            title.contains("not detected", true) ||
            title.contains("without", true) ||
            title.contains("allows", true) -> FindingConfidence.LOW
        title.contains("CORS", true) -> FindingConfidence.LOW
        else -> FindingConfidence.MEDIUM
    }

    private fun Map<String, List<String>>.headerValues(name: String): List<String> =
        entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value.orEmpty()

    private fun Map<String, List<String>>.header(name: String): String? =
        headerValues(name).takeIf { it.isNotEmpty() }?.joinToString(", ")

    private class RequestBudget(private val maximum: Int) {
        var count: Int = 0
            private set

        fun consume() {
            if (count >= maximum) throw IOException("Web audit request budget exceeded.")
            count++
        }
    }

    private data class HttpResponse(
        val status: Int,
        val headers: Map<String, List<String>>,
        val tls: TlsDetails?,
        val bodySample: String,
        val usedGetFallback: Boolean
    )

    private data class TlsDetails(
        val version: String?,
        val cipherSuite: String?,
        val subject: String?,
        val issuer: String?,
        val expiry: Long?,
        val sans: List<String>
    )

    companion object {
        const val TEST_ORIGIN = "https://gmap.invalid"
        private const val USER_AGENT = "Gmap-Android/2.11"
        private const val MAX_URL_LENGTH = 2048
        private const val MAX_RESPONSE_HEADERS = 64
        private const val MAX_VALUES_PER_HEADER = 8
        private const val MAX_HEADER_NAME_CHARS = 128
        private const val MAX_HEADER_VALUE_CHARS = 1024
        private const val CONNECT_TIMEOUT_MS = 4000L
        private const val READ_TIMEOUT_MS = 4000L
        private const val WRITE_TIMEOUT_MS = 4000L
        private const val CALL_TIMEOUT_MS = 8000L
        private const val MAX_SCAN_DURATION_MS = 45_000L
        private const val MAX_BODY_SAMPLE_BYTES = 256
        private const val MAX_REQUESTS_PER_AUDIT = 18
        private const val THIRTY_DAYS_MS = 30L * 24 * 60 * 60 * 1000
        private const val ONE_YEAR_SECONDS = 31_536_000L
        private const val MAX_CERTIFICATE_SANS = 12
        private const val MAX_REDIRECTS = 4
        private val REDIRECT_CODES = setOf(301, 302, 303, 307, 308)
        private val RESOURCE_PATHS = listOf(
            "/.well-known/security.txt",
            "/robots.txt",
            "/openapi.json",
            "/swagger-ui/index.html",
            "/sitemap.xml",
            "/.git/HEAD"
        )
    }
}

private fun stableFindingId(title: String): String =
    title.lowercase(Locale.ROOT)
        .replace(Regex("[^a-z0-9]+"), "-")
        .trim('-')
        .take(64)
