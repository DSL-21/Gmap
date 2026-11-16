package com.dsl.gmap.scanner.engine

import com.dsl.gmap.scanner.model.ServiceFingerprint
import com.dsl.gmap.scanner.model.SoftwareIdentity

/**
 * Converts explicit service-version banners into conservative CPE 2.3 candidates.
 * A candidate is correlation evidence, not proof that the installed package is vulnerable.
 */
object SoftwareFingerprintParser {
    private data class Rule(
        val displayName: String,
        val vendor: String,
        val product: String,
        val regex: Regex
    )

    private val rules = listOf(
        Rule("OpenSSH", "openbsd", "openssh", Regex("""\bOpenSSH[_ ]([0-9][A-Za-z0-9._+-]*)""", RegexOption.IGNORE_CASE)),
        Rule("Apache HTTP Server", "apache", "http_server", Regex("""\bApache/([0-9]+(?:\.[0-9]+){1,3}(?:[-+._A-Za-z0-9]*))""", RegexOption.IGNORE_CASE)),
        Rule("NGINX", "f5", "nginx", Regex("""\bnginx/([0-9]+(?:\.[0-9]+){1,3}(?:[-+._A-Za-z0-9]*))""", RegexOption.IGNORE_CASE)),
        Rule("Microsoft IIS", "microsoft", "internet_information_services", Regex("""\bMicrosoft-IIS/([0-9]+(?:\.[0-9]+){0,2})""", RegexOption.IGNORE_CASE)),
        Rule("lighttpd", "lighttpd_project", "lighttpd", Regex("""\blighttpd/([0-9]+(?:\.[0-9]+){1,3})""", RegexOption.IGNORE_CASE)),
        Rule("vsftpd", "vsftpd_project", "vsftpd", Regex("""\bvsFTPd\s+([0-9]+(?:\.[0-9]+){1,2})""", RegexOption.IGNORE_CASE)),
        Rule("ProFTPD", "proftpd", "proftpd", Regex("""\bProFTPD(?:\s+Server)?\s+([0-9]+(?:\.[0-9]+){1,2})""", RegexOption.IGNORE_CASE)),
        Rule("Postfix", "postfix", "postfix", Regex("""\bPostfix(?:/|\s+)([0-9]+(?:\.[0-9]+){1,2})""", RegexOption.IGNORE_CASE)),
        Rule("Exim", "exim", "exim", Regex("""\bExim\s+([0-9]+(?:\.[0-9]+){1,2})""", RegexOption.IGNORE_CASE))
    )

    fun identify(fingerprint: ServiceFingerprint): SoftwareIdentity? {
        val evidence = listOfNotNull(
            fingerprint.banner,
            fingerprint.serverHeader,
            fingerprint.additionalInfo
        ).joinToString(" | ").trim().take(600)

        if (evidence.isBlank()) return null

        if (evidence.contains("MariaDB", ignoreCase = true)) {
            val version = Regex("""5\.5\.5-([0-9]+\.[0-9]+\.[0-9]+)""", RegexOption.IGNORE_CASE)
                .find(evidence)?.groupValues?.get(1)
                ?: Regex("""([0-9]+\.[0-9]+\.[0-9]+)[-+._A-Za-z0-9]*MariaDB""", RegexOption.IGNORE_CASE)
                    .find(evidence)?.groupValues?.get(1)
            if (version != null) return identity("MariaDB", "mariadb", "mariadb", version, evidence)
        }

        if (evidence.contains("MySQL", ignoreCase = true) ||
            fingerprint.service.equals("MySQL", ignoreCase = true)
        ) {
            val version = Regex("""(?:Server version:\s*)?([0-9]+\.[0-9]+\.[0-9]+)""", RegexOption.IGNORE_CASE)
                .find(evidence)?.groupValues?.get(1)
            if (version != null) return identity("MySQL", "oracle", "mysql", version, evidence)
        }

        val rule = rules.firstOrNull { it.regex.containsMatchIn(evidence) } ?: return null
        val version = rule.regex.find(evidence)?.groupValues?.getOrNull(1)
            ?.takeIf { it.isNotBlank() && it.length <= 64 }
            ?: return null
        return identity(rule.displayName, rule.vendor, rule.product, version, evidence)
    }

    private fun identity(
        displayName: String,
        vendor: String,
        product: String,
        version: String,
        evidence: String
    ): SoftwareIdentity {
        val safeVersion = version.filter { it.isLetterOrDigit() || it in "._+-" }
        // CPE represents OpenSSH p-levels as the separate update component.
        val openSshParts = if (vendor == "openbsd" && product == "openssh") {
            Regex("""^(\d+(?:\.\d+)*)(p\d+)$""").matchEntire(safeVersion)
        } else null
        val cpeVersion = openSshParts?.groupValues?.get(1) ?: safeVersion
        val cpeUpdate = openSshParts?.groupValues?.get(2) ?: "*"
        val cpe = "cpe:2.3:a:$vendor:$product:$cpeVersion:$cpeUpdate:*:*:*:*:*:*"
        return SoftwareIdentity(
            vendor = vendor,
            product = product,
            displayName = displayName,
            version = safeVersion,
            cpeName = cpe,
            evidence = evidence
        )
    }
}
