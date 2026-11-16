package com.dsl.gmap

import com.dsl.gmap.scanner.engine.SoftwareFingerprintParser
import com.dsl.gmap.scanner.model.ServiceFingerprint
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SoftwareFingerprintParserTest {
    @Test
    fun identifiesOpenSshVersionAsCpe() {
        val identity = SoftwareFingerprintParser.identify(
            ServiceFingerprint(service = "SSH", banner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
        )
        assertEquals("OpenSSH", identity?.displayName)
        assertEquals("9.6p1", identity?.version)
        assertEquals("cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*", identity?.cpeName)
    }

    @Test
    fun identifiesApacheVersionFromServerHeader() {
        val identity = SoftwareFingerprintParser.identify(
            ServiceFingerprint(service = "HTTP", serverHeader = "Apache/2.4.58 (Ubuntu)")
        )
        assertEquals("Apache HTTP Server", identity?.displayName)
        assertEquals("2.4.58", identity?.version)
        assertEquals("cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*", identity?.cpeName)
    }

    @Test
    fun identifiesNginxVersionFromServerHeader() {
        val identity = SoftwareFingerprintParser.identify(
            ServiceFingerprint(service = "HTTP", serverHeader = "nginx/1.26.3")
        )
        assertEquals("NGINX", identity?.displayName)
        assertEquals("1.26.3", identity?.version)
    }

    @Test
    fun identifiesMariaDbVersionFromHandshake() {
        val identity = SoftwareFingerprintParser.identify(
            ServiceFingerprint(service = "MySQL", banner = "Server version: 5.5.5-10.11.4-MariaDB-0+deb12u1")
        )
        assertEquals("MariaDB", identity?.displayName)
        assertEquals("10.11.4", identity?.version)
    }

    @Test
    fun identifiesPhpVersionFromPoweredByHeader() {
        val identity = SoftwareFingerprintParser.identify(
            ServiceFingerprint(service = "HTTP", additionalInfo = "X-Powered-By: PHP/8.2.12")
        )
        assertEquals("PHP", identity?.displayName)
        assertEquals("8.2.12", identity?.version)
        assertEquals("cpe:2.3:a:php:php:8.2.12:*:*:*:*:*:*:*", identity?.cpeName)
    }

    @Test
    fun identifiesTomcatAndJettyVersions() {
        val tomcat = SoftwareFingerprintParser.identify(
            ServiceFingerprint(service = "HTTP", serverHeader = "Apache Tomcat/10.1.18")
        )
        val jetty = SoftwareFingerprintParser.identify(
            ServiceFingerprint(service = "HTTP", serverHeader = "Jetty(12.0.6)")
        )
        assertEquals("Apache Tomcat", tomcat?.displayName)
        assertEquals("10.1.18", tomcat?.version)
        assertEquals("Eclipse Jetty", jetty?.displayName)
        assertEquals("12.0.6", jetty?.version)
    }

    @Test
    fun identifiesPythonAppServers() {
        val gunicorn = SoftwareFingerprintParser.identify(
            ServiceFingerprint(service = "HTTP", serverHeader = "gunicorn/21.2.0")
        )
        val uvicorn = SoftwareFingerprintParser.identify(
            ServiceFingerprint(service = "HTTP", serverHeader = "uvicorn/0.27.1")
        )
        assertEquals("Gunicorn", gunicorn?.displayName)
        assertEquals("Uvicorn", uvicorn?.displayName)
    }

    @Test
    fun doesNotInventVersionWhenOnlyProductNameIsVisible() {
        val identity = SoftwareFingerprintParser.identify(
            ServiceFingerprint(service = "HTTP", serverHeader = "Apache")
        )
        assertNull(identity)
    }
}
