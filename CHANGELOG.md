# Changelog

## 2.4.0 — 2026-11-16

### Network discovery
- Parallel local IPv4 discovery using 27 common TCP service ports.
- Bounded concurrency, ordered results, and likely device-role labels.
- Added Android 17 local-network runtime permission support for local scan targets, including full HTTP(S) URLs.

### TCP service identification
- Added read-only SMB2 negotiate and RDP security negotiation fingerprints.
- Expanded identification for additional HTTP, HTTPS, TLS and service ports.
- Added standard-port service hints where active protocol identification is not available.
- Expanded version-to-CPE identification for PHP, Tomcat, Jetty, OpenResty, Gunicorn, Uvicorn, Werkzeug, HAProxy and Traefik.

### Web audit
- Added HEAD-to-bounded-GET fallback for servers that reject HEAD.
- Added same-host redirect tracking and TLS certificate SAN display.
- Added CORS, modern browser security-header and cookie-attribute checks.
- Added public endpoint checks for security.txt, robots.txt, OpenAPI metadata and exposed Git HEAD.
- Added optional CPE/CVE correlation for versioned web server headers with NVD, CISA KEV and FIRST EPSS.

### Interface, privacy and validation
- Expanded result details for local devices, web endpoints, identified products and CVE/KEV/EPSS findings.
- Kept scan history and findings RAM-only.
- Added unit tests for subnet handling, local-network permission decisions, service protocol identification, software fingerprints and Web audit behavior.
- Targets Android SDK 37 and keeps Android 8.0/API 26 as the minimum supported version.

### Limitations
- Local discovery uses TCP presence checks, not ARP.
- UDP silence remains OPEN|FILTERED.
- Service names guessed from port numbers are hints, not confirmed fingerprints.
- Web checks are read-only configuration and public-metadata checks, not an exploit scanner.
- CI APKs are debug-signed and are not production-keystore or Google Play packages.

## 2.3.1
- Previous stable release.
