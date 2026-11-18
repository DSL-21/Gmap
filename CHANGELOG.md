# Changelog

## 2.6.0 — 2026-11-18

### TCP scan reliability
- Resolve hostnames with all available IPv4/IPv6 addresses and scan each returned address instead of selecting only one DNS answer.
- Tag TCP results with the address that produced them so repeated port numbers across multiple resolved addresses remain distinguishable.
- Aggregate scan progress and state counts across all resolved addresses.
- Add a regression test ensuring every port in a requested range produces exactly one result while multiple listeners are detected.

### Interface
- Removed redundant instructional/disclaimer copy from the TCP scan form.

### Validation note
- Physical-device validation is still required for DNS/CDN targets and mobile network behaviour; a local unit test cannot prove that a remote host will respond on every address.


## 2.5.0 — 2026-11-16

### Security hardening
- Capped outstanding TCP connect probes to a strict maximum of 128, including adaptive growth, to protect mobile socket and file-descriptor resources.
- Redacted all Set-Cookie values before retaining response headers or generating findings.
- Removed query strings from Web audit requests and displayed URLs to avoid sending or retaining token-like URL parameters.
- Bounded response-header count, values per header and individual header lengths.
- Restricted Web audit redirects to the same host and port, except a same-host HTTP-to-default-HTTPS upgrade; HTTPS downgrades and port pivots are rejected.
- Disabled automatic redirects for public vulnerability-intelligence provider requests.
- Added regression tests for TCP concurrency limits, cookie redaction, query suppression and redirect port isolation.

### Repository and CI hygiene
- Removed tracked IDE state, Kotlin error logs and an unused legacy XML layout.
- Ignored local IDE state, generated build directories and APK outputs.
- Removed unused direct AppCompat and ConstraintLayout dependencies.
- Pinned GitHub Actions to immutable commit SHAs, enabled Android Lint in CI, removed duplicate debug APK CI artifacts and added Dependabot updates.
- Added a security policy and a source-level audit record.

### Limitations
- HTTP support remains available because the Web audit explicitly supports user-selected HTTP endpoints; HTTP traffic is unencrypted.
- The Web audit still relies on the platform URL connection stack and does not pin DNS results to a socket. DNS rebinding is a residual risk when a user manually audits an attacker-controlled hostname; avoid auditing untrusted domains and use literal IPs for local devices.
- CI unit tests, Android Lint and APK assembly do not replace testing on physical devices or an independent penetration test.
- Release APKs built by GitHub Actions remain debug-signed until a production signing key is configured.

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
- Explicitly enabled user-initiated HTTP auditing on Android 9+ and added a warning that HTTP requests are unencrypted.

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
