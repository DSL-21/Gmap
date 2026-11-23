# Changelog

## 2.9.0 — 2026-11-23

### Predictable TCP target selection and exact scan accounting
- Changed hostname scans to select one deterministic IPv4-preferred DNS address by default instead of silently scanning every A/AAAA answer.
- Added an explicit "Scan all resolved DNS addresses" option for users who intentionally want to assess every returned endpoint.
- Kept the requested start/end port range unchanged for every selected address and changed progress wording to count host/port checks accurately.
- Added a hard ceiling of 262,144 aggregate host/port checks to prevent unexpectedly large DNS expansion and excessive in-memory result allocation.
- Added deterministic address-selection regression tests for default single-address and opt-in multi-address behavior.

### Memory-only settings
- Removed SharedPreferences persistence for TCP scan profiles and custom tuning; settings now remain in memory only.
- Delete legacy TCP scan preferences created by Gmap 2.8.0 and earlier on application startup.

### Validation
- CI runs Android Lint, unit tests and debug APK assembly. Physical-device validation is still required for DNS rotation, IPv4/IPv6 selection and mobile-network behavior.

## 2.8.0 — 2026-11-19

## 2.8.0 — 2026-11-19

### Adaptive TCP scan engine
- Added Gmap-native Reliable, Balanced, Performance, Maximum and Custom scan modes in Settings.
- Added on-device persistence for scan mode, maximum concurrency, connection timeout, retry budget and adaptive concurrency preference.
- Added bounded retry scheduling for unanswered TCP probes. Confirmed connection refusals remain CLOSED and are not retried; ports with no response remain FILTERED after the selected retry budget.
- Added batch-based adaptive concurrency: the scanner reduces its window when a sample contains sustained timeouts and gradually increases it when responses are healthy.
- Added fair retry scheduling so retry traffic cannot starve first-pass coverage of the remaining requested ports.
- Enforced one final result per requested port and added scan-profile model tests.

### Validation note
- CI validation covers Lint, unit tests and debug APK assembly. Physical-device testing is still required across Wi-Fi, mobile data, filtered networks and different Android devices. No timing profile can guarantee that a remote host or firewall will answer.

## 2.7.0 — 2026-11-18

### TCP scan reliability
- Lowered the maximum number of simultaneous TCP connect probes from 128 to 32 to reduce burst pressure on mobile networks and remote services.
- Added adaptive congestion backoff when TCP connection attempts time out, halving the active probe window and temporarily slowing new probes before gradual recovery.
- Kept timeouts classified as FILTERED/NO RESPONSE rather than incorrectly reporting them as CLOSED; explicit connection refusals remain CLOSED.
- Updated the concurrency regression test to enforce the new 32-probe ceiling and minimum backoff window.

### Validation note
- CI and physical-device testing are required before treating remote scan consistency as verified. Network filtering, server rate limits, carrier policies and transient routing can still produce different results between scans.

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
