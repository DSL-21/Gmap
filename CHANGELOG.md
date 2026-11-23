# Changelog

## 2.11.0 — 2026-11-23

### Web Audit security and reliability overhaul
- Replaced HttpURLConnection with OkHttp 5.5.1 and a custom pinned DNS resolver. The selected IP answer set is reused for every request while the original hostname remains in the URL for HTTP Host, TLS SNI and platform certificate hostname verification.
- Disabled automatic redirects, system proxy use, cookies and implicit connection retries in the Web audit client. Redirects remain same-host, do not downgrade HTTPS and cannot pivot to arbitrary ports.
- Removed query strings and fragments from both the original target and every redirect before a request is sent. Preserved already-escaped raw path segments instead of double-encoding percent sequences.
- Added cancellable asynchronous HTTP calls. Cancelling the audit now cancels the active OkHttp call instead of waiting for connect/read timeouts.
- Added per-call timeouts, a 45-second scan deadline, a 18-request total budget and a 256-byte maximum response sample even when a server ignores Range.
- Fixed cancellation handling in fixed-path public resource checks; cancellation exceptions are rethrown instead of being converted into a missing-resource result.
- Expanded fixed public metadata checks to /.well-known/security.txt, /robots.txt, /openapi.json, /swagger-ui/index.html, /sitemap.xml and /.git/HEAD. Only the Git HEAD check reads a bounded body sample.
- Added TLS protocol version and request count to the result.
- Added stable finding IDs, categories, confidence estimates and endpoint context. Credentialed CORS origin reflection is now medium severity because a synthetic unauthenticated probe does not prove sensitive data exposure.
- Reduced browser-header false positives by evaluating CSP, clickjacking, Referrer Policy, Permissions Policy and COOP only on HTML/XHTML responses; CSP script directives are parsed instead of searched as an undifferentiated string.
- Added a Stop control, asynchronous local-network DNS permission preflight and regression tests for pinned DNS, escaped paths, redirect-query stripping and prompt cancellation.

### Dependency and validation notes
- Pinned OkHttp to 5.5.1. The upstream release includes a certificate-blocklist update; see the OkHttp 5.5.1 change log.
- CI must pass Android Lint, the unit-test suite and debug APK assembly before the release is published. Device-level validation remains necessary for Android 17 local-network permission behavior, OEM TLS providers, mobile networks and real-world servers.
- The Web audit remains a safe, unauthenticated configuration and public-metadata check. It is not a web application penetration test, does not execute JavaScript, submit forms, brute-force paths or exploit vulnerabilities.

## 2.10.0 — 2026-11-23

### Rebuilt rootless UDP engine
- Replaced one-coroutine/one-blocking-DatagramSocket-per-port probing with a non-blocking DatagramChannel + Selector event loop.
- Bounded in-flight probes to 64, added a conservative adaptive window, fair retry scheduling and 0–3 retries for unanswered ports.
- Added cancellation checks between selector waits (maximum 50 ms) and deterministic cleanup of every in-flight channel.
- Increased the UDP per-address range limit from 512 to 4,096 ports; all selected DNS addresses together are capped at 16,384 host/port checks.
- Added protocol-aware DNS A and NTP probes with transaction/response validation. A received generic UDP datagram confirms endpoint responsiveness, not the identity of the service.
- Added explicit NOT_TESTED results for DHCP, TFTP, SNMP, IKE, SSDP and mDNS when a safe/protocol-correct unicast probe is not available. No default SNMP community or guessed TFTP filename is sent.
- Added separate IPv4 LAN multicast discovery for SSDP M-SEARCH and mDNS DNS-SD PTR responses, with active-interface selection and temporary Android Wi-Fi multicast lock.
- Displayed every final port state, attempt count, evidence level and a bounded hexadecimal response preview. Results remain in RAM.
- Unified UDP hostname resolution with TCP: one deterministic IPv4-preferred IP by default, with an explicit all-address option.
- Added regression tests for DNS/NTP validation, retry-after-timeout, exact result coverage, unsupported probes and prompt cancellation.

### Validation
- Android Lint, unit tests and debug APK assembly run in GitHub Actions. Physical Android testing is still required for multicast behavior across OEMs, Wi-Fi chipsets, routers and IPv6 networks.
- Non-root Android still cannot guarantee delivery of every ICMP error or provide raw-packet capture. UDP silence therefore remains OPEN|FILTERED, not proof of an open or closed port.

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
