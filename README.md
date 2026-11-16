# Gmap 2.5.0 — Rootless Android Network Scanner

Gmap is a native Android network scanner and security-audit toolkit built with Kotlin, Jetpack Compose and standard Android networking APIs. It runs without root or a companion computer.

## Security and responsible use

Gmap is an explicitly user-operated, read-only network inspection tool. Use it only on devices and networks you own or have permission to assess. TCP concurrency is hard-capped to 128 outstanding probes, local discovery and UDP probing have independent limits, and the Web audit bounds response metadata, redacts cookie values, omits URL query strings and refuses unsafe cross-origin, cross-port or HTTPS-downgrade redirects.

The Web audit supports explicitly entered HTTP URLs for compatibility testing. HTTP is plaintext; do not include credentials or sensitive information in target URLs. See [SECURITY.md](SECURITY.md) and [the security audit](docs/SECURITY_AUDIT.md) for scope and known limitations.

## Modules

Gmap 2.5.0 keeps the primary interface focused on four destinations: Network, Scan, Web and Results. Settings are available from the top app bar.

### Network discovery

- Active connection type, interface, IPv4/IPv6 addresses, default gateway and DNS servers.
- Local IPv4 discovery for subnets from /22 through /30.
- Parallel TCP presence probes across 27 commonly used service ports.
- Concurrent work is bounded to keep socket and coroutine usage under control.
- Devices are sorted by IPv4 address and assigned a likely role such as Printer, NAS/File sharing, Camera/IoT, Remote access, Web service or Server.
- A discovered device can be opened directly in the single-host TCP scanner.

Local discovery uses ordinary TCP connections, not ARP. A device that does not answer any of the selected TCP ports will not appear in the discovered-device list. Device-role labels are estimates based on observed ports, not authenticated device identification.

### TCP host scanner

- One hostname, IPv4 address or IPv6 address per scan.
- Custom port ranges from 1 to 65535.
- Quick (1–256), Well-known (1–1024), Extended (1–10000) and Full TCP (1–65535) presets.
- Non-blocking TCP Connect engine built with Java NIO `SocketChannel` and `Selector`.
- Adaptive probe window, local socket-resource backoff, cancellation and progress metrics.
- Port states: `OPEN`, `CLOSED`, `FILTERED` and `ERROR`.
- Read-only application-layer identification for SSH, FTP, Telnet, SMTP, POP3, IMAP, HTTP, TLS, VNC, MySQL/MariaDB, Redis, PostgreSQL, SMB2 and RDP.
- For other standard TCP ports, Gmap shows a likely service label from the port number only. This is not a confirmed protocol fingerprint.
- Conservative product/version fingerprinting when a service exposes an explicit version banner or HTTP server header.
- CPE 2.3 candidate generation and optional NVD CVE, CISA KEV and FIRST EPSS enrichment.

### UDP probe scanner

- Custom UDP ranges up to 512 ports per run.
- DNS, NTP, SSDP and mDNS protocol-aware probes; other ports receive a zero-length UDP datagram.
- A received response is `OPEN`.
- An ICMP port-unreachable surfaced by Android is `CLOSED`.
- A silent probe is `OPEN|FILTERED`; silence is not reported as confirmed closed.
- Results and history are held in RAM.

### Web audit

- DNS resolution and HTTP/HTTPS status and response headers.
- TLS cipher, certificate subject, issuer, expiry and Subject Alternative Names where available.
- HSTS, CSP, X-Content-Type-Options, clickjacking protection, Referrer-Policy, Permissions-Policy and Cross-Origin-Opener-Policy checks.
- Cookie attribute checks for Secure, HttpOnly and SameSite.
- A synthetic-origin CORS check for reflected credentialed origins.
- Same-host redirect tracking, with a limited GET fallback when a server rejects HEAD.
- Explicit HTTP support for user-initiated audits. HTTP requests are unauthenticated and unencrypted; the UI warns users not to supply credentials or sensitive URL parameters.
- Checks for `/.well-known/security.txt`, `/robots.txt`, `/openapi.json` and `/.git/HEAD`. Only the Git metadata check reads a tiny, bounded response sample to confirm a Git reference.
- Findings include severity, evidence and remediation guidance.

The Web module checks exposed configuration and public metadata. It is not a web application exploit scanner and does not test authenticated application flows, input validation, authorization or business logic.

### Vulnerability intelligence

When an explicit product version is identified from a TCP banner or web response header, Gmap can create a CPE 2.3 candidate and query public NVD CVE data, CISA Known Exploited Vulnerabilities (KEV) and FIRST EPSS.

Results can include CVSS, EPSS, KEV status, date added and required action. A CPE/CVE match is a lead for manual verification, not proof that the running host is exploitable. Vendor backports, distribution patches, configuration and reachable attack surface must be checked before deciding whether a finding applies.

Online intelligence can be disabled independently for TCP and Web audits in Settings. When enabled, product CPEs and CVE identifiers are sent to the public intelligence providers; target hostnames and IP addresses are not included in those lookups.

### Privacy and history

TCP, UDP and Web results are held in application memory. Recent results are not exported, copied to the clipboard or written to a database, files, preferences or a cloud service. No analytics or cloud sync are used.

## Android compatibility and network permissions

- Minimum Android version: Android 8.0 (API 26).
- Compile SDK: 37.
- Target SDK: 37 (Android 17).
- Cleartext HTTP is permitted because the Web module audits user-selected HTTP endpoints; it sends only unauthenticated, read-only requests. Prefer HTTPS whenever available.
- Android 17 local-network access is requested at runtime when a LAN operation is started for a local address or local hostname. Public internet targets do not trigger that permission prompt.
- Local subnet discovery requires local-network access.

## Technical limits

Gmap uses standard Android networking APIs. It does not claim raw TCP SYN scanning, raw ICMP packet crafting, ARP packet scanning, Wi-Fi monitor mode or packet injection. Local discovery uses TCP presence probes.

UDP silence is inherently inconclusive. Some UDP services do not respond to an unauthenticated request, and firewalls may suppress ICMP errors.

Service labels inferred from a port number are hints only. Version-based vulnerability correlation is limited by what the remote service chooses to disclose.

## Build

- Android Gradle Plugin: 9.1.1
- Gradle wrapper: 9.3.1
- Kotlin: 2.2.10 (AGP built-in Kotlin)
- JDK: 17
- Compile SDK: 37
- Target SDK: 37
- Minimum SDK: 26
- UI: Jetpack Compose and Material 3

Build and run unit tests:

```bash
./gradlew --no-daemon testDebugUnitTest assembleDebug
```

The GitHub Actions release workflow produces a CI debug-signed APK for direct device testing. It is not a production-keystore or Google Play package. A SHA-256 checksum is published alongside the APK.

## Validation

CI runs the unit-test suite and assembles the Android debug APK. Protocol, parsing, subnet, permission-gate and Web audit behavior is covered by unit tests. Device-level compatibility, battery impact, router-specific behavior and comparative Nmap `-sT` benchmarks still need to be measured on physical Android devices before performance claims are made.
