# Gmap — Rootless Android Network Scanner

Gmap is a native Android network scanner and security-audit toolkit built with Kotlin, Jetpack Compose and standard Android networking APIs. It runs without root or a companion computer.

## Modules

Gmap 2.2.0 keeps the primary interface focused on four destinations: Network, Scan, Web and Results. Settings are available from the top app bar.


### Network
- Active connection type, interface, IPv4/IPv6 addresses, default gateway and DNS servers.
- Local IPv4 discovery for subnets from /22 through /30.
- TCP presence probes on ports 22, 80, 443, 445, 8080 and 3389.
- A discovered device can be opened directly in the single-host TCP scanner.

Local discovery uses ordinary TCP connections, not ARP. A device that does not answer any of the selected TCP ports will not appear in the discovered-device list.

### TCP host scanner
- One hostname, IPv4 address or IPv6 address per scan.
- Custom port ranges from 1 to 65535.
- Quick (1–256), Well-known (1–1024), Extended (1–10000) and Full TCP (1–65535) presets.
- Non-blocking TCP Connect engine built with Java NIO `SocketChannel` and `Selector`.
- Adaptive probe window, local socket-resource backoff, cancellation and progress metrics.
- Port states: `OPEN`, `CLOSED`, `FILTERED` and `ERROR`.
- Read-only service identification for selected SSH, FTP, SMTP, POP3, IMAP, VNC, MySQL, HTTP, TLS, Redis and PostgreSQL services.

### UDP probe scanner
- Custom UDP ranges up to 512 ports per run.
- DNS, NTP, SSDP and mDNS protocol-aware probes; other ports receive a zero-length UDP datagram.
- A received response is `OPEN`.
- An ICMP port-unreachable surfaced by Android is `CLOSED`.
- A silent probe is `OPEN|FILTERED`; silence is not reported as confirmed closed.
- Results and history are held in RAM.

### Web audit
- DNS resolution and HTTP/HTTPS response status.
- TLS cipher and peer certificate subject, issuer and expiry where the platform handshake succeeds.
- Checks for HSTS, Content-Security-Policy, X-Content-Type-Options, clickjacking-related headers, Referrer-Policy, Server disclosure and cookie attributes.
- Findings include severity, evidence and a remediation suggestion.
- A Web audit report can be copied explicitly from the Web screen.

The Web module checks response configuration and headers. It is not a web application exploit scanner, does not test authenticated application flows and does not correlate detected software versions with a CVE database.

### Findings
Host TCP scans, UDP scans and Web audits are grouped in one screen. Recent results stay in application memory only; they are not written to a database, files, preferences or a cloud service.

## Technical limits

Gmap uses standard Android networking APIs. It does not claim raw TCP SYN, raw ICMP packet crafting, ARP packet scanning, Wi-Fi monitor mode or packet injection. Local device discovery uses TCP presence probes.

UDP silence is inherently inconclusive. Some UDP services do not respond to an unauthenticated request, and firewalls may suppress ICMP errors.

The app targets Android SDK 36 and supports Android 8.0 (API 26) or later. Android 17/API 37 local-network permission handling must be implemented and tested before raising targetSdk to 37.

## Build

- Android Gradle Plugin: 9.1.1
- Gradle wrapper: 9.3.1
- Kotlin: 2.2.10 (AGP built-in Kotlin)
- JDK: 17
- Compile SDK: 37
- Target SDK: 36
- Minimum SDK: 26
- UI: Jetpack Compose and Material 3

Build and run unit tests:

```bash
./gradlew --no-daemon testDebugUnitTest assembleDebug
```

The release workflow currently produces a CI debug-signed APK for direct device testing. It is not a separately production-signed Google Play package.

## Performance validation

CI unit tests cover TCP scanning, UDP reply handling, subnet calculation and HTTP header analysis. Device-level compatibility, battery impact and comparative Nmap `-sT` benchmarks still need to be measured on physical Android devices before performance claims are made.
