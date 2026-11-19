# Gmap scanner architecture — 2.8.0

## Product and trust boundary

Gmap is a native Android application built with Kotlin and Jetpack Compose. All scans are user-initiated from the UI. The app does not expose an exported service, receiver, provider, WebView, JavaScript bridge or deep-link entry point. It uses ordinary Android networking APIs; it does not require root or a companion service.

Use Gmap only against devices and networks you own or are explicitly authorized to assess. The scanner sends network requests to the target selected by the user; it does not exploit services, authenticate, brute-force credentials or attempt state-changing actions.

## Permissions and data handling

The manifest requests only INTERNET, ACCESS_NETWORK_STATE and ACCESS_LOCAL_NETWORK. The application component is the launcher activity. Android backup is disabled. Scan inputs and result history remain in ViewModel memory; no scan database, report exports, app-owned output files, clipboard export, analytics or cloud sync are implemented.

## Local network discovery

The Network dashboard reads Android ConnectivityManager and LinkProperties data. Discovery supports IPv4 subnets from /22 to /30 and uses bounded batches of 32 hosts and a maximum of 128 concurrent TCP probes over 27 common ports. This is a TCP presence check, not ARP, ICMP or a complete layer-2 inventory. Devices without responsive services on those ports may be missed. Device-role names are estimates based on ports, not authenticated identification.

## TCP Connect scanner

The TCP engine uses non-blocking Java NIO SocketChannel and Selector rather than one thread per port. It exposes Gmap-native scan modes:

- Reliable: lower concurrency, longer connection timeout and a larger retry budget.
- Balanced: default balance of throughput and verification.
- Performance: higher concurrency with a shorter timeout and one retry.
- Maximum: up to 128 concurrent probes with a bounded retry budget and adaptive control.
- Custom: user-selected concurrency, timeout, retry count and adaptive control.

The selected configuration is persisted locally using Android SharedPreferences and is snapshotted when a scan starts. Changing Settings does not mutate a running scan.

Unanswered probes are retried only within the configured retry budget. A TCP refusal is a positive response and remains CLOSED; it is not retried. A port that still does not respond after retries remains FILTERED / NO RESPONSE, never CLOSED. Retry scheduling is fair: a retry cannot indefinitely starve the first attempt for other requested ports. The scan returns exactly one final result per requested port.

Adaptive concurrency evaluates batches of probe outcomes instead of cutting the window for each isolated timeout. Sustained timeout ratios decrease the active window and introduce a short backoff; healthy batches gradually increase it toward the profile's configured maximum. Turning adaptive control off uses the configured maximum directly, while local socket/resource protection remains active.

- Successful TCP connect: OPEN.
- Explicit connection refusal: CLOSED.
- No response after the configured retries: FILTERED.
- Local permission, routing or I/O failure: ERROR.

A hostname is resolved with `InetAddress.getAllByName()` and every returned IPv4/IPv6 address is scanned independently across the requested range. Results retain the address that produced them. This is TCP Connect, not raw-packet SYN scanning; ordinary non-root Android networking restrictions still apply.

## Service identification

A bounded worker pool performs read-only protocol handshakes for selected open ports: SSH/FTP/Telnet/SMTP/POP3/IMAP greetings, VNC greeting, MySQL greeting, HTTP HEAD, TLS handshake, Redis PING, PostgreSQL SSL negotiation, SMB2 negotiate and RDP negotiation. It does not send credentials or attempt login. A failed fingerprint probe does not alter the underlying TCP port state.

Port-number service labels are hints only. Product/version identities are generated only when a service explicitly discloses a version.

## UDP probing

UDP scanning accepts up to 512 ports per run and runs at most 48 simultaneous probes. It uses read-only DNS, NTP, SSDP and mDNS messages on selected service ports; other ports receive an empty datagram. A response means OPEN, a surfaced ICMP port-unreachable means CLOSED, and silence remains OPEN|FILTERED. UDP silence is not proof that a port is closed.

## Web audit

The Web audit accepts HTTP or HTTPS URLs, uses bounded connection/read timeouts, disables automatic redirect following and limits public resource checks to a fixed set of paths. A GET fallback is bounded to a 256-byte sample and is used only for the exposed Git HEAD check. Redirects must retain the hostname and effective port; a same-host HTTP-to-default-HTTPS upgrade is allowed, but HTTPS downgrade and arbitrary port pivots are rejected.

Before retaining response metadata, the audit:
- Redacts Set-Cookie values while retaining cookie names and security attributes.
- Omits query strings and fragments from the initial audit URL and redirect destinations.
- Caps the number and length of response headers and values.

HTTP support remains enabled because it is an explicit feature. HTTP has no transport encryption. The app displays a warning, and the audit does not accept embedded URL credentials or submit user authentication.

### Known Web-audit limitation

The current implementation uses the platform HttpURLConnection stack and does not pin a DNS answer to the actual socket connection. A hostname controlled by an attacker could theoretically change its DNS answer between resolution and connection (DNS rebinding). This is not triggered in the background: the user must manually submit a hostname in the Web audit. Do not use the Web audit on domains you do not trust. A future hardening step should replace this path with a DNS-pinned HTTP/TLS client that preserves SNI and hostname verification.

## Vulnerability intelligence

When a service exposes an explicit product version, Gmap can create a CPE candidate and query NVD, CISA KEV and FIRST EPSS using public HTTPS endpoints. It sends product CPEs and CVE identifiers, not target IP addresses or hostnames. Provider redirects are not followed. CPE/CVE matches are leads for manual verification, not proof that the installed service is vulnerable.

## Build and validation

CI runs Android Lint, the unit-test suite and debug APK assembly. The workflow uses GitHub Actions pinned to immutable commit SHAs and Dependabot monitors Gradle and GitHub Actions dependencies. CI validation does not cover every OEM implementation, physical-device battery/thermal behaviour or an independent penetration test.

The GitHub release APK is debug-signed for direct testing and is not a production-keystore or Play Store artifact. A production release requires a maintainer-controlled signing key and protected secrets.
