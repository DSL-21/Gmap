# Gmap scanner architecture — 2.10.0

## Product and trust boundary

Gmap is a native Android application built with Kotlin and Jetpack Compose. All scans are user-initiated from the UI. The app does not expose an exported service, receiver, provider, WebView, JavaScript bridge or deep-link entry point. It uses ordinary Android networking APIs; it does not require root or a companion service.

Use Gmap only against devices and networks you own or are explicitly authorized to assess. The scanner sends network requests to the target selected by the user; it does not exploit services, authenticate, brute-force credentials or attempt state-changing actions.

## Permissions and data handling

The manifest requests INTERNET, ACCESS_NETWORK_STATE, ACCESS_LOCAL_NETWORK and CHANGE_WIFI_MULTICAST_STATE. The application component is the launcher activity. Android backup is disabled. Scan inputs and result history remain in ViewModel memory; no scan database, report exports, app-owned output files, clipboard export, analytics or cloud sync are implemented.

## Local network discovery

The Network dashboard reads Android ConnectivityManager and LinkProperties data. Discovery supports IPv4 subnets from /22 to /30 and uses bounded batches of 32 hosts and a maximum of 128 concurrent TCP probes over 27 common ports. This is a TCP presence check, not ARP, ICMP or a complete layer-2 inventory. Devices without responsive services on those ports may be missed. Device-role names are estimates based on ports, not authenticated identification.

## TCP Connect scanner

The TCP engine uses non-blocking Java NIO SocketChannel and Selector rather than one thread per port. It exposes Gmap-native scan modes:

- Reliable: lower concurrency, longer connection timeout and a larger retry budget.
- Balanced: default balance of throughput and verification.
- Performance: higher concurrency with a shorter timeout and one retry.
- Maximum: up to 128 concurrent probes with a bounded retry budget and adaptive control.
- Custom: user-selected concurrency, timeout, retry count and adaptive control.

The selected configuration is held in ViewModel memory and is snapshotted when a scan starts. It is not persisted across process restarts. Legacy TCP scan preferences from previous versions are deleted at startup.

Unanswered probes are retried only within the configured retry budget. A TCP refusal is a positive response and remains CLOSED; it is not retried. A port that still does not respond after retries remains FILTERED / NO RESPONSE, never CLOSED. Retry scheduling is fair: a retry cannot indefinitely starve the first attempt for other requested ports. The scan returns exactly one final result per requested port.

Adaptive concurrency evaluates batches of probe outcomes instead of cutting the window for each isolated timeout. Sustained timeout ratios decrease the active window and introduce a short backoff; healthy batches gradually increase it toward the profile's configured maximum. Turning adaptive control off uses the configured maximum directly, while local socket/resource protection remains active.

- Successful TCP connect: OPEN.
- Explicit connection refusal: CLOSED.
- No response after the configured retries: FILTERED.
- Local permission, routing or I/O failure: ERROR.

A hostname is resolved once with `InetAddress.getAllByName()`. By default, Gmap selects one deterministic address (IPv4 preferred, then address order) so a normal 1–1024 scan means exactly 1,024 checks against one IP. The UI exposes an explicit option to scan every resolved IPv4/IPv6 answer. Each selected address receives only the requested start/end port range, and aggregate work is capped at 262,144 host/port checks. Results retain the address that produced them. This is TCP Connect, not raw-packet SYN scanning; ordinary non-root Android networking restrictions still apply.

## Service identification

A bounded worker pool performs read-only protocol handshakes for selected open ports: SSH/FTP/Telnet/SMTP/POP3/IMAP greetings, VNC greeting, MySQL greeting, HTTP HEAD, TLS handshake, Redis PING, PostgreSQL SSL negotiation, SMB2 negotiate and RDP negotiation. It does not send credentials or attempt login. A failed fingerprint probe does not alter the underlying TCP port state.

Port-number service labels are hints only. Product/version identities are generated only when a service explicitly discloses a version.

## UDP probing

The UDP engine uses non-blocking Java NIO DatagramChannel and Selector. A single selector manages a bounded in-flight set (maximum 64) rather than creating a coroutine and blocking DatagramSocket for every port. The default window starts conservatively and is adjusted from batches of timeout outcomes. A fair retry queue retries silent ports 0–3 times without starving first-pass coverage. Cancellation is checked between selector waits capped at 50 ms, and all registered channels are closed in a finally block.

A unicast UDP sweep accepts up to 4,096 ports per target address. Hostname resolution follows the same target-selection policy as TCP: one deterministic IPv4-preferred address by default, or all resolved addresses when explicitly requested. Aggregate work is capped at 16,384 host/port checks.

The probe catalog uses a DNS A query for example.com on UDP/53 and validates the matching transaction ID and DNS response bit. UDP/123 uses an NTPv4 client request and validates the NTP server mode, version and minimum response size. Other unrecognized ports receive a single-byte 0x00 probe; any response proves a responsive UDP endpoint but does not identify its application protocol.

DHCP, TFTP, SNMP, IKE, SSDP and mDNS are marked NOT_TESTED in the unicast sweep when a safe and protocol-correct probe is unavailable. The scanner does not guess TFTP filenames or send default SNMP communities. SSDP and mDNS are available in a separate IPv4 multicast discovery operation: SSDP sends M-SEARCH to 239.255.255.250:1900 and mDNS sends a DNS-SD PTR query to 224.0.0.251:5353. Discovery binds to the active interface and acquires a temporary Wi-Fi multicast lock. The mDNS listener may be unavailable if port 5353 is already occupied; the app reports this as a warning rather than silently claiming discovery succeeded.

Final states are OPEN, CLOSED, OPEN_FILTERED, ERROR and NOT_TESTED. A UDP reply confirms the endpoint is responsive; only protocol validation marks DNS or NTP service as confirmed. ICMP port-unreachable is classified CLOSED only when Android surfaces it to the application. Silence remains OPEN_FILTERED and never becomes proof of an open or closed port. A response preview is limited to 16 bytes and is kept only in memory.

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
