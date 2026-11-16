# Gmap scanner architecture

## Product target

Gmap is a native rootless Android scanner. It uses Android networking APIs and runs without Termux, root or a remote scanning service. Session findings remain in memory.

## Network dashboard and local discovery

The Network screen reads Android `ConnectivityManager` and `LinkProperties` data: transport, interface, assigned addresses, default route and DNS servers.

IPv4 discovery calculates host addresses for prefixes /22 through /30 and checks each address using ordinary TCP connections to ports 22, 80, 443, 445, 8080 and 3389. Concurrency is bounded to 64 hosts. This is a TCP presence check, not ARP, ICMP or a complete layer-2 inventory. A device with no responsive service on those ports can be missed. A discovered address can be passed directly to the TCP host scanner.

## TCP host scanning

The TCP engine uses non-blocking Java NIO `SocketChannel` and `Selector`. It does not allocate one thread or coroutine per port.

The outstanding-probe window grows as the scan progresses. If the OS reports local socket/file-descriptor exhaustion, the window is reduced, the scanner backs off, and the same port is retried. This avoids a permanent small worker cap while respecting current device limits.

TCP classification:

- TCP connect succeeds: `OPEN`.
- The target explicitly refuses the connection: `CLOSED`.
- The connection receives no response before its deadline: `FILTERED`.
- Local permission, routing or I/O failures: `ERROR`.

The scanner supports a single hostname, IPv4 or IPv6 address per run and custom TCP ranges from 1 to 65535. It is a TCP Connect scanner, not a raw-packet SYN scanner.

## Service identification

After the TCP scan completes, a separate bounded pass identifies selected open services using read-only exchanges: SSH, FTP, SMTP, POP3, IMAP and VNC greetings; MySQL greeting; HTTP HEAD headers; TLS handshake and certificate details; Redis PING; PostgreSQL SSL negotiation.

The detector does not authenticate, attempt passwords, change service state or exploit the endpoint. A probe failure does not change the underlying TCP state.

## UDP probing

The UDP scanner uses ordinary `DatagramSocket` APIs and permits up to 512 ports per run. It limits concurrent probes to 48.

Protocol-aware payloads are used for DNS (A query for example.com), NTP (client request), SSDP (M-SEARCH) and mDNS (DNS-SD service query). Other ports receive a zero-length datagram.

UDP classification:

- A datagram response: `OPEN`.
- ICMP port-unreachable exposed by the Android socket stack: `CLOSED`.
- No response before timeout: `OPEN|FILTERED`.
- Local socket or I/O failures: `ERROR`.

A quiet UDP port cannot be called closed based only on silence. ICMP error delivery varies by operating system and network path.

## Web audit

The Web screen resolves the target hostname and sends an HTTP HEAD request to the supplied URL (or HTTPS when no scheme is supplied). It records response status and headers, plus TLS cipher and peer certificate subject, issuer and expiry where the platform TLS handshake succeeds.

Checks currently cover:
- HTTPS/HSTS configuration.
- Content-Security-Policy.
- X-Content-Type-Options.
- X-Frame-Options or CSP frame-ancestors.
- Referrer-Policy.
- Server header disclosure.
- Cookie Secure, HttpOnly and SameSite attributes.
- HTTP redirect status and certificate expiry proximity.

These are response-configuration findings, not proof of exploitable vulnerabilities. The current Web module does not crawl paths, test authenticated workflows, execute payloads, exploit services or query a CVE database. Reports are copied only after an explicit user action.

## Findings and storage

Host TCP scans, UDP scans and Web audit findings are held in in-memory ViewModels. A bounded recent history is kept while the process is alive. Gmap does not write scan output to a database, JSON/CSV/TXT files, preferences or cloud storage.

## Android constraints

Gmap targets SDK 36 while compiling against SDK 37. Android 17/API 37 local-network permission handling must be added and tested before raising targetSdk to 37.

A standard Android application cannot assume access to privileged raw-packet capabilities. Do not promise raw SYN, arbitrary ICMP crafting, ARP packet scanning, Wi-Fi monitor mode or packet injection.

## Performance validation

Compare Gmap TCP Connect with Nmap `-sT` using the same host, port list, timeout assumptions and network path. Compare repeated median and p95 duration, state accuracy, timeouts, CPU, memory and battery. Do not compare TCP Connect against `-sS` as equivalent methods. Physical-device testing is still required.
