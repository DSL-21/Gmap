# Gmap scanner architecture and performance contract

## Product target

Gmap is a rootless Android network scanner. The objective is a fast, accurate, Nmap-inspired tool with a polished mobile interface. It is not a wrapper around a remote scanner and does not depend on Termux or root.

## Performance requirements

- No arbitrary low fixed concurrency limit as a product rule.
- Prefer event-driven non-blocking networking for high numbers of simultaneous probes.
- Treat coroutine count and socket concurrency as separate concepts.
- Use adaptive outstanding-probe scheduling based on measured RTT, timeout rate, errors, and device/network feedback.
- Provide an advanced manual override, but default to automatic tuning.
- Preserve scan accuracy: raising concurrency must not silently convert timeouts into closed ports.
- Expose elapsed time, scanned count, throughput, timeout count, and result confidence in the UI.
- Benchmark against Nmap \`-sT\` rather than comparing a rootless TCP Connect scan with Nmap's raw-packet SYN scan.

## Proposed TCP engine

Evaluate a Java NIO \`SocketChannel\` + \`Selector\` event loop coordinated by Kotlin coroutines. A selector can monitor many non-blocking connection attempts without dedicating one blocked thread to each connection. The implementation must be validated on real Android versions and devices before being treated as production-ready.

The scheduling window should adapt, not blindly grow forever:

- Increase the number of in-flight probes while the network is responding promptly and the device has resources.
- Decrease it when response latency, timeouts, descriptor pressure, or local errors indicate congestion.
- Handle cancellation by closing all pending channels and releasing selector resources.
- Keep port-state classification honest: connection accepted = OPEN; explicit refusal = CLOSED; timeout/no response = FILTERED or UNKNOWN; local/network errors = ERROR.

An implementation may still need a resource-aware operational ceiling. That is not an artificial speed throttle: it prevents file-descriptor exhaustion, memory pressure, router overload, and misleading results. The ceiling should be derived from tested Android behavior and configurable in advanced settings, not hard-coded to a small worker count.

## Memory-only privacy model

Runtime scan data is ephemeral:

- No JSON, CSV, TXT, XML, or other scan-result files.
- No SQLite, Room, DataStore, or SharedPreferences for scan results/settings.
- No automatic exports or background report writing.
- No analytics, telemetry, or cloud synchronization of targets/results.
- In-memory scan sessions and summaries are available while the app process is alive; they disappear when the process/session ends.

Android itself may maintain ordinary application/system metadata outside Gmap's control. The app must not create its own persistent scan-result artifacts.

## Benchmark method

1. Use the same Android phone, Wi-Fi/mobile network, target host, port set, and test window.
2. Compare Gmap TCP Connect with Nmap \`-sT\` on the same port set; do not compare against \`-sS\` as though the methods were equivalent.
3. Run repeated trials and compare median and p95 completion time, connection outcomes, timeout rate, CPU, memory, and battery impact.
4. Test at least a low-latency LAN target and a higher-latency target.
5. Report both speed and accuracy. A faster scan that misses open ports is not a better scanner.

## Android constraints

The normal unmodified Android app permission model does not provide general raw-packet privileges. Do not promise raw SYN, arbitrary ICMP, ARP packet crafting, Wi-Fi monitor mode, or injection without a separately validated platform capability.

For apps targeting Android 17 / API 37 and above, local network access requires handling the platform's \`ACCESS_LOCAL_NETWORK\` runtime permission. Keep this behind a version/target-aware permission layer; do not request it for the current target SDK 36 build.
