# Gmap scanner architecture and performance contract

## Product target

Gmap is a rootless Android network scanner. The objective is a fast, accurate, Nmap-inspired tool with a polished mobile interface. It is not a wrapper around a remote scanner and does not depend on Termux or root.

## Performance requirements

- Do not impose an arbitrary low fixed concurrency ceiling as a product rule.
- Use event-driven, non-blocking networking to handle large numbers of simultaneous TCP connection attempts.
- Treat coroutine count, worker-thread count, and outstanding socket count as separate concepts.
- Grow the outstanding-probe window dynamically as the scan progresses.
- Back off only when the operating system reports local resource pressure, and retry the affected port rather than silently skipping it.
- Provide advanced timeout/concurrency controls only where they improve measured outcomes.
- Preserve scan accuracy: a timeout is not a closed port.
- Expose elapsed time, scanned count, throughput, timeout count, and result confidence in the UI.
- Benchmark against Nmap TCP Connect scans (\`-sT\`) using the same target, port list, timeout assumptions, and network path.

## Current TCP engine prototype

The current engine uses Java NIO \`SocketChannel\` and \`Selector\` with non-blocking connection attempts. It does not allocate one thread or coroutine per port.

The initial outstanding-probe window is derived from the requested port count and device CPU availability. The window grows in batches as results arrive and can expand up to the requested scan size. If the OS reports local socket/file-descriptor exhaustion, the scanner reduces the window, waits briefly, and retries the same port. This avoids a permanent arbitrary limit such as 48 workers while respecting actual device limits.

A selector event loop monitors connect readiness and finalizes each connection through \`finishConnect()\`. A deadline queue expires silent probes without scanning every pending socket on every iteration. Cancellation closes outstanding channels and selector resources.

Port-state classification:

- TCP connect succeeds: \`OPEN\`.
- The target explicitly refuses the connection: \`CLOSED\`.
- The connection receives no response before the configured deadline: \`FILTERED\` / no response.
- Local permission, routing, or I/O failures: \`ERROR\`.

This is a TCP Connect scanner. It is not a raw-packet SYN scanner. It is still a prototype and must be benchmarked on actual Android devices and networks before performance claims are made.

## Benchmark method

1. Use the same Android phone, Wi-Fi/mobile network, target host, port set, and test window.
2. Compare Gmap TCP Connect with Nmap \`-sT\` on the same port set; do not compare against \`-sS\` as though the methods were equivalent.
3. Run repeated trials and compare median and p95 completion time, connection outcomes, timeout rate, CPU, memory, and battery impact.
4. Test at least a low-latency LAN target and a higher-latency target.
5. Report both speed and accuracy. A faster scan that misses open ports is not a better scanner.

## Memory-only privacy model

Runtime scan data is ephemeral:

- No JSON, CSV, TXT, XML, or other scan-result files.
- No SQLite, Room, DataStore, or SharedPreferences for scan results/settings.
- No automatic exports or background report writing.
- No analytics, telemetry, or cloud synchronization of targets/results.
- In-memory scan sessions and summaries are available while the app process is alive; they disappear when the process/session ends.

Android itself may maintain ordinary application/system metadata outside Gmap's control. The app must not create its own persistent scan-result artifacts.

## Android constraints

A normal Android application cannot assume privileged raw-packet access. Do not promise raw SYN, arbitrary ICMP, ARP packet crafting, Wi-Fi monitor mode, or injection without a separately validated platform capability.

For apps targeting Android 17 / API 37 and above, local network access requires handling the platform's \`ACCESS_LOCAL_NETWORK\` runtime permission. Keep this behind a version/target-aware permission layer; do not request it for the current target SDK 36 build.
