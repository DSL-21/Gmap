# Gmap — Rootless Network Scanner for Android

Gmap is an Android network assessment toolkit designed to run without root access. Its goal is to bring fast, practical, Nmap-inspired discovery and assessment workflows to a standalone Android application.

## Project principles

- **Rootless first:** use standard Android networking APIs; do not require root, Termux, or an external computer.
- **Performance matters:** optimize probe scheduling, socket handling, response timing, and result processing. Do not impose arbitrary low concurrency limits.
- **Accuracy over fake speed:** adapt the outstanding-probe window to observed latency, timeouts, device resources, and network behavior.
- **Memory-only by default:** scan results and session summaries exist only in application memory. Gmap does not write scan results to JSON, CSV, text files, a database, shared preferences, or external storage.
- **No background telemetry:** no analytics or cloud upload of scan targets/results.
- **English-first UI:** user-facing labels, scan states, and documentation are in English.

## Current development branch

The \`feature/rootless-scanner-v2\` branch is an architectural prototype introducing:

- A dark Jetpack Compose / Material 3 interface.
- A dedicated TCP Connect scanner module.
- Single-host scanning by hostname or IP address.
- User-defined TCP port ranges.
- Separate \`OPEN\`, \`CLOSED\`, \`FILTERED\`, and \`ERROR\` results.
- Progress reporting and cancellation.
- Explicit authorization confirmation before a scan starts.

**Performance note:** the current TCP implementation is a functional baseline, not the final high-performance engine. It currently uses blocking socket connects on a bounded worker pool. The next engine milestone is an event-driven, non-blocking TCP connect loop with adaptive in-flight probes, followed by real-device benchmarks. The temporary baseline worker count must not be treated as a product performance ceiling.

The current service labels are hints based on conventional port numbers. They are not protocol-level service or version detection.

## Performance strategy

The intended scanner will use an adaptive scheduling model:

1. Start with a measured, device-appropriate number of in-flight connection attempts.
2. Increase parallel probes while latency and completion rates remain healthy.
3. Reduce the outstanding window when timeouts, local resource pressure, or packet loss rise.
4. Keep timeouts and retries visible and configurable rather than silently misclassifying results.
5. Benchmark against Nmap TCP Connect scans (\`-sT\`) using the same target, port list, timeout assumptions, and network path.

Kotlin coroutines are useful for coordination and UI responsiveness, but blocking \`Socket.connect()\` still occupies a thread. The performance engine will therefore evaluate non-blocking Java NIO channels/selectors rather than assuming that creating more coroutines automatically makes network scans faster.

## Rootless technical boundaries

A normal Android application cannot assume privileged raw-packet access. Gmap will not claim to provide raw TCP SYN scanning, raw ICMP packet crafting, ARP packet scanning, Wi-Fi monitor mode, or packet injection on an unmodified device.

The initial supported method is TCP Connect scanning. Further rootless modules can include UDP application-level probes, DNS, TLS certificate inspection, protocol-aware service detection, HTTP security checks, and system-mediated local-service discovery where appropriate.

## Privacy and storage

Scan targets, port results, host details, and scan history are held in RAM for the active application session only. They are discarded when the process/session ends. There is no automatic file export, JSON/CSV report generation, local database, or cloud sync. A future export feature, if ever added, must be an explicit user-initiated action and must not run automatically.

## Build

Open the project in Android Studio and use the included Gradle wrapper.

- Minimum SDK: 26
- Compile SDK: 36
- Target SDK: 36
- Language: Kotlin
- UI: Jetpack Compose and Material 3

## Responsible use

Use Gmap only on systems and networks that you own or have explicit permission to assess. Start with a scan profile appropriate to the target and network, and avoid overwhelming devices or network infrastructure.
