# Gmap — Rootless Network Scanner for Android

Gmap is an Android network assessment toolkit designed to run without root access. Its goal is to bring fast, practical, Nmap-inspired discovery and assessment workflows to a standalone Android application.

## Project principles

- **Rootless first:** use standard Android networking APIs; do not require root, Termux, or an external computer.
- **Performance matters:** optimize probe scheduling, socket handling, response timing, and result processing. Do not impose arbitrary low concurrency limits.
- **Adaptive resource use:** expand outstanding TCP probes while the device and OS allow it; back off on real local resource pressure and retry affected probes.
- **Accuracy over fake speed:** a timeout is not proof that a port is closed.
- **Memory-only by default:** scan results and session summaries exist only in application memory. Gmap does not write scan results to JSON, CSV, text files, a database, shared preferences, or external storage.
- **No background telemetry:** no analytics or cloud upload of scan targets/results.
- **English-first UI:** user-facing labels, scan states, and documentation are in English.

## Current development branch

The `feature/rootless-scanner-v2` branch introduces:

- A dark, English-language Jetpack Compose interface.
- A dedicated non-blocking TCP Connect scanning engine using Java NIO `SocketChannel` and `Selector`.
- Single-host scanning by hostname, IPv4 address, or IPv6 address.
- User-defined TCP port ranges from 1 to 65535.
- Adaptive outstanding-probe scheduling that grows to the requested scan size and backs off on OS-level resource exhaustion.
- Separate `OPEN`, `CLOSED`, `FILTERED`, and `ERROR` outcomes.
- Scan progress, throughput metrics, and cancellation.
- A required confirmation that the user owns the target or is authorized to assess it.

The service labels shown in this milestone are hints based on conventional port numbers. They are not the result of protocol-level service or version detection.

This is an early engine prototype, not a verified speed leader. It needs build verification and controlled benchmarks on real Android devices before performance claims can be made.

## Why not one coroutine per port?

Coroutines are useful for coordination and keeping the UI responsive, but blocking `Socket.connect()` still occupies a worker thread. Gmap's new TCP engine uses non-blocking channels registered with one selector, so the scanner can monitor many connection attempts without allocating one blocking worker per port.

The adaptive window starts based on device CPU availability and the requested scan size. It grows as results arrive. When the OS reports local socket/file-descriptor exhaustion, Gmap reduces the window, waits briefly, and retries the same port rather than silently skipping it.

## Build system

- Android Gradle Plugin: 9.1.1
- Gradle wrapper: 9.3.1
- Kotlin: 2.2.10 (AGP built-in Kotlin)
- Compile SDK: 37
- Target SDK: 36
- Minimum SDK: 26
- JDK: 17
- UI: Jetpack Compose and Material 3

The app deliberately remains at target SDK 36 for now. Android 17 (API 37) gates direct local-network TCP/UDP access behind the `ACCESS_LOCAL_NETWORK` runtime permission for apps targeting API 37 or higher. Gmap must add and test the full permission flow before raising its target SDK.

## Rootless design and technical boundaries

A normal Android application cannot assume access to privileged raw-packet capabilities. Therefore, this project does not claim to implement raw TCP SYN scanning, raw ICMP packet crafting, ARP packet scanning, Wi-Fi monitor mode, or packet injection.

The current supported method is TCP Connect scanning. Further rootless modules can include UDP application-level probes, DNS, TLS certificate inspection, protocol-aware service detection, HTTP security checks, and system-mediated local-service discovery where appropriate.

## Privacy and storage

Scan targets, port results, host details, and scan history are held in RAM for the active application session only. They are discarded when the process/session ends. There is no automatic file export, JSON/CSV report generation, local database, or cloud sync. A future export feature, if ever added, must be an explicit user-initiated action and must not run automatically.

## Responsible use

Use Gmap only on systems and networks that you own or have explicit permission to assess. Scanning may trigger monitoring, alerts, or service rate limits. Start with a scan profile appropriate to the target and network, and avoid overwhelming devices or network infrastructure.
