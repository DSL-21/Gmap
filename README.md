# Gmap — Rootless Network Scanner for Android

Gmap is an Android network assessment toolkit designed to run without root access. The long-term goal is to bring practical, Nmap-inspired network discovery and service assessment workflows to a standalone Android application.

## Current development milestone

The \`feature/rootless-scanner-v2\` branch introduces the modern application foundation:

- A dark, English-language Jetpack Compose interface.
- A dedicated TCP Connect scanning engine.
- Single-host scanning by hostname, IPv4 address, or IPv6 address.
- User-defined TCP port ranges from 1 to 65535.
- Bounded worker concurrency instead of one coroutine per port.
- Separate \`OPEN\`, \`CLOSED\`, \`FILTERED\`, and \`ERROR\` outcomes.
- Scan progress and cancellation.
- A required confirmation that the user owns the target or is authorized to assess it.

The service labels shown in this milestone are hints based on conventional port numbers. They are not the result of protocol-level service or version detection.

## Rootless design and technical boundaries

Gmap uses standard Android networking APIs. It does not require root access, Termux, or an external computer.

A normal Android application cannot assume access to privileged raw-packet capabilities. Therefore, this project does not claim to implement raw TCP SYN scanning, raw ICMP packet crafting, ARP packet scanning, Wi-Fi monitor mode, or packet injection.

The current scanner uses TCP Connect probes. A timeout is reported as \`FILTERED\` / no response because a silent timeout cannot prove that a port is closed. UDP probing, host discovery, protocol-level service detection, TLS inspection, security checks, scan history, and report export are planned as separate modules.

## Build

Open the project in Android Studio and use the included Gradle wrapper.

- Minimum SDK: 26
- Compile SDK: 36
- Target SDK: 36
- Language: Kotlin
- UI: Jetpack Compose and Material 3

## Responsible use

Use Gmap only on systems and networks that you own or have explicit permission to assess. Scanning may trigger monitoring, alerts, or service rate limits. Start with small port ranges and conservative timeouts when testing unfamiliar environments.
