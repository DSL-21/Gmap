# Gmap 2.5.0 — source security audit

**Audit date:** 2026-11-16  
**Reviewed ref:** main before the 2.5.0 hardening commit  
**Audit type:** source/configuration review plus automated CI checks; not an independent penetration test.

## Scope

Reviewed the Android manifest and permissions, app lifecycle and Compose entry points, input validation, TCP/UDP/local-network scanners, protocol fingerprinting, Web audit, CVE data retrieval and parsing, result/history handling, Gradle configuration, resources, and GitHub Actions workflows.

## Findings and changes in 2.5.0

| Area | Finding | Change |
|---|---|---|
| TCP resource use | Adaptive TCP concurrency could grow to the whole port range, creating excessive simultaneous sockets on a phone. | Hard cap of 128 outstanding probes, including adaptive growth. |
| Web privacy | Raw Set-Cookie response values could be retained in result headers and exposed in finding evidence. | Cookie values are replaced with <redacted> before response metadata is retained. |
| Web privacy | URL query strings may carry short-lived tokens or session state. | Query strings are not sent by the audit after normalization and are not retained in displayed result URLs. |
| Web redirect boundary | Same-host redirects could change port or downgrade HTTPS to HTTP. | Redirects are limited to the same host and effective port; a same-host HTTP-to-default-HTTPS upgrade is the only allowed port-changing case. |
| Metadata memory | A remote server could return an unusually large number of long headers. | Response header count, value count and field lengths are capped. |
| Third-party intelligence | Provider requests allowed automatic redirects. | Automatic provider redirects are disabled. |
| Repository hygiene | IDE state, a Kotlin error log and an unused legacy layout were tracked. | Removed from the source tree and added to ignore rules. |
| CI supply chain | Actions referenced mutable major-version tags and the CI job published an extra debug APK artifact. | Actions pinned to immutable commit SHAs; Android Lint added; redundant APK artifact upload removed; Dependabot added. |

## Existing protections observed

- Only INTERNET, ACCESS_NETWORK_STATE and ACCESS_LOCAL_NETWORK are requested.
- The app has one exported launcher activity and no externally callable service, receiver or provider.
- Android backup is disabled.
- TCP, UDP and local discovery use bounded timeouts and concurrency; UDP is capped at 512 ports per run and 48 parallel probes; local discovery is bounded to 32 hosts per batch and 128 probes.
- Network connections are closed using scoped cleanup or cancellation cleanup.
- Service fingerprinting uses read-only handshakes; no credentials or exploit payloads are sent.
- TLS certificate checks use the platform trust store and hostname verification; no trust-all TLS context was found in the reviewed code.
- Vulnerability enrichment uses fixed HTTPS provider endpoints, bounded response sizes and CPE/CVE identifiers rather than target hostnames/IPs.
- Results are held in memory; no scan database, report file export, clipboard export, analytics or cloud sync was found in the reviewed app code.
- No WebView, JavaScript bridge, dynamic code loader, shell execution or runtime command execution was found in the reviewed source.

## Remaining limitations and risks

1. **DNS rebinding in Web audit:** the Web module uses the platform URL connection stack and does not pin DNS results to the actual socket connection. A user who manually audits an attacker-controlled hostname could theoretically encounter DNS rebinding. This is documented and remains an item for a dedicated DNS-pinned HTTP/TLS implementation.
2. **Cleartext HTTP:** usesCleartextTraffic is enabled because user-selected HTTP endpoints are a supported audit target. HTTP requests are unencrypted. The UI warns about this; users must not include credentials or sensitive query parameters.
3. **Local-network access:** on Android versions before the newer local-network permission model, an app with INTERNET permission can generally reach networks permitted by the OS. Gmap does not run network scans in the background, but users should still only specify authorized targets.
4. **Device validation:** unit tests and CI cannot validate all phone models, OEM network stacks, thermal throttling, battery impact or every router response. Physical-device testing remains required.
5. **Release signing:** CI releases are debug-signed. Production distribution requires a maintainer-managed release keystore and protected signing secrets.
6. **Audit assurance:** this is a focused source/configuration audit, not a formal security certification, fuzzing campaign or independent penetration test. No claim of zero vulnerabilities is made.

## Validation planned for CI

- Android Lint (lintDebug)
- Kotlin/JVM unit tests (testDebugUnitTest)
- Debug APK assembly (assembleDebug)
- Regression tests for TCP concurrency, cookie-value redaction, query suppression and redirect port isolation.
