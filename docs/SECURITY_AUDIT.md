# Gmap 2.11.0 — source security review

**Review date:** 2026-11-23  
**Reviewed ref:** main during the 2.11.0 Web Audit hardening  
**Review type:** focused source/configuration review plus regression tests and CI validation; not an independent penetration test or formal security certification.

## Scope

Reviewed the Android manifest and permissions, app lifecycle and Compose entry points, input validation, TCP/UDP/local-network scanners, protocol fingerprinting, Web audit, CVE data retrieval and parsing, result/history handling, Gradle configuration, resources, and GitHub Actions workflows.

## Web Audit changes in 2.11.0

| Area | Previous risk / limitation | 2.11.0 change |
|---|---|---|
| DNS rebinding | DNS addresses shown in results were resolved separately from the connection actually opened by HttpURLConnection. | OkHttp uses a per-audit custom DNS resolver that returns the already-resolved address list. The original hostname remains in the URL for Host, SNI and hostname verification. The client bypasses system proxy resolution. |
| Request cancellation | Blocking URLConnection calls could continue until timeout after the coroutine was cancelled. | Asynchronous OkHttp calls are connected to coroutine cancellation and active calls are cancelled immediately. |
| Redirect privacy | Redirects and request normalization needed a single enforced rule for query and fragment removal. | Raw path components are preserved; query strings and fragments are removed before initial and redirect requests. Same-host/port and no HTTPS downgrade constraints remain. |
| Resource checks | runCatching around public resource probes could swallow coroutine cancellation. | Cancellation is explicitly rethrown; only ordinary I/O failures become NO RESPONSE. |
| Resource limits | Repeated requests and GET samples needed a strict total ceiling. | Added 8-second per-call timeout, 45-second scan deadline, 18-request audit budget and 256-byte body sample cap. |
| Finding quality | Generic CSP string matching and missing document headers could flag JSON APIs. | CSP is parsed by directive; HTML-only controls are checked only on HTML/XHTML responses. CORS reflection is medium severity and explicitly not proof of data exposure. |
| Result triage | Findings had no stable machine-readable identifier or confidence context. | Findings now include stable IDs, categories, confidence estimates, endpoint and request method. |

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

1. **DNS and network environment:** DNS is pinned for direct OkHttp connections within one Web audit. System proxies are deliberately bypassed because they would resolve the hostname independently. VPNs, transparent network middleboxes, DNS changes between separate audits and platform routing behavior remain outside the app's control.
2. **Cleartext HTTP:** usesCleartextTraffic is enabled because user-selected HTTP endpoints are a supported audit target. HTTP requests are unencrypted. The UI warns about this; users must not include credentials or sensitive query parameters.
3. **Local-network access:** on Android versions before the newer local-network permission model, an app with INTERNET permission can generally reach networks permitted by the OS. Gmap does not run network scans in the background, but users should still only specify authorized targets.
4. **Device validation:** unit tests and CI cannot validate all phone models, OEM network stacks, thermal throttling, battery impact or every router response. Physical-device testing remains required.
5. **Release signing:** CI releases are debug-signed. Production distribution requires a maintainer-managed release keystore and protected signing secrets.
6. **Audit assurance:** this is a focused source/configuration review with regression tests, not a formal security certification, fuzzing campaign or independent penetration test. No claim of zero vulnerabilities is made.

## Validation required in CI and on devices

- Android Lint (lintDebug)
- Kotlin/JVM unit tests (testDebugUnitTest)
- Debug APK assembly (assembleDebug)
- Web regressions for pinned DNS, query suppression, raw path preservation, CORS evidence classification, resource handling and prompt cancellation.
- Physical-device verification of Android 17 local-network permission prompts, TLS/SNI/hostname verification, DNS behavior on Wi-Fi and mobile data, and cancellation under slow network conditions.
